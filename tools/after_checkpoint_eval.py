"""Local handoff: finish baseline, report, verify candidate/AWS, run one 10h window.

This is an experiment controller, not an agent or a publishing tool. Unknown
failures stop the handoff for review; completed failed model outputs stay saved.
"""
from pathlib import Path
from datetime import datetime,timezone
import argparse
import ctypes
import json
import os
import sqlite3
import subprocess
import sys
import time

try:import benchmark_support as support
except ModuleNotFoundError:from tools import chronological_public_eval as support


def alive(pid,not_after=None):
    if os.name!='nt':raise RuntimeError('This controller supervises the installed Windows task')
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD];kernel.OpenProcess.restype=wintypes.HANDLE
    kernel.GetExitCodeProcess.argtypes=[wintypes.HANDLE,ctypes.POINTER(wintypes.DWORD)]
    kernel.GetProcessTimes.argtypes=[wintypes.HANDLE,*([ctypes.POINTER(wintypes.FILETIME)]*4)]
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    handle=kernel.OpenProcess(0x1000,False,int(pid))
    if not handle:
        if ctypes.get_last_error() in (0,87):return False
        raise OSError(ctypes.get_last_error(),'Cannot verify process state')
    try:
        if not_after:
            times=[wintypes.FILETIME() for _ in range(4)]
            if not kernel.GetProcessTimes(handle,*[ctypes.byref(t) for t in times]):raise ctypes.WinError(ctypes.get_last_error())
            created=((times[0].dwHighDateTime<<32)|times[0].dwLowDateTime)/10_000_000-11_644_473_600
            if created>datetime.fromisoformat(not_after.replace('Z','+00:00')).timestamp():return False
        code=wintypes.DWORD()
        if not kernel.GetExitCodeProcess(handle,ctypes.byref(code)):raise ctypes.WinError(ctypes.get_last_error())
        return code.value==259
    finally:kernel.CloseHandle(handle)


def recoverable(baseline,progress):
    if progress.get('error')!='Worker error; inspect isolated events and L2 cases':return False
    workers=progress['workers']
    if any(w['errors'] for name,w in workers.items() if name!='l2'):return False
    if workers['l2']['errors']==0:return False
    with sqlite3.connect((baseline/'events.db').resolve().as_uri()+'?mode=ro',uri=True) as db:
        failed=[json.loads(r[0]) for r in db.execute("SELECT body FROM l2_cases WHERE json_extract(body,'$.review_failed')=1")]
        if not failed or any(c.get('review_error') not in ('ValueError','JSONDecodeError','HTTPError') for c in failed):return False
        if db.execute("SELECT COUNT(*) FROM telemetry WHERE state='failed'").fetchone()[0]:return False
        recent=db.execute("SELECT json_extract(analysis,'$.completed_at'),event_id FROM telemetry WHERE state='done' AND event_id IN (SELECT json_extract(body,'$.event_id') FROM l2_cases) ORDER BY json_extract(analysis,'$.completed_at') DESC LIMIT 3").fetchall()
        bad={c['event_id'] for c in failed}
        if len(recent)==3 and all(row[1] in bad for row in recent):return False
    return True


def main(plan_path):
    plan=json.loads(plan_path.read_text());root=Path(plan['repo']);baseline=Path(plan['baseline']);out=plan_path.parent
    sys.path.append(str(root))
    state={'status':'starting','updated_utc':support.utc(),'pid':os.getpid(),'baseline':str(baseline),'next_run':plan['next_run']}

    def progress(status,**extra):
        state.update(status=status,updated_utc=support.utc(),**extra)
        support.write_json(out/'handoff-progress.json',state)
        (out/'STATUS.txt').write_text(f'After-checkpoint handoff: {status}\nUpdated UTC: {state["updated_utc"]}\n'
            f'Baseline completed: {state.get("baseline_completed","checking")} / 26,000\n'
            f'Next measured window: 10 hours\nNext output: {plan["next_run"]}\n'
            f'Detail: {state.get("detail","")}\nNo GitHub publication or device actions.\n',encoding='utf-8')

    def check_files():
        for path,expected in plan['files'].items():
            if support.sha(Path(path))!=expected:raise ValueError('Planned artifact changed: '+path)

    def command(args,name,cwd=root,timeout=None):
        with (out/(name+'.log')).open('w',encoding='utf-8') as log:
            result=subprocess.run([str(a) for a in args],cwd=cwd,stdout=log,stderr=subprocess.STDOUT,
                timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW)
        if result.returncode:raise RuntimeError(name+' failed; inspect '+str(out/(name+'.log')))

    try:
        from arbiter.install.lifecycle import instance_lock
        with instance_lock(out):
            check_files()
            recoveries=0
            while True:
                g=json.loads((baseline/'progress.json').read_text())
                progress('waiting-for-baseline',baseline_completed=g['counts'].get('completed',0),baseline_status=g['status'],
                    detail='Current frozen run continues. Candidate and AWS wheels are staged but inactive.')
                if g['status']=='completed':break
                if g['status'] in ('stopped-error','paused'):
                    if g['status']=='paused' or not recoverable(baseline,g):
                        raise RuntimeError('Baseline stopped for a condition requiring review; no new run started')
                    # Same frozen evaluation; known invalid replies stay flagged and are never retried.
                    supervisor=json.loads((baseline/'supervisor.json').read_text(encoding='utf-8-sig'))
                    while alive(g['pid'],g['updated_utc']) or alive(supervisor['supervisor_pid'],g['updated_utc']):time.sleep(2)
                    saved=baseline/'interruptions'/('auto-'+datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S'))
                    saved.mkdir()
                    support.write_json(saved/'progress.json',g);support.write_json(saved/'supervisor.json',supervisor)
                    if support.model_identity()!=json.loads((baseline/'run.json').read_text())['models']:
                        raise RuntimeError('Local model service identity/health check failed; baseline not resumed')
                    progress('resuming-preserved-failure',detail='Saved failed L2 outcome remains flagged; unfinished records resume unchanged.')
                    command(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',plan['supervisor'],
                        '-RunDirectory',baseline,'-PythonPath',plan['python'],'-Resume'],f'baseline-resume-{recoveries}')
                    recoveries+=1
                time.sleep(20)
            supervisor=json.loads((baseline/'supervisor.json').read_text(encoding='utf-8-sig'))
            while alive(g['pid'],g['updated_utc']) or alive(supervisor['supervisor_pid'],g['updated_utc']):time.sleep(2)
            if g['counts']['completed']!=26000:raise ValueError('Expected the entire 26,000-record baseline')
            check_files()
            # Only the final checkpoint may approve the candidate's missed-attack coverage.
            progress('analyzing-final-checkpoint',detail='Writing plain-language results and replaying failed suppressions through candidate guards.')
            command([plan['python'],plan['reporter'],'--baseline',baseline,'--out',out/'baseline-report',
                '--candidate',plan['candidate_runtime']],'final-analysis')
            report=json.loads((out/'baseline-report/summary.json').read_text())
            if report['candidate_uncovered_misses']:raise ValueError('Uncovered final misses require further work')
            for name,expected in plan['base_core_files'].items():
                if support.sha(root/name)!=expected:raise ValueError('Source changed before applying candidate: '+name)
            progress('applying-tested-upgrade',detail='Final missed-attack coverage passed; applying the staged source patch.')
            command(['git','apply','--check',plan['patch']],'patch-check')
            command(['git','apply',plan['patch']],'apply-upgrade')
            progress('installing-optional-aws-sdk',detail='Installing pinned local wheels into the separate benchmark environment.')
            envdir=out/'aws-runtime'
            command([plan['python'],'-m','venv','--system-site-packages',envdir],'create-environment')
            python=envdir/'Scripts/python.exe'
            command([python,'-m','pip','install','--no-index','--find-links',out/'wheels','--require-hashes','-r',out/'aws-requirements.txt'],'install-aws')
            command([python,'-m','pip','check'],'dependency-check')
            progress('testing-upgrade-and-aws',detail='Full suite including the previously skipped AWS connector tests; mocked credentials, no live cloud calls.')
            command([python,'-m','pytest','-q','-rs'],'upgraded-tests')
            command([python,'-c',"import boto3,botocore,json;print(json.dumps({'boto3':boto3.__version__,'botocore':botocore.__version__}))"],'aws-versions')
            check_files()
            progress('running-10-hour-benchmark',detail='Fresh isolated state; bounded independent intake; final decisions counted only through the 10-hour cutoff.')
            command(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',plan['supervisor'],
                '-RunDirectory',plan['next_run'],'-PythonPath',python,'-Timed','-DurationSeconds','36000'],'ten-hour-supervision',timeout=37000)
            next_out=Path(plan['next_run']);summary=json.loads((next_out/'progress.json').read_text())
            if summary['status'] not in ('completed-window','source-exhausted'):raise RuntimeError('Timed benchmark did not finish normally')
            with sqlite3.connect((next_out/'results.db').resolve().as_uri()+'?mode=ro',uri=True) as db:
                populations=db.execute("SELECT json_extract(payload,'$.label'),COUNT(*) FROM inputs GROUP BY 1").fetchall()
                outcomes=db.execute("SELECT json_extract(payload,'$.label'),json_extract(payload,'$.decision'),COUNT(*) FROM results WHERE in_window=1 GROUP BY 1,2").fetchall()
                latency=db.execute("SELECT AVG(json_extract(payload,'$.receipt_to_final_s')),MAX(json_extract(payload,'$.receipt_to_final_s')),AVG(json_extract(payload,'$.processing_pipeline_s')) FROM results WHERE in_window=1").fetchone()
            support.write_json(next_out/'final-summary.json',{'window':summary,'accepted_label_counts':populations,
                'completed_label_outcomes':outcomes,'latency_s':{'mean_receipt_to_final':latency[0],'max_receipt_to_final':latency[1],'mean_pipeline':latency[2]},
                'selection_limit':'Priority scheduling selects which accepted records finish; report unprocessed labels as backlog, not correct decisions'})
            text=(f'# Ten-hour capacity result\n\n'
                'Source: [AIT Alert Data Set v1](https://zenodo.org/records/8263181), by Max Landauer, Florian Skopik and Markus Wurzenberger. '
                'Public Wazuh/Suricata records are used; AMiner is excluded. The replay starts in the attack-inclusive Fox period and can continue into other scenarios.\n\n'
                f'Configured window: 10 hours. Final status: {summary["status"]}; elapsed through cleanup: {summary["elapsed_s"]/3600:.2f} hours.\n\n'
                f'Accepted into the queue: {summary["accepted"]:,}. Final decisions within the measured window: {summary["completed_within_window"]:,}. '
                f'Unfinished at cutoff: {summary["unfinished_at_cutoff"]:,}. Decisions completed during cleanup: {summary["completed_after_cutoff"]:,}.\n\n'
                f'Final-decision throughput: {summary["completion_rate_per_min"]:.2f} records/minute. '
                'Ingestion is not equivalent to completed AI analysis. Raw records, worker counters and per-record model calls are saved separately.\n\n'
                'See progress.json for retained/missed attack labels, unannotated outcomes and failure-policy decisions. Unannotated does not prove benign. '
                'Results are for a prioritised, bounded replay, not a live corporate product comparison. The earlier baseline shared GPU time and was interrupted, so it is not an isolated speed comparator.\n\n'
                'Optional AWS SDK libraries were installed and tested with mocked sessions; this public AIT-ADS benchmark made no AWS API calls. '
                'All device actions remained disabled. Publication awaits owner review.\n')
            (next_out/'README.md').write_text(text,encoding='utf-8')
            progress('completed',detail='Baseline report, upgrade tests and timed results are saved locally for review.')
    except BaseException as exc:
        progress('needs-review',detail=f'{type(exc).__name__}: {exc}')
        raise


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--plan',type=Path,required=True)
    main(ap.parse_args().plan.resolve())
