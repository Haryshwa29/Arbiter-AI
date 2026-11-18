"""Stop one identified replay worker at a durable record limit and export its data."""
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
import argparse
import csv
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
import zipfile

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.full_public_eval import count_result, progress, write_json
from tools.public_dataset_eval import digest


def utc():
    return datetime.now(timezone.utc).isoformat()


def csv_text(value):
    if isinstance(value,str) and (value.startswith(('\t','\r','\n')) or value.lstrip().startswith(('=','+','-','@'))):
        return "'"+value
    return value


class Worker:
    """Hold the original Windows process handle, avoiding PID-reuse mistakes."""
    def __init__(self,pid,out):
        self.api=ctypes.WinDLL('kernel32',use_last_error=True)
        self.api.OpenProcess.argtypes=[wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
        self.api.OpenProcess.restype=wintypes.HANDLE
        self.api.WaitForSingleObject.argtypes=[wintypes.HANDLE,wintypes.DWORD]
        self.api.TerminateProcess.argtypes=[wintypes.HANDLE,wintypes.UINT]
        self.api.CloseHandle.argtypes=[wintypes.HANDLE]
        self.handle=self.api.OpenProcess(0x100001,False,pid)
        if not self.handle: raise OSError(ctypes.get_last_error(),'Cannot open the replay worker')
        try:
            command=f"Get-CimInstance Win32_Process -Filter 'ProcessId = {int(pid)}' | Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress"
            info=json.loads(subprocess.check_output(['powershell.exe','-NoProfile','-Command',command],text=True))
            line=(info.get('CommandLine') or '').replace('\\\\','\\').casefold()
            if (str(ROOT/'tools/full_public_eval.py').casefold() not in line
                    or str(out).casefold() not in line):
                raise ValueError('PID does not identify this full public replay')
            self.identity=info
        except BaseException:
            self.close()
            raise

    def running(self):
        return self.api.WaitForSingleObject(self.handle,0)==258

    def stop(self):
        if not self.running(): raise RuntimeError('Worker exited before the requested stop')
        if not self.api.TerminateProcess(self.handle,0):
            raise OSError(ctypes.get_last_error(),'Could not stop the identified replay worker')
        if self.api.WaitForSingleObject(self.handle,5000)!=0:
            raise RuntimeError('Worker termination was not confirmed')

    def close(self):
        self.api.CloseHandle(self.handle)


def rates(counts,prefix):
    tp,fn,fp,tn=(counts[prefix+'_'+k] for k in ('tp','fn','fp','tn'))
    n=tp+fn+fp+tn
    return {'records':n,'attack_labels_flagged':tp,'attack_labels_quieted':fn,
        'unannotated_flagged':fp,'unannotated_quieted':tn,
        'label_agreement_percent':100*(tp+tn)/n if n else None,
        'attack_label_recall_percent':100*tp/(tp+fn) if tp+fn else None,
        'unannotated_quieted_percent':100*tn/(tn+fp) if tn+fp else None}


def export_run(out,destination,receipt):
    destination.mkdir(parents=True,exist_ok=False)
    db=sqlite3.connect(out/'results.db')
    try:
        saved=Counter(json.loads(db.execute("SELECT value FROM state WHERE name='counts'").fetchone()[0]))
        counts=Counter();scenarios=Counter();rules=Counter()
        fields=['record','sample_id','scenario','raw_line','label','attack_annotation',
            'host','event_id','event_timestamp','event_message','l1_decision','l1_tier',
            'l1_rationale','l1_guardrail_veto','l2_rule','gemma_replied','l2_proposal',
            'final_decision','final_actor','final_reason','l1_error','l2_error']
        with (destination/'results.csv').open('w',newline='',encoding='utf-8-sig') as cf, (destination/'decisions.jsonl').open('w',encoding='utf-8') as jf:
            writer=csv.DictWriter(cf,fieldnames=fields);writer.writeheader()
            for seq,payload in db.execute('SELECT seq,payload FROM results ORDER BY seq'):
                row=json.loads(payload);count_result(counts,row)
                scenarios[row['scenario']]+=1
                first=row['first_stage'];second=row.get('second_stage') or {};event=row['event']
                rule=second.get('prefilter',{}).get('rule','')
                if rule: rules[rule]+=1
                jf.write(json.dumps({'record':seq,**row},ensure_ascii=True)+'\n')
                values=dict(zip(fields,[seq,row['sample_id'],row['scenario'],row['raw_line'],row['label'],row['expected_attack'],
                    event['host'],event['id'],event['timestamp'],event['message'],first['decision'],first['tier'],
                    first['rationale'],first['final_guardrail'].get('veto',''),rule,bool(row['usage']),second.get('proposed_decision',''),
                    row['decision'],row['decision_source'],second.get('decision_reason',first['rationale']),first['policy_fallback'],
                    json.dumps(row['l2_error']) if row['l2_error'] else '']))
                writer.writerow({k:csv_text(v) for k,v in values.items()})
        if counts!=saved: raise ValueError('Export totals disagree with committed evaluation counters')
        summary={'scope':'Contiguous first records in original file order, stopped at the user target; not the whole dataset or a random representative sample',
            'stop':receipt,'completed':counts['completed'],'by_scenario':dict(scenarios),
            'l1':rates(counts,'l1'),'final':rates(counts,'final'),'layers':dict(counts),'l2_rules':dict(rules),
            'label_caveat':'No attack annotation does not independently certify harmlessness; attack recall is undefined if no attack-labelled records were processed.',
            'csv_note':'Spreadsheet formula-like text is prefixed with an apostrophe in CSV; JSONL and SQLite preserve original values.'}
        write_json(destination/'summary.json',summary)
        write_json(destination/'stop-receipt.json',receipt)
        for name in ('run.json','input-check.json'):
            if (out/name).exists(): (destination/name).write_bytes((out/name).read_bytes())
        backup=sqlite3.connect(destination/'results.db')
        try: db.backup(backup)
        finally: backup.close()
        final=summary['final'];attack_total=final['attack_labels_flagged']+final['attack_labels_quieted']
        text=(f'# Arbiter AI: checkpoint at {counts["completed"]:,} records\n\n'
            f'Stopped at the requested threshold of {receipt["target"]:,}; {counts["completed"]:,} completed results are preserved.\n\n'
            'Dataset: AIT Alert Data Set (AIT-ADS) v1, DOI 10.5281/zenodo.8263181, '
            'Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology, CC BY 4.0. '
            'Source: https://zenodo.org/records/8263181 . The full supported population is 2,600,263 Wazuh/Suricata records; 55,558 AMiner records are unsupported.\n\n'
            f'This package contains the first records in file order from {dict(scenarios)}. It is a partial, non-random replay, not a completed full-dataset evaluation.\n\n'
            f'- Attack-labelled records examined: {attack_total:,}; kept flagged: {final["attack_labels_flagged"]:,}; quieted: {final["attack_labels_quieted"]:,}.\n'
            f'- Records without attack labels: {final["unannotated_flagged"]+final["unannotated_quieted"]:,}; quieted: {final["unannotated_quieted"]:,}; still flagged: {final["unannotated_flagged"]:,}.\n'
            f'- Agreement with publisher labels: {final["label_agreement_percent"]:.2f}%. Missing attack labels do not certify harmlessness.\n'
            f'- Qwen reviews: {counts["qwen_reviews"]:,}; Gemma records with replies: {counts["gemma_reviews"]:,}; warnings quieted by Gemma: {counts["gemma_suppressions"]:,}.\n'
            f'- Qwen errors: {counts["qwen_errors"]:,}; L2 errors: {counts["l2_errors"]:,}. No device actions were enabled.\n\n'
            'Attack detection cannot be estimated when the examined prefix contains no attack labels. '
            'The separate L2 security-context upgrade was not applied to this frozen run.\n\n'
            'Open results.csv for a spreadsheet, decisions.jsonl for complete per-record evidence, summary.json for exact counts, '
            'and results.db for the SQLite snapshot. CSV formula-like strings are escaped; JSONL/SQLite retain exact values. '
            'run.json fixes model identities, input provenance and evaluated source hashes. SHA256SUMS.txt covers this package.\n\n'
            'The final in-flight attempt may have been interrupted at the stop; it is journalled and is not a completed/scored result. '
            'Completed records were not deleted, rewritten or retried. The original run remains resumable if explicitly restarted.\n')
        (destination/'README.md').write_text(text,encoding='utf-8')
        files=sorted(p for p in destination.iterdir() if p.is_file())
        (destination/'SHA256SUMS.txt').write_text(''.join(digest(p)+'  '+p.name+'\n' for p in files),encoding='utf-8')
        archive=destination.with_suffix('.zip');temporary=archive.with_suffix('.partial')
        with zipfile.ZipFile(temporary,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
            for p in sorted(destination.iterdir()):z.write(p,p.name)
        with zipfile.ZipFile(temporary) as z:
            if z.testzip() is not None: raise ValueError('Export ZIP integrity failure')
        temporary.replace(archive)
        return {'archive':str(archive),'archive_sha256':digest(archive),'summary':str(destination/'summary.json'),'completed':counts['completed']}
    finally: db.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--target',type=int,required=True)
    p.add_argument('--export',type=Path,required=True)
    args=p.parse_args();out=args.out.resolve()
    if os.name!='nt' or args.target<1: p.error('Requires Windows and a positive completed-record target')
    if args.export.exists() or args.export.with_suffix('.zip').exists(): p.error('Use a new export destination')
    worker_info=json.loads((out/'worker.json').read_text(encoding='utf-8-sig'))
    worker=Worker(int(worker_info['Pid']),out)
    db=sqlite3.connect(out/'results.db',timeout=1)
    try:
        request={'target':args.target,'requested_utc':utc(),'worker_pid':worker_info['Pid'],
            'controller_pid':os.getpid(),'controller_sha256':digest(__file__),'export':str(args.export.resolve())}
        write_json(out/'stop-request.json',request)
        print(json.dumps({'status':'armed',**request}),flush=True)
        last=-1
        while True:
            counts=Counter(json.loads(db.execute("SELECT value FROM state WHERE name='counts'").fetchone()[0]))
            if counts['completed']>=args.target:
                db.execute('BEGIN IMMEDIATE')
                try:
                    counts=Counter(json.loads(db.execute("SELECT value FROM state WHERE name='counts'").fetchone()[0]))
                    if worker.running():worker.stop()
                finally:db.rollback()
                break
            if not worker.running():raise RuntimeError('Worker stopped before the requested target; data preserved, target not achieved')
            milestone=counts['completed']//500
            if milestone!=last:
                print(json.dumps({'status':'watching','completed':counts['completed'],'target':args.target}),flush=True);last=milestone
            time.sleep(.1)
        stopped=utc()
        with db:
            interrupted=db.execute("UPDATE attempts SET status='interrupted',finished=? WHERE status='running'",(stopped,)).rowcount
        receipt={**request,'stopped_utc':stopped,'actual_completed':counts['completed'],
            'interrupted_attempts_at_stop':interrupted,'worker_exit_confirmed':not worker.running(),
            'method':'Held original process handle; verified script/output identity; took SQLite writer lock and stopped after committed count reached target. Evaluation code unchanged.'}
        write_json(out/'stop-receipt.json',receipt)
        progress(out,db,counts,'stopped-at-user-target',pid=worker_info['Pid'],stop_target=args.target)
        result=export_run(out,args.export.resolve(),receipt)
        write_json(out/'export-ready.json',result)
        print(json.dumps({'status':'export-ready',**result}),flush=True)
    finally:
        db.close();worker.close()


if __name__=='__main__':main()
