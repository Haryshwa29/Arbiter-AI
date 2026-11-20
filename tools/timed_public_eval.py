"""A bounded 10-hour intake/decision benchmark, using only public native fixtures."""
from pathlib import Path
from collections import Counter
from datetime import datetime,timezone
import argparse
import hashlib
import json
import os
import platform
import sqlite3
import sys
import time

try:
    import benchmark_support as support
    from public_benchmark_input import records,native_from_raw
except ModuleNotFoundError:
    from tools import chronological_public_eval as support
    from tools.public_benchmark_input import records,native_from_raw


def classify_completion(row,deadline_utc):
    first=row['first_stage'];analysis=row['final_analysis']
    completed=analysis.get('completed_at') or first.get('completed_at') or row.get('observed_final_utc')
    return bool(completed and datetime.fromisoformat(completed)<=datetime.fromisoformat(deadline_utc))


def run(args):
    out=args.out.resolve()
    support.verify(out);support.frozen_imports(out)
    from arbiter.install.lifecycle import instance_lock
    from arbiter.ingestion.service import IngestionService
    from arbiter.memory import Memory
    from arbiter.store import AuditStore
    with instance_lock(out):
        if (out/'run.json').exists():raise ValueError('Timed benchmarks require a fresh directory; never reset a 10-hour timer')
        identity=support.model_identity()
        provenance=json.loads((out/'input-provenance.json').read_text())
        source=iter(records(out,provenance))
        current=next(source,None)
        if not current:raise ValueError('No source data')
        ledger=sqlite3.connect(out/'results.db')
        ledger.execute('PRAGMA journal_mode=WAL');ledger.execute('PRAGMA synchronous=FULL')
        ledger.executescript('''CREATE TABLE inputs(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL);
            CREATE TABLE results(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,in_window INTEGER NOT NULL,payload TEXT NOT NULL);''')
        counts=Counter();pending={};services=[];scenario=None;service=None;memory=audit=None
        started=time.monotonic();start_utc=datetime.now(timezone.utc)
        deadline=started+args.duration
        deadline_utc=datetime.fromtimestamp(start_utc.timestamp()+args.duration,timezone.utc).isoformat()
        run_meta={'started_utc':start_utc.isoformat(),'deadline_utc':deadline_utc,'duration_s':args.duration,
            'models':identity,'initial_loaded_models':support.request('/api/ps'),'python':platform.python_version(),
            'protocol':'Single independent intake loop, bounded 10,000-record durable buffer, production priority scheduling, five workers; no L1 admission gate',
            'source':'Pinned AIT-ADS Wazuh/Suricata native fixtures; Fox from Jan 18 12:37 UTC, then original scenario/file order',
            'scenario_isolation':'Separate ingestion/audit/memory databases per scenario; old scenario drains before next starts',
            'memory':'Empty at each scenario start; persistent during that scenario; no ground-truth feedback',
            'timer':'Monotonic 10-hour admission window; only final decisions timestamped by the cutoff count; shutdown completions reported separately',
            'actions':'No Agent, collectors, response scheduler or executor; alert/suppress decisions only',
            'frozen_manifest_sha256':support.sha(out/'frozen-files.json')}
        support.write_json(out/'run.json',run_meta)
        status,error='running',None;last_progress=last_identity=0;next_seq=1;late=0

        def collect():
            nonlocal late
            if not pending:return
            with service.buffer.lock:
                ids=list(pending)
                done=service.buffer.conn.execute("SELECT event_id FROM telemetry WHERE state IN ('done','failed') AND event_id IN ("+','.join('?'*len(ids))+')',ids).fetchall()
            for saved in done:
                event_id=saved[0];item=pending[event_id]
                row=support.scored_result(service,item)
                row['observed_final_utc']=support.utc()
                within=classify_completion(row,deadline_utc)
                row['completed_within_window']=within
                with ledger:
                    ledger.execute('INSERT INTO results VALUES(?,?,?,?)',(item['seq'],event_id,int(within),json.dumps(row,allow_nan=False)))
                if within:
                    support.add_counts(counts,row)
                    first=row['first_stage']
                    counts['qwen_classified_records']+=first.get('tier')=='llm' and first.get('backend')=='ollama'
                else:late+=1
                del pending[event_id]

        def close_scenario():
            nonlocal service,memory,audit
            if service:
                services.append({'scenario':scenario,'workers':service.pipeline.status()})
                service.stop();memory.close();audit.close()
                service=memory=audit=None

        def progress():
            elapsed=time.monotonic()-started
            result={'status':status,'updated_utc':support.utc(),'pid':os.getpid(),'started_utc':run_meta['started_utc'],
                'deadline_utc':deadline_utc,'window_duration_s':args.duration,'elapsed_s':elapsed,
                'remaining_window_s':max(0,deadline-time.monotonic()),'accepted':next_seq-1,
                'completed_within_window':counts['completed'],'completed_after_cutoff':late,'unfinished':len(pending),
                'unfinished_at_cutoff':next_seq-1-counts['completed'],
                'counts':dict(counts),'scenario':scenario,'workers':service.pipeline.status() if service else {},
                'prior_scenario_workers':services,'error':error,'device_actions':0,
                'completion_rate_per_min':counts['completed']/(min(elapsed,args.duration)/60) if elapsed>0 else 0}
            support.write_json(out/'progress.json',result)
            (out/'STATUS.txt').write_text(
                f'10-hour AIT-ADS benchmark: {status}\nUpdated UTC: {result["updated_utc"]}\n'
                f'Measured time: {min(elapsed,args.duration)/3600:.2f} / {args.duration/3600:.2f} hours\n'
                f'Accepted into durable queue: {next_seq-1:,}\nFinal decisions within window: {counts["completed"]:,}\n'
                f'Still unfinished: {len(pending):,}\nCompleted after cutoff: {late:,}\n'
                f'Attack-labelled kept / suppressed: {counts["final_tp"]:,} / {counts["final_fn"]:,}\n'
                f'Unannotated retained / quieted: {counts["final_fp"]:,} / {counts["final_tn"]:,}\n'
                f'Qwen classified: {counts["qwen_classified_records"]:,}; Gemma reviewed: {counts["gemma_records"]:,}\n'
                f'Failed records retained: {counts["failed_records"]:,}; device actions: 0\nError: {error or "none"}\n'
                'Accepted records are not completed decisions. Unannotated is not certified benign.\n',encoding='utf-8')

        try:
            if os.name=='nt':
                import ctypes
                if not ctypes.windll.kernel32.SetThreadExecutionState(0x80000001):raise OSError('Could not keep benchmark awake')
            while time.monotonic()<deadline:
                now=time.monotonic()
                if (out/'STOP').exists():status='paused';break
                if now-last_identity>=30:
                    # The small runtime/scripts stay hash-checked; pinned archives are checked at start and end.
                    manifest=json.loads((out/'frozen-files.json').read_text())
                    for name,expected in manifest.items():
                        if not name.endswith('.zip') and support.sha(out/name)!=expected:raise ValueError('Frozen benchmark changed: '+name)
                    if support.model_identity()!=identity:raise ValueError('Model identity changed')
                    last_identity=now
                if service:
                    collect()
                    workers=service.pipeline.status()
                    failure=support.health_failure(workers,counts)
                    if failure:raise RuntimeError(failure)
                if current is None:
                    if not pending:status='source-exhausted';break
                elif current[1]['scenario']!=scenario:
                    if not pending:
                        close_scenario();scenario=current[1]['scenario']
                        state=out/scenario;state.mkdir()
                        memory=Memory(state/'memory.db');audit=AuditStore(state/'audit.db')
                        service=IngestionService(state/'events.db',memory,audit,'ollama',support.MODELS[0],
                            ollama_url='http://127.0.0.1:11434',capacity=10000)
                        service.enable_final_review(support.MODELS[1],support.NoActions(),180)
                        support.measured_pipeline(service).start()
                elif len(pending)<10000:
                    # Independent intake: do not wait for either brain to finish the previous record.
                    for _ in range(32):
                        if current is None or current[1]['scenario']!=scenario or len(pending)>=10000 or time.monotonic()>=deadline:break
                        raw,item=current;event=native_from_raw(raw)
                        item={**item,'seq':next_seq,'original_event_id':event.event_id}
                        event.event_id=hashlib.sha256((item['sample_id']+':'+item['raw_sha256']).encode()).hexdigest()
                        event.received_at=support.utc();item['event_id']=event.event_id
                        with ledger:
                            ledger.execute('INSERT INTO inputs VALUES(?,?,?)',(next_seq,event.event_id,json.dumps(item)))
                            if not service.buffer.enqueue(event,'wazuh'):raise ValueError('Duplicate benchmark event')
                        pending[event.event_id]=item;next_seq+=1
                        current=next(source,None)
                if now-last_progress>=20:progress();last_progress=now
                time.sleep(.02)
            else:status='completed-window'
        except BaseException as exc:
            status,error='stopped-error',f'{type(exc).__name__}: {exc}'
        finally:
            if service:
                # No unlimited drain: join in-flight calls, leave backlog durable, report late completions separately.
                service.pipeline.stop();collect();progress();close_scenario()
            progress()
            with (out/'decisions.jsonl').open('w',encoding='utf-8') as target:
                for row, in ledger.execute('SELECT payload FROM results ORDER BY seq'):target.write(row+'\n')
            ledger.close();source.close()
            support.verify(out)
            if os.name=='nt':
                import ctypes
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        if error:raise RuntimeError(error)


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--duration',type=float,default=36000)
    args=ap.parse_args()
    if not 0<args.duration<=36000:ap.error('duration must be positive and at most 10 hours')
    run(args)
