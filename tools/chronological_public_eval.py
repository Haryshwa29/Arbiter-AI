"""Frozen, isolated AIT-ADS checkpoint through the real five-worker pipeline.

Labels are read only by preparation/scoring. No collectors, response workflow,
customer databases, policy edits or model-generated human feedback are enabled.
"""
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

MODELS = ('qwen3.5:4b', 'gemma4:12b')


def utc():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    digest=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def write_json(path, data):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(data, indent=2, allow_nan=False)+'\n', encoding='utf-8')
    temp.replace(path)


def request(path, body=None):
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request('http://127.0.0.1:11434'+path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={'Content-Type':'application/json'})
    with opener.open(req, timeout=10) as response:
        return json.load(response)


def model_identity():
    tags = {m['name']:m for m in request('/api/tags')['models']}
    result = {}
    for name in MODELS:
        item, metadata = tags[name], request('/api/show', {'model':name})
        if any(obj.get('remote_host') or obj.get('remote_model') for obj in (item, metadata)):
            raise ValueError('Only verified local models may run this benchmark')
        if not item.get('digest') or not metadata.get('details', {}).get('format'):
            raise ValueError('Missing local model identity')
        result[name] = {'digest':item['digest'], 'details':metadata['details'],
            'parameters':metadata.get('parameters'), 'template_sha256':hashlib.sha256(metadata.get('template','').encode()).hexdigest()}
    return result


def frozen_imports(out):
    runtime = out/'runtime.pyz'
    sys.path.insert(0, str(runtime))
    import arbiter
    if str(runtime) not in str(arbiter.__file__):
        raise RuntimeError('Arbiter was imported outside the frozen runtime; use a fresh process')


def prepare(args):
    root = Path(__file__).resolve().parents[1]
    if args.out.exists():
        raise ValueError('Preparation requires a new output directory')
    provenance = json.loads((root/'evals/2026-11-17-l2-evidence-gated/input-provenance.json').read_text())
    for filename, key in [('ait_ads.zip','dataset_sha256'),('alerts_csv.zip','labels_sha256')]:
        if sha(args.cache/filename) != provenance[key]:
            raise ValueError('Pinned public archive changed: '+filename)
    args.out.mkdir(parents=True)
    shutil.copy2(args.runtime, args.out/'runtime.pyz')
    frozen_imports(args.out)
    sys.path.append(str(root))
    from tools.full_public_eval import alerts
    from tools.public_dataset_eval import native_from_raw
    from tools.public_dataset_eval import label_rows
    from arbiter.ingestion.schema import timestamp
    raw_path, event_path, index_path = [args.out/name for name in ('raw.jsonl','events.jsonl','scorer-index.jsonl')]
    labels = Counter()
    start = datetime.fromisoformat(args.start.replace('Z','+00:00'))
    previous = first = last = None
    count = 0
    with zipfile.ZipFile(args.cache/'alerts_csv.zip') as labelzip, raw_path.open('w',encoding='utf-8') as rawfile, event_path.open('w',encoding='utf-8') as events, index_path.open('w',encoding='utf-8') as index:
        publisher_rows = iter(label_rows(labelzip,'fox'))
        for global_seq, raw, item in alerts(args.cache, provenance):
            if item['scenario'] != 'fox':
                break
            publisher = next(publisher_rows)
            instant = datetime.fromisoformat(timestamp(raw['@timestamp']))
            if int(instant.timestamp()) != int(publisher['time']):
                raise ValueError('Raw timestamp does not match publisher label timestamp')
            if instant < start:
                continue
            if previous and instant < previous:
                raise ValueError('Selected source records are not chronological')
            native = native_from_raw(raw)
            encoded = json.dumps(raw, sort_keys=True, allow_nan=False)
            raw_hash = hashlib.sha256(encoded.encode()).hexdigest()
            original_id = native.event_id
            # Each public row must be scored, including duplicate native IDs.
            native.event_id = hashlib.sha256((item['sample_id']+':'+raw_hash).encode()).hexdigest()
            native.received_at = native.timestamp
            count += 1
            labels[item['label']] += 1
            rawfile.write(encoded+'\n')
            events.write(native.to_json()+'\n')
            index.write(json.dumps({**item, 'seq':count, 'global_seq':global_seq,
                'event_id':native.event_id, 'original_event_id':original_id, 'raw_sha256':raw_hash,
                'timestamp':native.timestamp})+'\n')
            first = first or native.timestamp
            last, previous = native.timestamp, instant
            if count == args.limit:
                break
    if count != args.limit or labels['-'] == 0 or labels['-'] == count:
        raise ValueError('Cohort must reach the target and contain both label classes')
    shutil.copy2(Path(__file__), args.out/'run_eval.py')
    write_json(args.out/'cohort.json', {
        'dataset':'AIT Alert Data Set v1', 'doi':provenance['doi'],
        'dataset_url':provenance['dataset_url'], 'dataset_sha256':provenance['dataset_sha256'],
        'labels_url':provenance['labels_url'], 'labels_revision':provenance['labels_revision'],
        'labels_sha256':provenance['labels_sha256'], 'scenario':'fox', 'records':count,
        'selection':'Contiguous supported records from the requested source time; no outcome-based selection',
        'requested_start_utc':args.start, 'first_source_utc':first, 'last_source_utc':last,
        'label_counts':dict(labels), 'attack_labelled':count-labels['-'], 'unannotated':labels['-'],
        'label_caveat':'Unannotated is not certified benign. This selected scenario is not a full-dataset accuracy estimate.',
        'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'protocol':{
            'workers':5, 'l1':MODELS[0], 'l2':MODELS[1], 'l2_review_seconds':180,
            'ordering':'Accelerated chronological admission: next record after preceding L1 is saved; L2 overlaps L1',
            'memory':'Initially empty, persistent within this isolated run; no ground-truth feedback',
            'connector':'Test-only native Wazuh fixture to exercise live learned-pattern eligibility; not a live collector',
            'clocks':'Context uses original source time; learned-pattern one-hour TTL uses processing wall time, maximum 25 hits',
            'timing':'Observed benchmark receipt-to-final; not original-arrival delay or corporate product comparison',
            'actions':'No collectors, Agent, response executor or customer database; recommendations only',
            'qwen_options':{'think':False,'temperature':.1,'format':'json','context':'server default'},
            'gemma_options':{'think':False,'num_ctx':8192,'num_predict':1536,'temperature':.1},
            'development_overlap':'Policy development used earlier AIT-ADS samples; no independent held-out claim'
        }})
    files = ('runtime.pyz','run_eval.py','raw.jsonl','events.jsonl','scorer-index.jsonl','cohort.json')
    write_json(args.out/'frozen-files.json', {name:sha(args.out/name) for name in files})
    print(json.dumps(json.loads((args.out/'cohort.json').read_text()),indent=2))


def verify(out):
    for name, expected in json.loads((out/'frozen-files.json').read_text()).items():
        if sha(out/name) != expected:
            raise ValueError('Frozen benchmark file changed: '+name)


class NoActions:
    def proposal(self, row):
        return None


def measured_pipeline(service):
    from arbiter.ingestion.review_pipeline import ReviewPipeline

    class Measured(ReviewPipeline):
        def __init__(self, previous):
            super().__init__(previous.buffer,previous.engine,previous.audit,previous.workflow)
            self.local = threading.local()

        def _step(self, stage, job):
            self.local.job = job
            job.setdefault('benchmark_stages', {})[stage] = {
                'started':time.monotonic(),
                'queue_wait_s':time.monotonic()-job['_queued_at'] if stage!='gateway' else None}
            try:
                return super()._step(stage,job)
            finally:
                self.local.job = None

        def _put(self, stage, job, caller):
            timing = job.get('benchmark_stages',{}).get(caller)
            if timing:
                timing['work_before_handoff_s'] = time.monotonic()-timing.pop('started')
            return super()._put(stage,job,caller)

        def finish(self, job, analysis):
            timing = job['benchmark_stages']['final_guardrail']
            timing['work_before_persist_s'] = time.monotonic()-timing.pop('started')
            analysis['benchmark'] = {'stages':job['benchmark_stages'], 'calls':job.get('benchmark_calls',[])}
            return super().finish(job,analysis)

    previous = service.pipeline
    pipeline = Measured(previous)
    service.pipeline = pipeline
    for name, backend in [('qwen',pipeline.engine.llm),('gemma',pipeline.workflow.brain.backend)]:
        original = backend.generate
        def timed(*args, _name=name, _backend=backend, _original=original, **kwargs):
            started = time.monotonic()
            call = {'brain':_name, 'status':'failed'}
            usage = getattr(_backend,'usage',[])
            before = usage[-1] if usage else None
            try:
                result = _original(*args,**kwargs)
                call['status'] = 'replied'
                return result
            except Exception as exc:
                call['error'] = type(exc).__name__
                raise
            finally:
                call['elapsed_s'] = time.monotonic()-started
                usage = getattr(_backend,'usage',[])
                if usage and usage[-1] is not before:
                    call['usage'] = dict(usage[-1])
                job = getattr(pipeline.local,'job',None)
                if job is not None:
                    job.setdefault('benchmark_calls',[]).append(call)
        backend.generate = timed
    return pipeline


def scored_result(service, item):
    stored = service.buffer.detail(item['event_id'])
    row = service.project(stored)
    analysis = row.get('analysis') or {}
    first = analysis.get('first_stage') or stored.get('analysis') or {}
    complete = analysis.get('completed_at') or first.get('completed_at')
    observed = (datetime.fromisoformat(complete)-datetime.fromisoformat(row['received_at'])).total_seconds() if complete else None
    return {**item, 'state':row['state'], 'decision':analysis.get('decision','escalate'),
        'first_stage':first, 'final_analysis':analysis, 'event':row['event'],
        'processing_pipeline_s':row['latency_ms']/1000 if row['latency_ms'] is not None else None,
        'receipt_to_final_s':observed, 'attempts':row['attempts'], 'error':row['error'],
        'timing_interrupted':row['attempts']!=1, 'action_executed':False}


def add_counts(counts, row):
    counts['completed'] += 1
    counts['attack_labelled' if row['expected_attack'] else 'unannotated'] += 1
    for stage, decision in [('l1',row['first_stage'].get('decision','escalate')),('final',row['decision'])]:
        outcome = ('tp' if row['expected_attack'] else 'fp') if decision=='escalate' else ('fn' if row['expected_attack'] else 'tn')
        counts[stage+'_'+outcome] += 1
    first, analysis = row['first_stage'], row['final_analysis']
    counts['l1_tier_'+first.get('tier','failed')] += 1
    counts['l1_learned_hits'] += 'L1 learned exact routine pattern' in first.get('rationale','')
    second = analysis.get('second_stage') or {}
    counts['l2_status_'+str(second.get('review_status','not_entered'))] += 1
    counts['l2_prefilter_suppressions'] += second.get('review_status')=='prefilter' and row['decision']=='suppress'
    counts['l2_learned_hits'] += 'L2_LEARNED_EXACT_PATTERN' in json.dumps(second)
    calls = first.get('benchmark',{}).get('calls',[])
    reviewed = {'qwen':first.get('tier')=='llm' and first.get('backend')=='ollama',
        'gemma':second.get('backend')=='ollama'}
    for brain in ('qwen','gemma'):
        selected = [c for c in calls if c['brain']==brain]
        counts[brain+'_records'] += bool(selected) or reviewed[brain]
        counts[brain+'_calls'] += len(selected)
        counts[brain+'_call_errors'] += sum(c['status']!='replied' for c in selected)
    counts['gemma_suppressions'] += (reviewed['gemma'] or any(c['brain']=='gemma' for c in calls)) and row['decision']=='suppress'
    failure = first.get('backend')=='policy-fallback' or analysis.get('second_stage_status')=='failed-alert-retained' or row['state']=='failed'
    counts['failed_records'] += failure
    if failure: counts['consecutive_model_errors'] += 1
    elif calls: counts['consecutive_model_errors'] = 0
    error_streaks(counts,row)


def error_streaks(counts,row):
    first=row['first_stage'];analysis=row['final_analysis']
    calls=first.get('benchmark',{}).get('calls',[])
    if any(c['brain']=='qwen' for c in calls):
        counts['qwen_consecutive_errors']=counts['qwen_consecutive_errors']+1 if first.get('backend')=='policy-fallback' else 0
    if any(c['brain']=='gemma' for c in calls):
        counts['gemma_consecutive_errors']=counts['gemma_consecutive_errors']+1 if analysis.get('second_stage_status')=='failed-alert-retained' else 0


def health_failure(workers,counts):
    if any(not w['alive'] or w.get('failure') or (w['errors'] and name!='l2') for name,w in workers.items()):
        return 'Structural worker failure; inspect isolated events and L2 cases'
    if max(counts.get(name,0) for name in ('consecutive_model_errors','qwen_consecutive_errors','gemma_consecutive_errors'))>=3:
        return 'Three consecutive model failures'
    return None


def run(args):
    out = args.out
    verify(out)
    frozen_imports(out)
    from arbiter.install.lifecycle import instance_lock
    from arbiter.ingestion.schema import SecurityEvent
    from arbiter.ingestion.service import IngestionService
    from arbiter.memory import Memory
    from arbiter.store import AuditStore
    with instance_lock(out):
        identity = model_identity()
        run_path = out/'run.json'
        identity_fields = {'models':identity, 'frozen_files_sha256':sha(out/'frozen-files.json'), 'python':platform.python_version()}
        if run_path.exists():
            metadata = json.loads(run_path.read_text())
            if any(metadata[k]!=v for k,v in identity_fields.items()):
                raise ValueError('Run identity changed; refusing to mix results')
        else:
            metadata = {**identity_fields, 'started_utc':utc(), 'platform':platform.platform(),
                'ollama_version':request('/api/version'), 'initial_loaded_models':request('/api/ps'),
                'dashboard':'Owner authorized pausing the installed service for isolated timing'}
            write_json(run_path,metadata)
        items = [json.loads(line) for line in (out/'scorer-index.jsonl').read_text().splitlines()]
        with (out/'events.jsonl').open(encoding='utf-8') as source:
            event_count = sum(1 for _ in source)
        if len(items)!=event_count or len({r['event_id'] for r in items})!=len(items):
            raise ValueError('Input index integrity failure')
        ledger = sqlite3.connect(out/'results.db')
        ledger.execute('PRAGMA journal_mode=WAL')
        ledger.execute('PRAGMA synchronous=FULL')
        ledger.execute('CREATE TABLE IF NOT EXISTS results(seq INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL)')
        counts, saved = Counter(), set()
        for seq, payload in ledger.execute('SELECT seq,payload FROM results ORDER BY seq'):
            add_counts(counts,json.loads(payload)); saved.add(seq)
        for name in ('consecutive_model_errors','qwen_consecutive_errors','gemma_consecutive_errors'):counts[name]=0
        memory, audit = Memory(out/'memory.db'), AuditStore(out/'audit.db')
        service = IngestionService(out/'events.db',memory,audit,'ollama',MODELS[0],
            ollama_url='http://127.0.0.1:11434',capacity=128)
        status, error = 'running', None
        pipeline = None
        pending = {}
        next_seq, last_admitted = 1, None
        events_stream = (out/'events.jsonl').open(encoding='utf-8')
        elapsed_before = json.loads((out/'progress.json').read_text()).get('active_elapsed_s',0) if (out/'progress.json').exists() else 0
        session_start = time.monotonic()

        def progress():
            elapsed = elapsed_before+time.monotonic()-session_start
            value = {'status':status,'updated_utc':utc(),'pid':os.getpid(),'target':len(items),
                'counts':dict(counts),'remaining':len(items)-counts['completed'],'in_flight':len(pending),
                'next_sequence':next_seq,'active_elapsed_s':elapsed,'started_utc':metadata['started_utc'],
                'workers':pipeline.status() if pipeline else {}, 'error':error, 'device_actions':0,
                'partial_results':counts['completed']!=len(items),
                'label_caveat':'FP/TN use unannotated records, not confirmed benign ground truth'}
            write_json(out/'progress.json',value)
            (out/'STATUS.txt').write_text(
                f'AIT-ADS five-worker checkpoint: {status}\nUpdated UTC: {value["updated_utc"]}\n'
                f'Completed: {counts["completed"]:,} / {len(items):,}\nIn flight: {len(pending)}\n'
                f'Attack-labelled kept / suppressed: {counts["final_tp"]:,} / {counts["final_fn"]:,}\n'
                f'Unannotated retained / quieted: {counts["final_fp"]:,} / {counts["final_tn"]:,}\n'
                f'Qwen records: {counts["qwen_records"]:,}; Gemma records: {counts["gemma_records"]:,}\n'
                f'Active time: {elapsed/3600:.2f} hours; failures: {counts["failed_records"]}\n'
                f'Device actions: 0\nError: {error or "none"}\n'
                'Partial, selected cohort; missing attack labels do not prove harmlessness.\n',encoding='utf-8')

        try:
            service.enable_final_review(MODELS[1],NoActions(),180)
            pipeline = measured_pipeline(service)
            # Recover all previously admitted rows before admitting anything newer.
            with service.buffer.lock:
                existing = {r['event_id'] for r in service.buffer.conn.execute('SELECT event_id FROM telemetry')}
            for item in items:
                if item['event_id'] in existing and item['seq'] not in saved:
                    pending[item['event_id']] = item
                if item['event_id'] in existing:
                    last_admitted = item['event_id']; next_seq = item['seq']+1
                elif item['seq'] in saved:
                    raise ValueError('Result is missing its durable telemetry row')
            for _ in range(next_seq-1): next(events_stream)
            if os.name=='nt':
                import ctypes
                if not ctypes.windll.kernel32.SetThreadExecutionState(0x80000001):
                    raise OSError('Could not keep benchmark awake')
            pipeline.start()
            last_progress = last_identity = 0
            draining_since = None
            while True:
                now = time.monotonic()
                if now-last_identity>=30:
                    verify(out)
                    if model_identity()!=identity:
                        raise ValueError('Local model identity changed during evaluation')
                    last_identity = now
                if pending:
                    ids = list(pending)
                    with service.buffer.lock:
                        rows = service.buffer.conn.execute('SELECT event_id,state FROM telemetry WHERE event_id IN ('+','.join('?'*len(ids))+')',ids).fetchall()
                    for row in rows:
                        if row['state'] not in ('done','failed'): continue
                        item = pending[row['event_id']]
                        result = scored_result(service,item)
                        with ledger:
                            ledger.execute('INSERT INTO results VALUES(?,?,?)',(item['seq'],item['event_id'],json.dumps(result,allow_nan=False)))
                        add_counts(counts,result)
                        del pending[row['event_id']]
                workers = pipeline.status()
                failure=health_failure(workers,counts)
                if failure:status,error='stopped-error',failure
                if (out/'STOP').exists() and status=='running': status='paused'
                if status!='running':
                    draining_since = draining_since or now
                    if not pending or now-draining_since>200: break
                elif next_seq<=len(items) and len(pending)<128:
                    with service.buffer.lock:
                        previous = service.buffer.conn.execute('SELECT state,analysis IS NOT NULL AS analysed FROM telemetry WHERE event_id=?',(last_admitted,)).fetchone() if last_admitted else None
                    if not previous or previous['analysed'] or previous['state'] in ('done','failed'):
                        data = json.loads(next(events_stream)); data['received_at']=utc()
                        if data['event_id']!=items[next_seq-1]['event_id']:
                            raise ValueError('Event/index order mismatch')
                        if not service.buffer.enqueue(SecurityEvent(**data),'wazuh'):
                            raise ValueError('Duplicate benchmark admission')
                        item = items[next_seq-1]; last_admitted=item['event_id']
                        pending[last_admitted]=item; next_seq+=1
                elif not pending and next_seq>len(items):
                    status='completed'; break
                if now-last_progress>=20:
                    progress(); last_progress=now
                time.sleep(.02)
        except BaseException as exc:
            status, error = 'stopped-error', f'{type(exc).__name__}: {exc}'
            raise
        finally:
            if pipeline:
                pipeline.stop()
                # Preserve completions that raced with stop or a scoring failure.
                for event_id,item in list(pending.items()):
                    row = service.buffer.detail(event_id)
                    if row['state'] in ('done','failed'):
                        result = scored_result(service,item)
                        with ledger:
                            ledger.execute('INSERT OR IGNORE INTO results VALUES(?,?,?)',(item['seq'],event_id,json.dumps(result,allow_nan=False)))
                        add_counts(counts,result); del pending[event_id]
            progress()
            with (out/'decisions.jsonl').open('w',encoding='utf-8') as export:
                for payload, in ledger.execute('SELECT payload FROM results ORDER BY seq'):
                    export.write(payload+'\n')
            service.stop(); memory.close(); audit.close(); ledger.close(); events_stream.close()
            if os.name=='nt':
                import ctypes
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
        if status=='stopped-error': raise RuntimeError(error)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=('prepare','run'))
    parser.add_argument('--out',type=lambda v:Path(v).resolve(),required=True)
    parser.add_argument('--cache',type=Path,default=Path('output/public-eval/ait-ads'))
    parser.add_argument('--runtime',type=Path)
    parser.add_argument('--start',default='2022-01-18T12:37:00Z')
    parser.add_argument('--limit',type=int,default=26000)
    args=parser.parse_args()
    if args.command=='prepare':
        if not args.runtime or args.limit<1: parser.error('prepare needs --runtime and positive --limit')
        prepare(args)
    else: run(args)


if __name__=='__main__':
    main()
