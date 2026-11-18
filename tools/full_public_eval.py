"""Resumable full AIT-ADS replay through the existing local Qwen/Gemma cascade."""
from pathlib import Path
from collections import Counter
from datetime import datetime, timezone
import argparse
import hashlib
import json
import os
import platform
import sqlite3
import sys
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from arbiter.install.lifecycle import instance_lock
from arbiter.l2_advisory import packet_for
from arbiter.l2_final_review import FinalReviewL2Brain, eligible
from arbiter.llm import OllamaBackend
from arbiter.memory import Memory
from arbiter.triage import TriageEngine
from tools.public_dataset_eval import (SCENARIOS, check_match, digest,
    event_from_raw, label_rows, ollama_json)

SUPPORTED = 2_600_263
EXCLUDED = 55_558
PROVENANCE = ROOT / 'evals/2026-11-17-l2-evidence-gated/input-provenance.json'


def utc():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    temporary = path.with_suffix('.tmp')
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False)+'\n', encoding='utf-8')
    temporary.replace(path)


def alerts(cache, provenance):
    """Match every supported raw record to its publisher label without loading it all."""
    seq = 0
    with zipfile.ZipFile(cache/'ait_ads.zip') as rawzip, zipfile.ZipFile(cache/'alerts_csv.zip') as labels:
        for scenario in SCENARIOS:
            rows = iter(label_rows(labels, scenario))
            count = 0
            with rawzip.open(f'{scenario}_wazuh.json') as stream:
                for line_number, line in enumerate(stream, 1):
                    if not line.strip() or b'The average number' in line:
                        continue
                    raw = json.loads(line)
                    row = next(rows)
                    check_match(raw, row)
                    count += 1
                    seq += 1
                    yield seq, raw, {'sample_id':f'{scenario}:{line_number}',
                        'scenario':scenario, 'raw_line':line_number, 'label_row':count+1,
                        'label':row['event_label'], 'expected_attack':row['event_label']!='-'}
            remaining = list(rows)
            if (count != provenance['alignment'][scenario]['matched_supported_alerts']
                    or len(remaining) != provenance['alignment'][scenario]['excluded_aminer']
                    or any(not r['name'].startswith('AMiner: ') for r in remaining)):
                raise ValueError('Full dataset alignment mismatch: '+scenario)
    if seq != SUPPORTED:
        raise ValueError('Full supported-record count mismatch')


def evaluate(raw, item, backend, second, audit):
    started = time.perf_counter()
    event = event_from_raw(raw)
    memory = Memory(':memory:')
    try:
        verdict = TriageEngine(memory, backend, audit, shadow=True).triage(event)
    finally:
        memory.close()
    first = json.loads(verdict.to_json())
    first.update(backend='ollama', model=backend.model,
        final_guardrail=getattr(verdict, 'final_guardrail', {}),
        policy_fallback=verdict.rationale.startswith('LLM tier failed ('))
    l1_elapsed = time.perf_counter()-started
    review = None
    error = None
    packet = None
    second.backend.usage.clear()
    l2_started = time.perf_counter()
    if eligible(first):
        packet = packet_for(event, first, True, final_review=True)
        try:
            review = second.review_event(event, first, True)
        except Exception as exc:
            error = {'type':type(exc).__name__, 'message':str(exc)[:500]}
    l2_elapsed = time.perf_counter()-l2_started if eligible(first) else 0
    actor = ('l2-prefilter' if review['review_status']=='prefilter' else 'gemma') if review else 'l2-failure-policy' if error else first['tier']
    decision = review['alert_decision'] if review else 'escalate' if error else first['decision']
    return {**item, 'event':json.loads(event.to_json()), 'first_stage':first,
        'second_stage':review, 'l2_error':error, 'l2_packet':packet,
        'usage':list(second.backend.usage), 'decision':decision, 'decision_source':actor,
        'l1_elapsed_s':l1_elapsed, 'l2_elapsed_s':l2_elapsed,
        'elapsed_s':time.perf_counter()-started, 'action_executed':False}


def count_result(counts, row):
    first = row['first_stage']
    counts['completed'] += 1
    truth = row['expected_attack']
    for name, decision in [('l1',first['decision']),('final',row['decision'])]:
        outcome = ('tp' if truth else 'fp') if decision=='escalate' else ('fn' if truth else 'tn')
        counts[name+'_'+outcome] += 1
    counts['l1_tier_'+first['tier']] += 1
    qwen = first['tier']=='llm'
    counts['qwen_reviews'] += qwen
    counts['qwen_errors'] += first['policy_fallback']
    counts['l2_inputs'] += eligible(first)
    gemma = bool(row['usage'])
    counts['gemma_reviews'] += gemma
    counts['gemma_model_calls_completed'] += len(row['usage'])
    counts['gemma_attack_inputs'] += gemma and truth
    counts['l2_errors'] += row['l2_error'] is not None
    counts['l2_rule_decisions'] += row['decision_source']=='l2-prefilter'
    counts['gemma_suppressions'] += row['decision_source']=='gemma' and row['decision']=='suppress'
    counts['l2_rule_suppressions'] += row['decision_source']=='l2-prefilter' and row['decision']=='suppress'
    counts['l1_elapsed_s'] += row['l1_elapsed_s']
    counts['l2_elapsed_s'] += row['l2_elapsed_s']
    if first['policy_fallback'] or row['l2_error']:
        counts['consecutive_model_errors'] += 1
    elif qwen or gemma:
        counts['consecutive_model_errors'] = 0


def journal(path):
    db = sqlite3.connect(path)
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    db.executescript('''
        CREATE TABLE IF NOT EXISTS results (
            seq INTEGER PRIMARY KEY, sample_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS attempts (
            id INTEGER PRIMARY KEY, seq INTEGER NOT NULL, started TEXT NOT NULL,
            finished TEXT, status TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS idx_attempts_status ON attempts(status);
        CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value TEXT NOT NULL);
    ''')
    with db:
        db.execute("UPDATE attempts SET status='interrupted', finished=? WHERE status='running'", (utc(),))
    saved = db.execute("SELECT value FROM state WHERE name='counts'").fetchone()
    counts = Counter(json.loads(saved[0]) if saved else {})
    total, last = db.execute('SELECT count(*), coalesce(max(seq),0) FROM results').fetchone()
    if total != last or total != counts['completed']:
        db.close()
        raise ValueError('Journal count or sequence mismatch; refusing to skip records')
    return db, counts


def finish(db, seq, attempt, row, counts):
    count_result(counts, row)
    with db:
        db.execute('INSERT INTO results VALUES (?,?,?)',
            (seq,row['sample_id'],json.dumps(row,allow_nan=False)))
        db.execute("UPDATE attempts SET status='completed',finished=? WHERE id=?", (utc(),attempt))
        db.execute("INSERT OR REPLACE INTO state VALUES ('counts',?)", (json.dumps(counts),))


def progress(out, db, counts, status, **extra):
    interrupted = db.execute("SELECT count(*) FROM attempts WHERE status='interrupted'").fetchone()[0]
    value = {'status':status, 'updated_utc':utc(), 'pid':os.getpid(),
        'total_supported':SUPPORTED, 'excluded_aminer':EXCLUDED,
        'remaining':SUPPORTED-counts['completed'], 'counts':dict(counts),
        'interrupted_attempts':interrupted, 'device_actions':0, **extra}
    write_json(out/'progress.json', value)
    text = (f'Full AIT-ADS evaluation: {status.upper()}\n'
        f'Updated (UTC): {value["updated_utc"]}\n'
        f'Processed: {counts["completed"]:,} / {SUPPORTED:,}\n'
        f'Qwen reviews: {counts["qwen_reviews"]:,}\n'
        f'L2 decisions without Gemma: {counts["l2_rule_decisions"]:,}\n'
        f'Gemma records with model replies: {counts["gemma_reviews"]:,}\n'
        f'Warnings quieted by Gemma: {counts["gemma_suppressions"]:,}\n'
        f'Qwen errors: {counts["qwen_errors"]:,}; L2 errors: {counts["l2_errors"]:,}\n'
        f'Interrupted attempts retained in journal: {interrupted:,}\n\n'
        f'Attack-labelled records kept flagged: {counts["final_tp"]:,}\n'
        f'Attack-labelled records quieted: {counts["final_fn"]:,}\n'
        f'Unannotated records still flagged: {counts["final_fp"]:,}\n'
        f'Unannotated records quieted: {counts["final_tn"]:,}\n\n'
        'These are partial results until COMPLETED. Missing attack labels do not prove harmlessness.\n'
        'Both models run locally. No device actions are enabled.\n'
        'Automatic system sleep is prevented on Windows while this worker runs; the screen can turn off.\n'
        'After an interruption, run tools/Start-FullPublicEval.ps1 to resume.\n')
    temporary = out/'STATUS.tmp'
    temporary.write_text(text,encoding='utf-8')
    temporary.replace(out/'STATUS.txt')
    print(json.dumps(value), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--cache',type=Path,default=ROOT/'output/public-eval/ait-ads')
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True,exist_ok=True)
    with instance_lock(out):
        provenance = json.loads(PROVENANCE.read_text())
        for name,key in [('ait_ads.zip','dataset_sha256'),('alerts_csv.zip','labels_sha256')]:
            if digest(args.cache/name) != provenance[key]:
                raise ValueError('Pinned public archive hash mismatch: '+name)
        second = FinalReviewL2Brain('gemma4:12b',180)
        second.backend.verify()
        models = {m['name']:m for m in ollama_json('/api/tags')['models']}
        selected = [models[name] for name in ('qwen3.5:4b','gemma4:12b')]
        if any(m.get('remote_host') or m.get('remote_model') for m in selected):
            raise ValueError('Both models must be local')
        files = sorted((ROOT/'arbiter').rglob('*.py'))+[Path(__file__),ROOT/'tools/public_dataset_eval.py']
        code = {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in files}
        dataset = {k:provenance[k] for k in ('dataset','doi','dataset_url','dataset_sha256',
            'dataset_md5','labels_url','labels_revision','labels_sha256','label_caveat')}
        dataset.update(supported_records=SUPPORTED, excluded_aminer=EXCLUDED,
            alignment={s:{k:v for k,v in a.items() if k!='sampled'} for s,a in provenance['alignment'].items()})
        meta = {'dataset':dataset, 'models':selected, 'canonical_code_sha256':code,
            'protocol':'all supported records, original scenario/file order; independent empty memory per record; existing L1 and L2 rules/models; fresh inference, no old-result reuse or deduplication; no human feedback, live collectors, temporal correlation or actions',
            'interruption_policy':'journal incomplete attempts, then resume unfinished records; completed model errors are retained and never retried until successful',
            'qwen_options':{'think':False,'temperature':.1,'format':'json','context_length':'server default, unchanged existing L1 backend'},
            'gemma_options':{'think':False,'num_ctx':8192,'num_predict':1536,'temperature':.1,'review_seconds':180},
            'python':platform.python_version()}
        meta_path = out/'run.json'
        if meta_path.exists():
            prior = json.loads(meta_path.read_text())
            if any(prior[key] != value for key,value in meta.items()):
                raise ValueError('Run inputs, models, settings or source changed; use a new output directory')
        else:
            write_json(meta_path,{**meta,'started_utc':utc()})
        db, counts = journal(out/'results.db')
        counts['consecutive_model_errors'] = 0
        backend = OllamaBackend('qwen3.5:4b','http://127.0.0.1:11434')
        status = 'running'
        last_progress = 0
        if os.name == 'nt':
            import ctypes
            if not ctypes.windll.kernel32.SetThreadExecutionState(0x80000001):
                raise OSError('Could not keep the overnight worker awake')
        progress(out,db,counts,status)
        try:
            for seq,raw,item in alerts(args.cache,provenance):
                if seq <= counts['completed']:
                    continue
                if time.monotonic()-last_progress>=30:
                    progress(out,db,counts,status,current_record=item['sample_id'])
                    last_progress=time.monotonic()
                with db:
                    attempt = db.execute("INSERT INTO attempts (seq,started,status) VALUES (?,?,'running')", (seq,utc())).lastrowid
                row = evaluate(raw,item,backend,second,out/'primary-audit.jsonl')
                finish(db,seq,attempt,row,counts)
                if counts['completed']%100==0:
                    progress(out,db,counts,status,current_record=item['sample_id'])
                    last_progress=time.monotonic()
                if counts['consecutive_model_errors']>=3:
                    raise RuntimeError('Three consecutive model failures; stopped rather than silently skipping model work')
            status = 'completed'
        except KeyboardInterrupt:
            status = 'paused'
        except BaseException as exc:
            status = 'stopped-error'
            progress(out,db,counts,status,error=f'{type(exc).__name__}: {exc}')
            raise
        finally:
            if status != 'stopped-error':
                progress(out,db,counts,status)
            db.close()
            if os.name == 'nt':
                ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)


if __name__=='__main__':
    main()
