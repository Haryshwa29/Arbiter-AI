"""Benchmark bookkeeping must not change routing, labels, timing or actions."""
from collections import Counter
import json
import threading
import time
from types import SimpleNamespace
from pathlib import Path
import subprocess
import sys
import sqlite3

import pytest

from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.service import IngestionService
from arbiter.memory import Memory
from arbiter.store import AuditStore
from tools import chronological_public_eval as benchmark
from tools.public_dataset_eval import native_from_raw, event_from_raw
from tests.test_full_public_eval import raw_event
from tests.test_l2_final_review import candidate


def wait(predicate):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        if predicate(): return
        time.sleep(.01)
    assert predicate()


def test_native_normalization_preserves_existing_legacy_interface_and_raw():
    raw=raw_event()
    native=native_from_raw(raw)
    assert native.metadata['normalized_by']!='legacy'
    assert native.raw_event['id']=='original'
    assert native.to_event().to_json()==event_from_raw(raw).to_json()
    assert 'timestamp' not in raw


def test_frozen_input_verification_rejects_mutation(tmp_path):
    path=tmp_path/'events.jsonl';path.write_text('{}\n')
    benchmark.write_json(tmp_path/'frozen-files.json',{'events.jsonl':benchmark.sha(path)})
    benchmark.verify(tmp_path)
    path.write_text('{"changed":true}\n')
    with pytest.raises(ValueError,match='changed'):benchmark.verify(tmp_path)


def test_hashing_supports_python_310_without_file_digest(tmp_path,monkeypatch):
    import hashlib
    monkeypatch.delattr(hashlib,'file_digest',raising=False)
    data=b'published input fixture'*(1024*70)
    path=tmp_path/'fixture';path.write_bytes(data)
    assert benchmark.sha(path)==hashlib.sha256(data).hexdigest()


def test_measured_real_pipeline_keeps_overlap_final_projection_and_scoring_separate(tmp_path,monkeypatch):
    memory,audit=Memory(tmp_path/'memory.db'),AuditStore(tmp_path/'audit.db')
    service=IngestionService(tmp_path/'events.db',memory,audit,'ollama','qwen3.5:4b')
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.verify',lambda self,*args: {})
    prompts=[]
    def qwen(prompt,system):
        prompts.append(prompt)
        return json.dumps(dict(decision='escalate',confidence=.99,evidence='Recorded observation',rationale='Review recorded behavior'))
    service.pipeline.engine.llm.generate=qwen
    service.enable_final_review('gemma4:12b',benchmark.NoActions(),10)
    entered,release=threading.Event(),threading.Event()
    def gemma(prompt,*args,**kwargs):
        prompts.append(prompt)
        if not entered.is_set():
            entered.set();assert release.wait(5)
        service.final_review.brain.backend.usage.append({'eval_count':5})
        if 'recommendation' in json.loads(prompt):
            return json.dumps(dict(accept=True,objections=[],citations=['F1']))
        return json.dumps(candidate())
    service.final_review.brain.backend.generate=gemma
    pipeline=benchmark.measured_pipeline(service)
    def event(identity):
        return SecurityEvent(source_type='wazuh',hostname='fixture',event_type='security_finding',
            message='Recorded observation requiring assessment',severity=4,event_id=identity)
    try:
        pipeline.start();service.buffer.enqueue(event('one'),'wazuh')
        assert entered.wait(5)
        service.buffer.enqueue(event('two'),'wazuh')
        wait(lambda: service.buffer.detail('two')['analysis'])
        assert service.buffer.detail('one')['state']=='processing'
        release.set()
        wait(lambda: all(service.buffer.detail(i)['state']=='done' for i in ('one','two')))
        row=benchmark.scored_result(service,dict(seq=1,event_id='one',expected_attack=True,label='secret-ground-truth'))
        assert row['first_stage']['decision']=='escalate'
        assert row['decision']=='suppress' and row['action_executed'] is False
        assert row['receipt_to_final_s']>=row['processing_pipeline_s']>=0
        stages=row['first_stage']['benchmark']['stages']
        assert set(stages)==set(pipeline.stages)
        assert stages['l1']['work_before_handoff_s']>=0
        counts=Counter();benchmark.add_counts(counts,row)
        assert counts['l1_tp']==1 and counts['final_fn']==1
        assert counts['qwen_records']==counts['gemma_records']==1
        assert counts['qwen_calls']==1 and counts['gemma_calls']==2
        assert not any('secret-ground-truth' in p or 'expected_attack' in p for p in prompts)
        assert len(pipeline.threads)==5 and all(t.is_alive() for t in pipeline.threads.values())
        assert not hasattr(service.final_review.agent.protection,'approve')
    finally:
        release.set();service.stop();memory.close();audit.close()


def test_usage_capture_remains_correct_after_transport_64_reply_limit(tmp_path,monkeypatch):
    # Exercise the same transport list replacement semantics without a GPU.
    memory,audit=Memory(tmp_path/'m.db'),AuditStore(tmp_path/'a.db')
    service=IngestionService(tmp_path/'e.db',memory,audit,'ollama','qwen3.5:4b')
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.verify',lambda self,*args: {})
    service.enable_final_review('gemma4:12b',benchmark.NoActions(),10)
    backend=service.final_review.brain.backend
    backend.usage=[{'eval_count':1} for _ in range(64)]
    def generate(*args,**kwargs):
        backend.usage.append({'eval_count':99});del backend.usage[:-64]
        return '{}'
    backend.generate=generate
    pipeline=benchmark.measured_pipeline(service)
    try:
        pipeline.local.job={}
        backend.generate('fixture','fixture')
        call=pipeline.local.job['benchmark_calls'][0]
        assert call['usage']['eval_count']==99 and len(backend.usage)==64
    finally:service.stop();memory.close();audit.close()


@pytest.fixture
def offline_run(tmp_path,monkeypatch):
    monkeypatch.setattr(benchmark,'frozen_imports',lambda out:None)
    monkeypatch.setattr(benchmark,'verify',lambda out:None)
    monkeypatch.setattr(benchmark,'model_identity',lambda:{'controlled':'identity'})
    monkeypatch.setattr(benchmark,'request',lambda *args:{})
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.verify',lambda self,*args:{})
    calls=[]
    def qwen(self,prompt,system):
        calls.append('qwen')
        return json.dumps(dict(decision='escalate',confidence=.99,evidence='Recorded observation',rationale='Review recorded behavior'))
    def gemma(self,prompt,*args,**kwargs):
        calls.append('gemma')
        if 'recommendation' in json.loads(prompt):
            return json.dumps(dict(accept=True,objections=[],citations=['F1']))
        return json.dumps(candidate())
    monkeypatch.setattr('arbiter.llm.OllamaBackend.generate',qwen)
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.generate',gemma)
    events=[SecurityEvent(source_type='wazuh',hostname='fixture',event_type='security_finding',severity=4,
        message='Recorded observation requiring assessment',event_id=str(i)) for i in range(3)]
    items=[dict(seq=i+1,event_id=e.event_id,expected_attack=i==0,label='attack' if i==0 else '-') for i,e in enumerate(events)]
    (tmp_path/'scorer-index.jsonl').write_text(''.join(json.dumps(i)+'\n' for i in items))
    (tmp_path/'events.jsonl').write_text(''.join(e.to_json()+'\n' for e in events))
    (tmp_path/'frozen-files.json').write_text('{}')
    return SimpleNamespace(out=tmp_path),calls


def test_runner_stops_resumes_and_does_not_rerun_completed_records(offline_run):
    args,calls=offline_run;tmp_path=args.out
    stop=tmp_path/'STOP';stop.touch()
    benchmark.run(args)
    assert json.loads((tmp_path/'progress.json').read_text())['status']=='paused'
    assert not calls
    stop.unlink()
    benchmark.run(args)
    progress=json.loads((tmp_path/'progress.json').read_text())
    assert progress['status']=='completed' and progress['counts']['completed']==3
    assert progress['counts']['final_fn']==1 and progress['counts']['final_tn']==2
    assert len((tmp_path/'decisions.jsonl').read_text().splitlines())==3
    before=list(calls)
    benchmark.run(args)
    assert calls==before


@pytest.mark.parametrize('fault',['invalid_reply','http_500'])
def test_one_failed_l2_review_stays_flagged_and_does_not_stop_following_records(offline_run,monkeypatch,fault):
    from arbiter.l2_transport import L2Transport
    from urllib.error import HTTPError
    args,calls=offline_run;original=L2Transport.generate;failed=False
    def fail_once(self,*params,**kwargs):
        nonlocal failed
        if not failed:
            failed=True
            if fault=='http_500':raise HTTPError('http://127.0.0.1:11434/api/generate',500,'Controlled server failure',None,None)
            return '{}'
        return original(self,*params,**kwargs)
    monkeypatch.setattr(L2Transport,'generate',fail_once)
    benchmark.run(args)
    saved=json.loads((args.out/'progress.json').read_text())
    assert saved['status']=='completed' and saved['counts']['completed']==3
    rows=[json.loads(line) for line in (args.out/'decisions.jsonl').read_text().splitlines()]
    bad=[r for r in rows if r['final_analysis'].get('second_stage_status')=='failed-alert-retained']
    assert len(bad)==1 and bad[0]['decision']=='escalate'
    assert saved['counts']['failed_records']==1
    assert saved['workers']['l2']['errors']==1
    assert any(r['decision']=='suppress' for r in rows)


def test_three_bad_gemma_replies_stop_even_while_qwen_is_healthy(offline_run,monkeypatch):
    args,calls=offline_run
    def invalid(*args,**kwargs):
        time.sleep(.03)
        return '{}'
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.generate',invalid)
    with pytest.raises(RuntimeError,match='Three consecutive model failures'):benchmark.run(args)
    saved=json.loads((args.out/'progress.json').read_text())
    assert saved['counts']['gemma_consecutive_errors']==3
    assert saved['counts']['qwen_consecutive_errors']==0


def test_resumed_qwen_verdict_is_counted_without_inventing_a_second_model_call():
    counts=Counter()
    row={'expected_attack':False,'decision':'suppress','state':'done',
        'first_stage':{'tier':'llm','backend':'ollama','decision':'suppress','rationale':'Saved Qwen assessment'},
        'final_analysis':{}}
    benchmark.add_counts(counts,row)
    assert counts['qwen_records']==1 and counts['qwen_calls']==0


def test_transient_result_write_failure_preserves_completed_rows_for_final_checkpoint(offline_run,monkeypatch):
    args,calls=offline_run;connect=sqlite3.connect
    class FlakyLedger:
        failed=False
        def __init__(self,db):self.db=db
        def __getattr__(self,name):return getattr(self.db,name)
        def __enter__(self):self.db.__enter__();return self
        def __exit__(self,*params):return self.db.__exit__(*params)
        def execute(self,sql,*params):
            if sql.startswith('INSERT INTO results') and not self.failed:
                self.failed=True
                raise sqlite3.OperationalError('Controlled ledger failure')
            return self.db.execute(sql,*params)
    def wrapped(path,*params,**kwargs):
        db=connect(path,*params,**kwargs)
        return FlakyLedger(db) if Path(str(path)).name=='results.db' else db
    monkeypatch.setattr(benchmark.sqlite3,'connect',wrapped)
    with pytest.raises(sqlite3.OperationalError,match='Controlled ledger failure'):benchmark.run(args)
    with connect(args.out/'events.db') as db:
        finished={r[0] for r in db.execute("SELECT event_id FROM telemetry WHERE state='done'")}
    with connect(args.out/'results.db') as db:
        saved={r[0] for r in db.execute('SELECT event_id FROM results')}
    assert finished and finished<=saved


@pytest.mark.skipif(sys.platform!='win32',reason='Windows supervisor')
def test_supervisor_refuses_to_resume_a_running_checkpoint_before_touching_dashboard(tmp_path):
    (tmp_path/'run_eval.py').write_text('')
    benchmark.write_json(tmp_path/'progress.json',{'status':'running','pid':0,'counts':{'completed':1}})
    supervisor=Path(__file__).resolve().parents[1]/'tools/Start-ChronologicalPublicEval.ps1'
    result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(supervisor),
        '-RunDirectory',str(tmp_path),'-PythonPath',sys.executable,'-Resume'],capture_output=True,text=True,timeout=15)
    assert result.returncode!=0
    state=json.loads((tmp_path/'supervisor.json').read_text(encoding='utf-8-sig'))
    assert state['status']=='supervisor-failed'
    assert 'stopped or paused' in state['error']
    assert 'dashboard_restart_requested_utc' not in state


@pytest.mark.skipif(sys.platform!='win32',reason='Windows supervisor')
def test_supervisor_reports_missing_preparation_as_a_failed_command(tmp_path):
    supervisor=Path(__file__).resolve().parents[1]/'tools/Start-ChronologicalPublicEval.ps1'
    result=subprocess.run(['powershell.exe','-NoProfile','-ExecutionPolicy','Bypass','-File',str(supervisor),
        '-RunDirectory',str(tmp_path),'-PythonPath',sys.executable],capture_output=True,text=True,timeout=15)
    assert result.returncode!=0
    state=json.loads((tmp_path/'supervisor.json').read_text(encoding='utf-8-sig'))
    assert state['status']=='supervisor-failed'
    assert 'dashboard_restart_requested_utc' not in state


@pytest.mark.skipif(sys.platform!='win32',reason='Windows supervisor')
@pytest.mark.parametrize('leave_stopped,originally_enabled,expected',[(True,True,[]),(False,True,['/Enable','/Run']),(False,False,[])])
def test_supervisor_honors_requested_dashboard_shutdown_without_real_task_changes(tmp_path,leave_stopped,originally_enabled,expected):
    supervisor=Path(__file__).resolve().parents[1]/'tools/Start-ChronologicalPublicEval.ps1'
    probe=tmp_path/'probe.ps1'
    probe.write_text(r'''
param([string]$Source,[int]$LeaveStopped,[int]$OriginallyEnabled)
$ErrorActionPreference='Stop'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($Source,[ref]$null,[ref]$null)
$node=$ast.EndBlock.Statements | Where-Object {$_ -is [System.Management.Automation.Language.TryStatementAst]} | Select-Object -First 1
$body=$node.Finally.Extent.Text
$taskState=@{}; $taskPauseAttempted=$true; $taskDisabled=$true
$LeaveDashboardStopped=[bool]$LeaveStopped; $taskOriginallyEnabled=[bool]$OriginallyEnabled
$script:actions=@()
function Save-State {}
function Invoke-ArbiterTask($action,$log) { $script:actions+= $action; return 0 }
. ([scriptblock]::Create($body.Substring(1,$body.Length-2)))
@{actions=@($script:actions);state=$taskState} | ConvertTo-Json -Depth 5 -Compress
''')
    result=subprocess.run(['powershell.exe','-NoProfile','-File',str(probe),'-Source',str(supervisor),
        '-LeaveStopped',str(int(leave_stopped)),'-OriginallyEnabled',str(int(originally_enabled))],capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    saved=json.loads(result.stdout)
    assert saved['actions']==expected
    assert ('dashboard_restart_requested_utc' in saved['state'])==bool(expected)
    if leave_stopped:assert 'Owner requested termination' in saved['state']['dashboard_restart_note']
