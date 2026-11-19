"""Automatic learning stays exact, short lived, revocable and stage separated."""
import copy
import json
from unittest.mock import Mock

import pytest

from arbiter.ingestion.normalization import normalize
from arbiter.ingestion.pipeline import Pipeline
from arbiter.ingestion.store import EventBuffer
from arbiter.learned_patterns import pattern_key
from arbiter.llm import LLMVerdict,OllamaBackend
from arbiter.memory import Memory
from arbiter.schema import Decision
from arbiter.store import AuditStore
from arbiter.triage import TriageEngine
from tests.test_review_pipeline import setup_agent,done,wait_for


def native(identity='one',host='shared-agent',agent='1',message='Recorded routine inventory notification'):
    return normalize({'id':identity,'timestamp':'2026-11-18T10:00:00Z',
        'agent':{'name':host,'id':agent,'ip':'192.0.2.'+agent},
        'rule':{'id':'100123','level':4,'description':message,'groups':['inventory']},
        'full_log':message,'data':{'package':'example','version':'1.0'}},'wazuh')


def test_l1_remembers_only_model_suppressions_and_changed_details_call_model(tmp_path):
    memory=Memory(tmp_path/'memory.db');audit=AuditStore(tmp_path/'audit.db');buffer=EventBuffer(tmp_path/'events.db')
    model=OllamaBackend('qwen3.5:4b');model.triage=Mock(return_value=LLMVerdict(Decision.SUPPRESS,.95,'Inventory record','Recorded routine inventory'))
    engine=TriageEngine(memory,model,tmp_path/'triage.jsonl');pipeline=Pipeline(buffer,engine,audit)
    try:
        for event in (native(),native('two'),native('three',agent='2'),native('four',message='New command was executed')):
            buffer.enqueue(event,'wazuh');assert pipeline.process_one()
        assert model.triage.call_count==3
        row=buffer.detail(native('two').event_id)
        assert row['analysis']['tier']=='prefilter' and 'learned exact routine pattern' in row['analysis']['rationale']
        assert memory.learned_counts()['l1']['hits']==1
        # A guardrail signal cannot inherit the routine decision.
        attack=native('five',message='powershell -enc SQBFAFgA')
        buffer.enqueue(attack,'wazuh');pipeline.process_one()
        assert buffer.detail(attack.event_id)['analysis']['decision']=='escalate'
    finally:buffer.close();audit.close();memory.close()


def test_memory_persists_but_expires_and_does_not_train_on_its_own_hits(tmp_path):
    path=tmp_path/'memory.db';memory=Memory(path);event=native().to_event()
    memory.learn_pattern('l1','key',event,'qwen','Reason',now=100)
    memory.close();memory=Memory(path)
    try:
        assert memory.match_pattern('l2','key',now=101) is None
        for n in range(25):assert memory.match_pattern('l1','key',now=101)['hit']==n+1
        memory.learn_pattern('l1','key',event,'qwen','Same origin cannot renew',now=102)
        assert memory.match_pattern('l1','key',now=103) is None
        event.id='new-model-review';memory.learn_pattern('l1','key',event,'qwen','Fresh model review',now=104)
        assert memory.match_pattern('l1','key',now=105)
        assert memory.match_pattern('l1','key',now=3705) is None
    finally:memory.close()


def test_human_feedback_revokes_and_prevents_automatic_relearning(tmp_path):
    memory=Memory(tmp_path/'memory.db');event=native().to_event()
    try:
        memory.learn_pattern('l1','key',event,'qwen','Reason')
        memory.label_verdicts(event.signature,'overruled')
        event.id='new';memory.learn_pattern('l1','key',event,'qwen','Another model opinion')
        assert memory.match_pattern('l1','key') is None
    finally:memory.close()


def test_fingerprint_is_not_a_host_or_signature_allowlist(tmp_path):
    memory=Memory(tmp_path/'memory.db');event=native()
    try:
        key=pattern_key(event,'wazuh',memory,'qwen')
        assert key and key==pattern_key(native('two'),'wazuh',memory,'qwen')
        assert key!=pattern_key(native(agent='2'),'wazuh',memory,'qwen')
        assert key!=pattern_key(event,'wazuh',memory,'different-model')
        changed=copy.deepcopy(event);changed.raw_event['rule']['id']='100124'
        assert key!=pattern_key(changed,'wazuh',memory,'qwen')
        changed=copy.deepcopy(event);changed.raw_event['data']['version']='2.0'
        assert key!=pattern_key(changed,'wazuh',memory,'qwen')
        memory.add_fact('Inventory procedure changed',event.hostname)
        assert key!=pattern_key(event,'wazuh',memory,'qwen')
        for connector in ('api','file','replay','demo'):
            assert pattern_key(event,connector,memory,'qwen') is None
        assert pattern_key(event,'wazuh',memory,'qwen',True) is None
        event.metadata['correlation']=[{'rule':'new-risk'}]
        assert pattern_key(event,'wazuh',memory,'qwen') is None
    finally:memory.close()


def test_l2_repeats_use_its_own_prefilter_and_human_rejection_revokes(tmp_path,monkeypatch):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    try:
        first=native();agent.service.buffer.enqueue(first,'wazuh');wait_for(lambda:done(agent,first.event_id))
        assert brain.backend.generate.call_count==2
        second=native('two');agent.service.buffer.enqueue(second,'wazuh');wait_for(lambda:done(agent,second.event_id))
        rows=agent.service.project_rows([agent.service.buffer.detail(second.event_id)])
        assert brain.backend.generate.call_count==2
        assert rows[0]['analysis']['decision']=='suppress'
        assert rows[0]['analysis']['second_stage']['prefilter']['rule']=='L2_LEARNED_EXACT_PATTERN'
        case=agent.l2.cases(event_ids=[second.event_id])[0]
        agent.l2.control('reject',case['id'],'Investigate this pattern')
        third=native('three');agent.service.buffer.enqueue(third,'wazuh');wait_for(lambda:done(agent,third.event_id))
        assert brain.backend.generate.call_count==4
        assert agent.memory.learned_counts().get('l2',{}).get('patterns',0)==0
        assert not agent.memory.learned_counts().get('l1')
    finally:agent.close()


def test_recovered_l2_brief_cannot_reteach_an_expired_pattern(tmp_path,monkeypatch):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    try:
        event=native();service=agent.service
        service.buffer.enqueue(event,'wazuh');wait_for(lambda:done(agent,event.event_id))
        service.pipeline.stop()
        with agent.memory._lock,agent.memory.conn:
            agent.memory.conn.execute('DELETE FROM learned_patterns')
        with service.buffer.lock,service.buffer.conn:
            service.buffer.conn.execute("UPDATE telemetry SET state='pending' WHERE event_id=?",(event.event_id,))
        from arbiter.ingestion.review_pipeline import ReviewPipeline
        service.pipeline=ReviewPipeline(service.buffer,service.pipeline.engine,agent.audit,agent.l2)
        service.pipeline.start();wait_for(lambda:done(agent,event.event_id))
        assert brain.backend.generate.call_count==2
        assert agent.memory.learned_counts()=={}
    finally:agent.close()


def test_a_maintenance_window_does_not_cover_the_same_pattern_at_another_time(tmp_path):
    memory=Memory(tmp_path/'memory.db')
    try:
        event=native();event.timestamp='2026-11-18T10:15:00Z'
        memory.add_fact('Approved inventory window',event.hostname,window='10:00-11:00')
        within=pattern_key(event,'wazuh',memory,'qwen')
        event.timestamp='2026-11-18T18:15:00Z'
        assert within!=pattern_key(event,'wazuh',memory,'qwen')
    finally:memory.close()


def test_parallel_context_uses_ordered_time_index_without_sorting_history(tmp_path):
    buffer=EventBuffer(tmp_path/'events.db');queries=[]
    try:
        buffer.conn.set_trace_callback(queries.append)
        buffer.recent(native(),review_pending=True)
        sql=next(q for q in queries if q.startswith('SELECT payload,connector FROM telemetry'))
        buffer.conn.set_trace_callback(None)
        plan=' '.join(str(tuple(row)) for row in buffer.conn.execute('EXPLAIN QUERY PLAN '+sql))
        assert 'idx_telemetry_review_context' in plan
        assert 'TEMP B-TREE' not in plan and 'SCAN telemetry' not in plan
    finally:buffer.close()
