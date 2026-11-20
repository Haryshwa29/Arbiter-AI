"""Compact evidence-bound decisions and durable reports without inference."""
import json
import sqlite3
import threading
import time
from unittest.mock import Mock

import pytest

from arbiter.ingestion.schema import SecurityEvent
from arbiter.ingestion.service import IngestionService
from arbiter.l2_final_review import FinalReviewL2Brain
from arbiter.memory import Memory
from arbiter.store import AuditStore
from arbiter.reports import render,snapshot
from tests.test_l2_final_review import first


def compact(**changes):
    return dict(decision='suppress',confidence=.95,
        decision_reason='The recorded source describes an ordinary update.',
        benign_explanation='An ordinary update explains the recorded action.',
        suspicious_explanation='Unverified software activity could require review.',
        gaps='Authorization must be checked against the original record.',
        evidence_ids=['A1'],**changes)


def event(identity='one'):
    return SecurityEvent(source_type='wazuh',hostname='fixture',event_type='security_finding',
        severity=4,message='Recorded observation',event_id=identity)


def brain(data=None,accept=True):
    b=FinalReviewL2Brain('gemma4:12b')
    b.backend.generate=Mock(side_effect=[json.dumps(data or compact()),
        json.dumps(dict(accept=accept,objections=[] if accept else ['Ordinary cause is unsupported'],citations=['F1']))])
    return b


def test_compact_decision_references_actual_facts_and_persists_the_packet():
    b=brain();r=b.review_event(event().to_event(),first())
    request=json.loads(b.backend.generate.call_args_list[0].args[0])
    schema=b.backend.generate.call_args_list[0].kwargs['format_schema']
    assert schema['properties']['evidence_ids']['items']['enum']==['A1']
    assert set(schema['properties'])==set(compact())
    assert not {'assessment','hypotheses','recovery','recommendation'}&set(schema['properties'])
    assert b.backend.num_predict==768 and b.backend.think is False
    assert r['decision']=='suppress' and r['action_authority'] is False
    assert r['assertions']==[dict(fact_id='F1',field='event_type',value='security_finding')]
    assert r['decision_receipt']['evidence_packet']==request['evidence_packet']
    assert r['decision_receipt']['final_decision']=='suppress'
    assert r['report_template']=='security-event-v1'
    challenge=json.loads(b.backend.generate.call_args_list[1].args[0])
    assert challenge['recommendation']==compact()


@pytest.mark.parametrize('change',[
    {'evidence_ids':['invented']},{'evidence_ids':['A1','A1']},{'evidence_ids':[]},
    {'decision':'ignore'},{'confidence':True},{'confidence':float('nan')},
    {'benign_explanation':''},{'decision_reason':'x'*321},{'action':'block_ip'},
])
def test_compact_invalid_reply_never_reaches_suppression(change):
    data=compact();data.update(change);b=brain(data)
    with pytest.raises(ValueError):b.review_event(event().to_event(),first())
    assert b.backend.generate.call_count==1


def test_compact_suppression_still_needs_confidence_and_challenge():
    low=compact();low['confidence']=.89
    assert brain(low).review_event(event().to_event(),first())['decision']=='escalate'
    assert brain(accept=False).review_event(event().to_event(),first())['decision']=='escalate'
    keep=compact();keep['decision']='escalate';b=brain(keep)
    assert b.review_event(event().to_event(),first())['decision']=='escalate'
    assert b.backend.generate.call_count==1


@pytest.fixture
def service(tmp_path):
    m,a=Memory(tmp_path/'memory.db'),AuditStore(tmp_path/'audit.db')
    s=IngestionService(tmp_path/'events.db',m,a)
    try:yield s
    finally:s.stop();m.close();a.close()


def finish(service,identity='one',decision='suppress'):
    e=event(identity);service.buffer.enqueue(e,'wazuh')
    row=service.buffer.detail(identity)
    service.buffer.finish(row['id'],dict(event_id=identity,decision=decision,tier='llm',backend='ollama',model='qwen3.5:4b',
        score=4,rationale='Recorded short decision reason.',evidence='Recorded event type',model_confidence=.95),[],1)
    return service.buffer.detail(identity)


def test_report_is_durable_and_does_not_modify_the_decision_or_call_models(service):
    original=finish(service)
    service.pipeline.engine.llm.triage=Mock(side_effect=AssertionError('No inference for reports'))
    assert service.project(original)['report']['state']=='pending'
    assert service.reports.process_one()
    shown=service.project(service.buffer.detail('one'))
    assert shown['report']['state']=='ready'
    assert shown['report']['body']['brief']['why']=='Recorded short decision reason.'
    assert shown['report']['body']['decision']=='suppress'
    assert shown['report']['body']['action_authority'] is False
    assert service.buffer.detail('one')['analysis']==original['analysis']
    service.pipeline.engine.llm.triage.assert_not_called()


def test_partial_template_shows_recorded_facts_without_inventing_a_decision(service):
    service.buffer.enqueue(event(),'wazuh')
    row=service.project(service.buffer.detail('one'))
    assert row['report']['state']=='partial'
    assert row['report']['body']['decision'] is None
    assert row['report']['body']['brief']['observed']=='Recorded observation'
    assert row['report']['body']['brief']['why']=='Analysis is pending.'
    assert row['report']['body']['action_authority'] is False


def test_failed_analysis_still_has_an_evidence_report_without_a_fabricated_verdict(service):
    service.buffer.enqueue(event(),'wazuh')
    row=service.buffer.detail('one');service.buffer.fail(row['id'])
    service.reports.process_one()
    shown=service.project(service.buffer.detail('one'))
    assert shown['report']['state']=='ready' and shown['analysis'] is None
    assert shown['report']['body']['decision'] is None
    assert 'Analysis failed' in shown['report']['body']['brief']['why']


def test_render_failure_preserves_decision_and_can_be_requeued(service,monkeypatch):
    finish(service)
    with monkeypatch.context() as patch:
        patch.setattr('arbiter.ingestion.report_worker.render',Mock(side_effect=ValueError('controlled failure')))
        assert service.reports.process_one()
    shown=service.project(service.buffer.detail('one'))
    assert shown['report']['state']=='failed' and shown['analysis']['decision']=='suppress'
    service.buffer.queue_report('one');service.reports.process_one()
    assert service.project(service.buffer.detail('one'))['report']['state']=='ready'


def test_old_render_cannot_overwrite_a_new_decision_revision(service,monkeypatch):
    finish(service);entered,release=threading.Event(),threading.Event()
    actual=render
    def slow(value):
        entered.set();assert release.wait(5)
        return actual(value)
    with monkeypatch.context() as patch:
        patch.setattr('arbiter.ingestion.report_worker.render',slow)
        thread=threading.Thread(target=service.reports.process_one)
        try:
            thread.start();assert entered.wait(5)
            row=service.buffer.detail('one');updated={**row['analysis'],'decision':'escalate','rationale':'A person requested review.'}
            service.buffer.finish(row['id'],updated,[],1)
        finally:release.set();thread.join(5)
    assert service.project(service.buffer.detail('one'))['report']['state']=='pending'
    service.reports.process_one()
    assert service.project(service.buffer.detail('one'))['report']['body']['decision']=='escalate'


def test_slow_report_worker_does_not_block_the_decision_pipeline(service,monkeypatch):
    entered,release=threading.Event(),threading.Event()
    def slow(value):
        entered.set();assert release.wait(5)
        return render(value)
    monkeypatch.setattr('arbiter.ingestion.report_worker.render',slow)
    try:
        service.start();service.buffer.enqueue(event('one'),'wazuh')
        assert entered.wait(5)
        service.buffer.enqueue(event('two'),'wazuh')
        deadline=time.monotonic()+5
        while time.monotonic()<deadline and service.buffer.detail('two')['state']!='done':time.sleep(.02)
        assert service.buffer.detail('two')['state']=='done'
        assert service.project(service.buffer.detail('one'))['report']['state']=='pending'
        assert service.reports.thread.name=='arbiter-reports'
    finally:release.set()


def test_pending_reports_survive_restart_without_an_eager_history_backfill(tmp_path):
    m,a=Memory(tmp_path/'m.db'),AuditStore(tmp_path/'a.db')
    s=IngestionService(tmp_path/'e.db',m,a)
    finish(s);s.stop()
    s=IngestionService(tmp_path/'e.db',m,a)
    try:
        assert s.reports.status()['queued']==1
        s.reports.process_one()
        assert s.project(s.buffer.detail('one'))['report']['state']=='ready'
    finally:s.stop();m.close();a.close()


def test_report_retention_follows_the_underlying_event(service):
    finish(service);service.reports.process_one()
    with service.buffer.lock,service.buffer.conn:
        service.buffer.conn.execute("UPDATE telemetry SET received_at='2000-01-01T00:00:00+00:00'")
    service.buffer.prune()
    assert service.buffer.detail('one') is None
    assert service.reports.status()['completed']==0


def test_learned_template_preserves_origin_without_claiming_another_model_review(service):
    memory=service.pipeline.engine.memory;e=event().to_event()
    memory.learn_pattern('l2','exact-key',e,'gemma4:12b','Recorded ordinary explanation',now=100)
    hit=memory.match_pattern('l2','exact-key',now=101)
    assert hit['report_template']=='security-event-v1'
    row=finish(service,'repeat')
    row['analysis']['learned_pattern']=dict(hit,stage='l1')
    body=render(snapshot(row))
    assert body['reviewer']=='L1 pre-filter'
    assert body['brief']['origin']['Learned pattern origin']=='one'
    assert 'did not review this record again' in body['brief']['origin']['Current review']
    with pytest.raises(ValueError):memory.learn_pattern('l2','other',e,'gemma4:12b','Reason',report_template='untrusted-template')
    memory.revoke_pattern('l2','exact-key')
    assert memory.match_pattern('l2','exact-key',now=102) is None


def test_template_migration_keeps_existing_learned_rules(tmp_path):
    path=tmp_path/'old.db'
    with sqlite3.connect(path) as db:
        db.execute('CREATE TABLE learned_patterns (stage TEXT,pattern_key TEXT,signature TEXT,host TEXT,model TEXT,reason TEXT,'
            'origin_event TEXT,expires REAL,hits INTEGER DEFAULT 0,blocked INTEGER DEFAULT 0,PRIMARY KEY(stage,pattern_key))')
        db.execute("INSERT INTO learned_patterns VALUES ('l1','key','sig','host','qwen','reason','origin',1000,0,0)")
    memory=Memory(path)
    try:
        hit=memory.match_pattern('l1','key',now=100)
        assert hit['origin_event']=='origin' and hit['report_template']==''
        assert memory.match_pattern('l1','key',now=1001) is None
    finally:memory.close()


def test_l1_receipt_keeps_the_actual_model_context_without_changing_verdict_schema(service,monkeypatch):
    from arbiter.llm import OllamaBackend
    backend=OllamaBackend('qwen3.5:4b');seen=[]
    def generate(prompt,system):
        seen.append(json.loads(prompt))
        return json.dumps(dict(decision='suppress',confidence=.95,evidence='Recorded event',rationale='Recorded ordinary behavior'))
    backend.generate=generate;service.pipeline.engine.llm=backend
    monkeypatch.setattr('arbiter.ingestion.pipeline.correlate',lambda *args,**kwargs:[])
    service.buffer.enqueue(event(),'wazuh');assert service.pipeline.process_one()
    row=service.buffer.detail('one');receipt=row['analysis']['decision_receipt']
    assert receipt['evidence_packet']==seen[0]
    assert receipt['final_decision']==row['analysis']['decision']
    saved=service.pipeline.audit.verdict_for_event('one')
    assert json.loads(saved['detail'])['fields']['_decision_receipt']==receipt


def test_human_rejection_rebuilds_report_from_the_final_visible_decision(service):
    from types import SimpleNamespace
    from arbiter.l2_workflow import L2Workflow
    e=event();r=brain().review_event(e.to_event(),first())
    service.buffer.enqueue(e,'wazuh')
    row=service.buffer.detail(e.event_id)
    service.buffer.finish(row['id'],dict(first(),event_id=e.event_id),[],1)
    host=SimpleNamespace(service=service,memory=service.pipeline.engine.memory,audit=service.pipeline.audit,
        protection=SimpleNamespace(),scope=None,actor='test')
    workflow=L2Workflow(host,brain());service.final_review=workflow
    case=dict(id='case',event_id=e.event_id,severity='low',created=1,deadline=None,state='needs_review',brief=r,action_id=None)
    workflow.save(case)
    service.reports.process_one()
    assert service.project(service.buffer.detail('one'))['report']['body']['decision']=='suppress'
    workflow.control('reject','case','A person requires further investigation')
    assert service.project(service.buffer.detail('one'))['report']['body'] is None
    service.reports.process_one()
    assert service.project(service.buffer.detail('one'))['report']['body']['decision']=='escalate'


def test_event_templates_are_distinct_and_never_authorize_actions(service):
    row=finish(service);row['event']['event_type']='auth_success'
    auth=render(snapshot(row))
    assert auth['template_id']=='authentication-v1'
    assert any('absence of failed logins' in check for check in auth['checks'])
    row['event']['event_type']='web_request'
    web=render(snapshot(row))
    assert web['checks']!=auth['checks'] and web['checks_source']=='template'
    assert web['action_authority'] is False


def test_l1_repeat_uses_its_learned_template_without_another_model_call(service):
    from arbiter.llm import OllamaBackend,LLMVerdict
    from arbiter.schema import Decision
    from tests.test_learned_patterns import native
    backend=OllamaBackend('qwen3.5:4b')
    backend.triage=Mock(return_value=LLMVerdict(Decision.SUPPRESS,.95,'Recorded inventory','Recorded routine inventory'))
    service.pipeline.engine.llm=backend
    for e in (native(),native('two')):
        service.buffer.enqueue(e,'wazuh');assert service.pipeline.process_one()
    assert backend.triage.call_count==1
    repeat=service.buffer.detail(native('two').event_id)
    assert repeat['analysis']['learned_pattern']['report_template']=='security-event-v1'
    while service.reports.process_one():pass
    body=service.project(repeat)['report']['body']
    assert body['reviewer']=='L1 pre-filter'
    assert body['brief']['origin']['Learned pattern origin']==native().event_id


@pytest.mark.parametrize('body',['{broken',json.dumps({'event_id':'another-event','decision':'suppress','action_authority':False})])
def test_corrupt_report_never_hides_the_saved_decision(service,body):
    finish(service);service.reports.process_one()
    with service.buffer.lock,service.buffer.conn:
        service.buffer.conn.execute('UPDATE decision_reports SET body=?',(body,))
    row=service.project(service.buffer.detail('one'))
    assert row['analysis']['decision']=='suppress'
    assert row['report']['state']=='failed' and row['report']['body'] is None
