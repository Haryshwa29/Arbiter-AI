"""The second brain can add advice, but cannot clear alerts or gain action rights."""
import copy
import json
from unittest.mock import Mock

import pytest

from arbiter.agent import Agent
from arbiter.l2 import L2Brain
from arbiter.l2_advisory import AdvisoryL2Brain, packet_for
from arbiter.l2_workflow import L2Workflow
from arbiter.schema import Event


def event():
    return Event(source='wazuh',host='public-lab',event_type='security_finding',
        message='Recorded protocol anomaly; cause is not established',timestamp='2022-01-01T00:00:00Z',id='public-record')


def first():
    return {'decision':'escalate','tier':'llm','rationale':'Precautionary review','evidence':'Check source record',
        'expected_attack':True,'label':'must-not-enter-the-prompt'}


def candidate():
    d={k:'One short review sentence.' for k in ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')}
    d.update(action='human_review',target=None,confidence=.8,outlook='uncertain',
        assertions=[{'fact_id':'F1','field':'event_type','value':'security_finding'}],
        hypotheses=[{'kind':k,'summary':'Explanation to check','supports':['F1'],'against':[]} for k in ('malicious','benign')])
    return d


def brain(d=None,critic=None):
    b=AdvisoryL2Brain('gemma4:12b',180)
    b.backend.generate=Mock(side_effect=[json.dumps(d or candidate()),json.dumps(critic or {'accept':True,'objections':[],'citations':['F1']})])
    return b


def test_historical_review_preserves_time_and_has_no_execution_rights():
    e=event();packet=packet_for(e,first(),True)
    assert packet['facts'][0]['timestamp']==e.timestamp
    assert packet['mode']=='historical_replay_advice' and packet['action_authority'] is False
    assert 'must-not-enter-the-prompt' not in json.dumps(packet) and 'expected_attack' not in json.dumps(packet)
    b=brain();result=b.review_event(e,first(),True)
    assert result['alert_decision']=='escalate' and result['action']=='human_review'
    assert result['target'] is None and result['action_authority'] is False
    assert result['review_status']=='accepted' and b.backend.generate.call_count==2
    assert not b.authorize({'action':'block_ip','target':'10.0.0.1','guardrail':{'version':2,'grounded':True}}, {}, {'target':'10.0.0.1'})


def test_advice_transport_is_bounded_and_native_defaults_are_unchanged():
    advisory=AdvisoryL2Brain('gemma4:12b')
    native=L2Brain('gemma4:12b')
    assert advisory.backend.think is False and advisory.backend.num_ctx==8192 and advisory.backend.num_predict==1536
    assert native.backend.think is True and native.backend.num_ctx==16384 and native.backend.num_predict==3072


@pytest.mark.parametrize('mutation',['block','suppress','target','invented_fact','wrong_value','outlook','one_hypothesis'])
def test_invalid_advice_is_rejected(mutation):
    d=candidate()
    if mutation=='block':d['action']='block_ip'
    if mutation=='suppress':d['action']='suppress'
    if mutation=='target':d['target']='10.0.0.1'
    if mutation=='invented_fact':d['assertions'][0]['fact_id']='F99'
    if mutation=='wrong_value':d['assertions'][0]['value']='malware_detection'
    if mutation=='outlook':d['outlook']='definitely_safe'
    if mutation=='one_hypothesis':d['hypotheses']=d['hypotheses'][:1]
    with pytest.raises(ValueError):brain(d).review_event(event(),first(),True)


def test_challenge_can_mark_uncertain_but_never_remove_alert():
    d=candidate();d['outlook']='routine_looking'
    b=brain(d,{'accept':False,'objections':['Missing authorization context'],'citations':['F1']})
    r=b.review_event(event(),first(),True)
    assert r['outlook']=='uncertain' and r['proposed_outlook']=='routine_looking'
    assert r['alert_decision']=='escalate' and r['review_status']=='challenged'


@pytest.mark.parametrize('critic',[{'accept':True,'objections':[],'citations':[]},
    {'accept':True,'objections':[],'citations':['F99']},{'accept':'yes','objections':[],'citations':['F1']}])
def test_invalid_challenge_is_not_successful_review(critic):
    with pytest.raises(ValueError):brain(critic=critic).review_event(event(),first(),True)


def test_no_secondary_call_on_a_quiet_observation():
    b=brain()
    with pytest.raises(ValueError):b.review_event(event(),{'decision':'suppress'},True)
    b.backend.generate.assert_not_called()


def test_native_action_evidence_rules_remain_strict():
    row={'connector':'replay','event':{'event_id':'x','hostname':'public-lab','timestamp':'2022-01-01T00:00:00+00:00','source_type':'wazuh','tags':['replay'],'message':'recorded'}}
    b=L2Brain('gemma4:12b');b.backend.generate=Mock()
    with pytest.raises(ValueError,match='no current locally sourced'):b.review(row,None)
    b.backend.generate.assert_not_called()


def test_advice_mode_rejects_automatic_policy_and_same_model(tmp_path):
    a=Agent(tmp_path,backend='ollama',model='qwen3.5:4b',firewall=Mock())
    try:
        with pytest.raises(ValueError):a.enable_l2('gemma4:12b',{'automatic':True},advice_only=True)
        with pytest.raises(ValueError):a.enable_l2('qwen3.5:4b',advice_only=True)
    finally:a.close()


def test_workflow_routes_only_model_alerts_and_never_calls_protection(tmp_path):
    from arbiter.ingestion.schema import SecurityEvent
    a=Agent(tmp_path,firewall=Mock())
    b=brain();w=L2Workflow(a,b);a.l2=w
    try:
        for suffix,sev in [('rule',9),('model',4)]:
            e=SecurityEvent(source_type='wazuh',hostname='owned-lab',event_type='security_finding',message='recorded anomaly',severity=sev,event_id=suffix)
            a.service.buffer.enqueue(e,'wazuh');a.service.pipeline.process_one()
        w.tick()
        assert len(w.cases())==1 and w.cases()[0]['event_id']=='model'
        assert w.jobs.qsize()==1
        a.protection.firewall.block.assert_not_called()
    finally:a.close()
