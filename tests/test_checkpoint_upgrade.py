"""Run against the staged candidate, then ship in tests with its reviewed patch."""
import copy
import json
from unittest.mock import Mock

import pytest

from arbiter.guardrails import guardrail_check, final_guardrail_check
from arbiter.ingestion.normalization import normalize
from arbiter.learned_patterns import pattern_key
from arbiter.memory import Memory
from tests.test_learned_patterns import native


def web(groups=None,decoder='web-accesslog'):
    return {'id':'observation','timestamp':'2026-11-19T00:00:00Z',
        'agent':{'id':'1','name':'web','ip':'192.0.2.1'},
        'rule':{'id':'31516','level':6,'description':'Suspicious URL access.',
            'groups':groups or ['web','appsec','attack']},
        'decoder':{'name':decoder},'data':{'id':'404','protocol':'GET','url':'/.htpasswd'},
        'full_log':'192.0.2.2 - - "GET /.htpasswd HTTP/1.1" 404'}


def test_source_attack_group_does_not_require_an_accesslog_group_alias():
    e=normalize(web(),'wazuh').to_event()
    assert guardrail_check(e).code=='NON_SUPPRESSIBLE_WEB_ALERT'
    assert final_guardrail_check(e,'suppress').code=='NON_SUPPRESSIBLE_WEB_ALERT'


def test_ordinary_access_log_404_and_unverified_upload_are_not_source_attack_proof():
    data=web(['web','accesslog']);data['data']['url']='/ordinary-missing-image.png'
    assert guardrail_check(normalize(data,'wazuh').to_event()) is None
    data['decoder']['name']='unrelated-decoder';data['rule']['groups']=['web','attack']
    assert guardrail_check(normalize(data,'wazuh').to_event()) is None


@pytest.mark.parametrize('code,text',[
    ('AH01630','AH01630: client denied by server configuration: /var/www/example/.htpasswd'),
    ('AH01276','AH01276: Cannot serve directory /var/www/example/: No matching DirectoryIndex found, and server-generated directory index forbidden by Options directive')])
def test_native_denied_access_is_reviewed_without_claiming_a_successful_breach(code,text):
    data=web(['apache','web','access_denied'],'apache-errorlog')
    data['data']={'id':code};data['full_log']=text
    assert guardrail_check(normalize(data,'wazuh').to_event()).code=='NON_SUPPRESSIBLE_WEB_ALERT'
    data['decoder']['name']='generic'
    assert guardrail_check(normalize(data,'wazuh').to_event()) is None


def test_missing_http_request_cannot_be_dismissed_as_a_known_harmless_decoder_fault():
    data=web(['ids','suricata'],'json')
    data['rule'].update(id='86601',description='Suricata: Alert')
    data['data']={'event_type':'alert','alert':{'severity':'3','signature_id':'2221010',
        'signature':'SURICATA HTTP unable to match response to request','category':'Generic Protocol Command Decode'}}
    data['full_log']='SURICATA HTTP unable to match response to request'
    assert final_guardrail_check(normalize(data,'wazuh').to_event(),'suppress').code=='L2_HTTP_REQUEST_UNOBSERVED'
    data['data']['alert']['signature']='ET INFO Observed TLS Connection'
    data['full_log']='ET INFO Observed TLS Connection'
    assert final_guardrail_check(normalize(data,'wazuh').to_event(),'suppress') is None


def test_envelope_counters_do_not_defeat_exact_pattern_learning_or_mutate_evidence(tmp_path):
    memory=Memory(tmp_path/'memory.db')
    try:
        first=native();second=copy.deepcopy(first)
        first.raw_event['rule']['firedtimes']=1;first.metadata['rule']['firedtimes']=1
        second.raw_event['rule']['firedtimes']=2;second.metadata['rule']['firedtimes']=2
        key=pattern_key(first,'wazuh',memory,'qwen')
        assert key==pattern_key(second,'wazuh',memory,'qwen')
        assert second.metadata['rule']['firedtimes']==2
        second.message+=' different observed behavior'
        assert key!=pattern_key(second,'wazuh',memory,'qwen')
        assert pattern_key(first,'file',memory,'qwen') is None
    finally:memory.close()


def test_keep_alert_skips_redundant_challenge_but_suppression_still_requires_one():
    from arbiter.ingestion.schema import SecurityEvent
    from arbiter.l2_final_review import FinalReviewL2Brain
    from tests.test_l2_final_review import candidate,first
    event=SecurityEvent(source_type='wazuh',hostname='fixture',event_type='security_finding',
        severity=4,message='Recorded observation requiring review').to_event()
    brain=FinalReviewL2Brain('gemma4:12b')
    keep={**candidate(),'decision':'escalate'}
    brain.backend.generate=Mock(return_value=json.dumps(keep))
    result=brain.review_event(event,first())
    assert result['alert_decision']=='escalate' and brain.backend.generate.call_count==1
    assert result['action_authority'] is False and result['guardrail']['critic_accepted'] is None
    assert result['challenge']['skipped'] is True
    brain.backend.generate=Mock(side_effect=[json.dumps(candidate()),json.dumps({'accept':False,'objections':['No supported ordinary explanation'],'citations':['F1']})])
    result=brain.review_event(event,first())
    assert brain.backend.generate.call_count==2 and result['alert_decision']=='escalate'
    assert result['guardrail']['critic_accepted'] is False
