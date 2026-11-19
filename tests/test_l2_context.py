"""Context enriches investigation; reference knowledge never certifies safety."""
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import copy
import json
import subprocess
import sys
from unittest.mock import Mock
import zipapp

import pytest

from arbiter.guardrails import final_guardrail_check
from arbiter.ingestion.normalization import normalize
from arbiter.l2_advisory import packet_for
from arbiter.l2_context import catalog, context_for
from arbiter.l2_final_review import FinalReviewL2Brain
from arbiter.l2_prefilter import prefilter
from tools.build_security_knowledge import build

NOW=datetime(2026,11,18,12,tzinfo=timezone.utc)


def raw():
    return {'timestamp':NOW.isoformat(),'id':'test','agent':{'id':'1','name':'lab','ip':'10.0.0.1'},
        'rule':{'id':'1','level':4,'description':'IDS observation','groups':['ids','suricata']},
        'data':{'event_type':'alert','src_ip':'10.0.0.2','dest_ip':'10.0.0.1',
            'src_port':443,'dest_port':41000,'flow_id':23,'app_proto':'tls',
            'alert':{'severity':3,'signature_id':100,'signature':'SURICATA TLS invalid record/traffic','category':'Generic Protocol Command Decode'},
            'flow':{'pkts_toserver':2,'pkts_toclient':3},
            'tls':{'sni':'internal.example','version':'TLS 1.3'}}}


def event(data=None):
    return normalize(data or raw(),'wazuh').to_event()


def first():
    return {'decision':'escalate','tier':'llm','backend':'ollama','model':'qwen3.5:4b',
        'rationale':'UNVERIFIED_QWEN_OPINION','evidence':'L1 opinion'}


def auth(when,kind='auth_failure',user='alice',peer='10.0.0.2',host='lab'):
    data=raw()
    data.update(timestamp=when.isoformat(),id=when.isoformat())
    data['agent']['name']=host
    data['predecoder']={'hostname':host}
    data['rule'].update(description='Recorded login',groups=[
        'authentication_failed' if kind=='auth_failure' else 'authentication_success'])
    data['data']={'dstuser':user,'srcip':peer}
    native=normalize(data,'wazuh')
    return {'connector':'wazuh','event':asdict(native),'analysis':{'expected_attack':False,'decision':'suppress'}}


def test_native_security_fields_are_preserved_without_mining_cves_from_prose():
    data=raw()
    data['rule']['mitre']={'id':['T1110','invalid','T1548.003']}
    data['data']['alert']['metadata']={'cve':['CVE_2021_44228','not-a-CVE',False]}
    data['full_log']='Attacker-controlled mention CVE-2020-99999 is not a scanner finding'
    e=event(data);ctx=context_for(e)
    assert ctx['observed']['reported_cves']==['CVE-2021-44228']
    assert ctx['observed']['reported_techniques']==['T1110','T1548.003']
    p=packet_for(e,first(),final_review=True)
    assert p['facts'][0]['flow_pkts_toclient']==3
    assert p['facts'][0]['reported_cves']=='CVE-2021-44228'
    assert 'UNVERIFIED_QWEN_OPINION' not in json.dumps(p)
    assert ctx['cve_reference'][0]['known_exploited_as_of_event'] is True


def test_conversation_details_do_not_explain_a_protocol_anomaly():
    e=event()
    assert context_for(e)['has_conversation_context']
    assert prefilter(e)['rule']=='L2_PROTOCOL_CONTEXT_ONLY'
    assert final_guardrail_check(e,'suppress').code=='L2_PROTOCOL_CONTEXT_ONLY'
    data=raw();data['data']['flow'].pop('pkts_toclient')
    e=event(data);e.fields['_l2_context']={'has_conversation_context':True}
    assert prefilter(e)['rule']=='L2_CONTEXT_REQUIRED'


def test_cve_reference_alone_is_not_a_vulnerability_or_exploitation_verdict():
    data=raw();data['rule']['cve']='CVE-2021-44228'
    e=event(data)
    assert final_guardrail_check(e,'suppress').code=='L2_PROTOCOL_CONTEXT_ONLY'
    data['data']['alert']['signature']='ET INFO Observed TLS Connection'
    e=event(data)
    assert final_guardrail_check(e,'suppress') is None
    assert prefilter(e)['route']=='model'
    data['data']['vulnerability']={'status':'Active','package':{'name':'other-package','version':'1'}}
    assert final_guardrail_check(event(data),'suppress') is None
    data['data']['vulnerability']={'cve':'CVE-2021-44228','status':'Active',
        'package':{'name':'log4j','version':'2.14.1'}}
    e=event(data)
    assert final_guardrail_check(e,'suppress').code=='L2_REPORTED_VULNERABILITY'
    b=FinalReviewL2Brain('gemma4:12b');b.backend.generate=Mock()
    assert b.review_event(e,first())['decision']=='escalate'
    b.backend.generate.assert_not_called()


def test_cve_catalog_does_not_leak_later_kev_knowledge_into_historical_replay():
    data=raw();data['rule']['cve']='CVE-2021-44228'
    stored,_=catalog();known=stored['entries']['CVE-2021-44228']
    before=datetime.fromisoformat(known['date_added']).replace(tzinfo=timezone.utc)-timedelta(days=1)
    data['timestamp']=before.isoformat()
    card=context_for(event(data))['cve_reference'][0]
    assert card['known_exploited_as_of_event'] is False and 'product' not in card
    assert 'not proof' in card['scope']


def test_auth_window_requires_same_host_account_peer_and_past_native_evidence():
    current=auth(NOW,'auth_success')
    from arbiter.ingestion.schema import SecurityEvent
    e=SecurityEvent(**current['event']).to_event()
    valid=auth(NOW-timedelta(seconds=10))
    invalid=[auth(NOW+timedelta(seconds=1)),auth(NOW-timedelta(minutes=6)),
        auth(NOW-timedelta(seconds=5),user='bob'),
        auth(NOW-timedelta(seconds=5),peer='10.0.0.9'),
        auth(NOW-timedelta(seconds=5),host='other')]
    fake=copy.deepcopy(valid);fake['event']['metadata']['normalized_by']='legacy'
    ctx=context_for(e,[valid,valid,current,fake,*invalid])
    assert len(ctx['related_auth_events'])==1 and ctx['auth_failures_same_peer_5m']==1
    assert prefilter(e,security_context=ctx)['route']=='model'
    assert 'expected_attack' not in json.dumps(ctx) and 'decision' not in json.dumps(ctx)
    many=[auth(NOW-timedelta(seconds=i)) for i in range(1,6)]
    ctx=context_for(e,many)
    assert ctx['auth_failures_same_peer_5m']==5
    assert final_guardrail_check(e,'suppress',security_context=ctx).code=='L2_REPEATED_AUTH_FAILURES'
    b=FinalReviewL2Brain('gemma4:12b');b.backend.generate=Mock()
    assert b.review_event(e,first(),related=many)['decision']=='escalate'
    b.backend.generate.assert_not_called()


def test_context_reaches_assessment_and_challenge_without_new_action_rights():
    b=FinalReviewL2Brain('gemma4:12b')
    data={k:'Recorded ordinary explanation' for k in ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')}
    data.update(decision='suppress',decision_reason='Recorded ordinary explanation',confidence=.95,
        action='human_review',target=None,
        assertions=[{'fact_id':'F1','field':'flow_pkts_toclient','value':3}],
        hypotheses=[{'kind':k,'summary':'Check evidence','supports':['F1'],'against':[]} for k in ('malicious','benign')])
    b.backend.generate=Mock(side_effect=[json.dumps(data),json.dumps({'accept':True,'objections':[],'citations':['F1']})])
    observation=raw();observation['data']['alert']['signature']='ET INFO Observed TLS Connection'
    result=b.review_event(event(observation),first())
    assert result['decision']=='suppress' and result['action_authority'] is False
    for call in b.backend.generate.call_args_list:
        prompt=json.loads(call.args[0])
        assert prompt['evidence_packet']['security_context']['has_conversation_context']
    assert result['guardrail']['veto'] is None


def test_offline_import_validates_count_identity_and_dates():
    entry={'cveID':'CVE-2021-44228','vendorProject':'Apache','product':'Log4j','dateAdded':'2021-12-10'}
    data={'count':1,'catalogVersion':'test','dateReleased':'2026-11-17','vulnerabilities':[entry]}
    assert build(data,'https://example.invalid/source','a'*64)['count']==1
    with pytest.raises(ValueError):build({**data,'count':2},'', '')
    with pytest.raises(ValueError):build({**data,'count':2,'vulnerabilities':[entry,entry]},'', '')
    bad={**entry,'dateAdded':'never'}
    with pytest.raises(ValueError):build({**data,'vulnerabilities':[bad]},'', '')


def test_local_reference_survives_release_staging_and_zip_import(tmp_path):
    from tools.build_release import stage_source
    stage=tmp_path/'stage';stage.mkdir()
    stage_source(stage)
    assert (stage/'arbiter/data/kev.json').exists()
    archive=tmp_path/'runtime.pyz'
    zipapp.create_archive(stage,archive)
    code=f"import sys;sys.path.insert(0,{str(archive)!r});from arbiter.l2_context import catalog;print(catalog()[0]['count'])"
    result=subprocess.run([sys.executable,'-I','-c',code],capture_output=True,text=True,check=True,cwd=tmp_path)
    assert int(result.stdout.strip())==catalog()[0]['count']
