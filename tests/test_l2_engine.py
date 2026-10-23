import copy
import json
import socket
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock
import pytest
from arbiter.l2 import L2Brain
from arbiter.l2_evidence import dossier, assess
from arbiter.l2_guardrails import validate
from arbiter.l2_transport import L2Transport, NoRedirect

NOW=datetime.now(timezone.utc)

def row(i=0,kind='auth_failure',origin='linux_auth',**fields):
    event=dict(event_id=str(i),source_type=origin,hostname=socket.gethostname(),timestamp=NOW.isoformat(),
        event_type=kind,username='alice',src_ip='10.20.0.5',dst_ip='',process_name='',file_path='',
        process_id='12',severity=8,tags=[],message='observed',metadata={})
    event.update(fields)
    return {'event':event,'event_id':str(i),'connector':origin,'analysis':{'decision':'escalate','correlation':[]},'state':'done'}

@pytest.fixture
def case():
    current=row(4); current['_l2_related']=[row(i) for i in range(4)]
    return current, {'kind':'block_ip','target':'10.20.0.5','minutes':5}

def candidate(packet,target='10.20.0.5'):
    result={k:'Operator explanation' for k in ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')}
    result.update(action='block_ip',target=target,confidence=.99,
        assertions=[{'fact_id':f['id'],'field':'event_type','value':f['event_type']} for f in packet['facts']])
    result['hypotheses']=[{'kind':kind,'summary':'Explanation to investigate','supports':[packet['facts'][0]['id']],'against':[]} for kind in ('malicious','benign')]
    return result

def transport_fixture(prompt,system,**kwargs):
    request=json.loads(prompt); packet=request['evidence_packet']
    if 'recommendation' in request:
        return json.dumps({'accept':True,'objections':[],'citations':[f['id'] for f in packet['facts']]})
    return json.dumps(candidate(packet,request['supported_proposal']['target']))

def test_independent_engine_grounding_and_two_passes(case):
    current,proposal=case; brain=L2Brain('local-14b')
    brain.backend.generate=Mock(side_effect=transport_fixture)
    result=brain.review(current,proposal)
    assert result['action']=='block_ip' and result['engine']=='l2-independent-v2'
    assert brain.backend.generate.call_count==2
    assert brain.authorize(result,current,proposal)
    assert len(result['guardrail']['evidence_ids'])==5
    # The L1 verdict rationale and correlation are not evidence for L2.
    current['analysis']={'decision':'suppress','correlation':[{'rule':'made_up','severity':10}]}
    assert brain.authorize(result,current,proposal)

@pytest.mark.parametrize('mutation',['unknown_fact','wrong_value','missing_support','changed_target','nonfinite','command_action'])
def test_rejects_ungrounded_recommendations(case,mutation):
    current,proposal=case; packet=dossier(current,current['_l2_related']); assessment=assess(packet,proposal)
    data=candidate(packet)
    if mutation=='unknown_fact': data['assertions'][0]['fact_id']='F999'
    if mutation=='wrong_value': data['assertions'][0]['value']='malware_detection'
    if mutation=='missing_support': data['assertions']=data['assertions'][:1]
    if mutation=='changed_target': data['target']='10.20.0.2'
    if mutation=='nonfinite': data['confidence']=float('nan')
    if mutation=='command_action': data['action']='run_shell'
    with pytest.raises(ValueError): validate(data,packet,assessment,proposal)

@pytest.mark.parametrize('mutation',['host','peer','user','source','replay','stale','future','duplicate'])
def test_prefilter_rebuilds_support(case,mutation):
    current,proposal=case
    related=current['_l2_related']; event=related[0]['event']
    if mutation=='host': event['hostname']='other-host'
    if mutation=='peer': event['src_ip']='10.20.0.6'
    if mutation=='user': event['username']='bob'
    if mutation=='source': related[0]['connector']='file'
    if mutation=='replay': event['tags']=['replay']
    if mutation=='stale': event['timestamp']=(NOW-timedelta(minutes=8)).isoformat()
    if mutation=='future': event['timestamp']=(NOW+timedelta(minutes=8)).isoformat()
    if mutation=='duplicate': event['event_id']=related[1]['event']['event_id']
    packet=dossier(current,related); assert assess(packet,proposal)['rule'] is None

def test_critic_disagreement_escalates(case):
    current,proposal=case; brain=L2Brain('local-14b'); packet=dossier(current,current['_l2_related'])
    brain.backend.generate=Mock(side_effect=[json.dumps(candidate(packet)),json.dumps({'accept':False,'objections':['Possible shared peer'],'citations':['F1']})])
    result=brain.review(current,proposal)
    assert result['action']=='human_review' and not brain.authorize(result,current,proposal)

def critical_case():
    current=row(2,'network_connection','sysmon',src_ip='',dst_ip='10.20.0.5',process_name=r'C:\Temp\sample.exe')
    current['_l2_related']=[row(1,'malware_detection','defender',file_path=r'C:\Temp\sample.exe')]
    return current,{'target':'10.20.0.5','kind':'block_ip','minutes':5}

def test_verified_critical_fast_path_does_not_wait_for_model():
    current,proposal=critical_case(); brain=L2Brain('local-14b'); brain.backend.generate=Mock(side_effect=TimeoutError)
    result=brain.review(current,proposal)
    assert result['needs_deep_review'] and brain.authorize(result,current,proposal)
    brain.backend.generate.assert_not_called()
    current['_l2_deep']=True
    with pytest.raises(TimeoutError): brain.review(current,proposal)

@pytest.mark.parametrize('mutation',['wrong_path','wrong_origin','stale'])
def test_critical_fast_path_requires_native_support(mutation):
    current,proposal=critical_case(); detector=current['_l2_related'][0]
    if mutation=='wrong_path': detector['event']['file_path']=r'C:\Other\sample.exe'
    if mutation=='wrong_origin': detector['connector']='file'
    if mutation=='stale': detector['event']['timestamp']=(NOW-timedelta(minutes=8)).isoformat()
    assert assess(dossier(current,current['_l2_related']),proposal)['route']!='verified_critical'

@pytest.mark.parametrize('size',['4B','3.9B','4000M','unknown',''])
def test_transport_rejects_small_or_unknown_model(size):
    backend=L2Transport('model'); backend.request=Mock(side_effect=[{'models':[{'name':'model'}]}, {'details':{'format':'gguf','parameter_size':size}}])
    with pytest.raises(ValueError): backend.verify()

def test_l2_transport_separate_reasoning_configuration():
    backend=L2Transport('model'); backend.request=Mock(side_effect=[{'models':[{'name':'model'}]},
        {'details':{'format':'gguf','parameter_size':'14.8B'}},{'response':'{}'}])
    backend.generate('evidence','senior reviewer')
    payload=backend.request.call_args.args[1]
    assert payload['think'] is True and payload['options']['num_ctx']==16384
    assert payload['model']=='model'

def test_cloud_alias_and_redirect_refused():
    with pytest.raises(ValueError): L2Transport('model:cloud')
    with pytest.raises(ValueError): NoRedirect().redirect_request(None,None,302,'',{},'https://external.example')

def test_remote_model_metadata_refused_before_prompt():
    backend=L2Transport('model'); backend.request=Mock(return_value={'models':[{'name':'model','remote_host':'cloud'}]})
    with pytest.raises(ValueError): backend.generate('private evidence','review')
    assert backend.request.call_count==1

@pytest.mark.parametrize('mutation',['missing','single_kind','unknown_support'])
def test_hypotheses_are_grounded(case,mutation):
    current,proposal=case; packet=dossier(current,current['_l2_related']); data=candidate(packet)
    if mutation=='missing': del data['hypotheses']
    if mutation=='single_kind': data['hypotheses'][1]['kind']='malicious'
    if mutation=='unknown_support': data['hypotheses'][0]['supports']=['invented']
    with pytest.raises(ValueError): validate(data,packet,assess(packet,proposal),proposal)

def test_guard_rejects_changed_support_and_target(case):
    current,proposal=case; brain=L2Brain('fixture-14b'); brain.backend.generate=Mock(side_effect=transport_fixture)
    result=brain.review(current,proposal)
    assert not brain.authorize({**result,'target':'10.20.0.9'},current,proposal)
    current['_l2_related'][0]['event']['src_ip']='10.20.0.9'
    assert not brain.authorize(result,current,proposal)

def test_review_budget_bounds():
    for invalid in (0,True,181):
        with pytest.raises(ValueError): L2Brain('local-14b',invalid)
