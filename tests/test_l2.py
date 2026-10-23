import json
from datetime import datetime, timezone
from unittest.mock import Mock
import pytest
from arbiter.agent import Agent
from arbiter.ingestion.containment import ContainmentScope
from arbiter.ingestion.schema import SecurityEvent
from arbiter.l2 import L2Brain
from arbiter.l2_workflow import L2Workflow, ResponsePolicy

@pytest.fixture
def workflow(tmp_path):
    firewall=Mock(); firewall.active.return_value=True; firewall.removed.return_value=True
    agent=Agent(tmp_path, scope=ContainmentScope(['10.20.0.0/24'],['10.20.0.2']),firewall=firewall)
    workflow=L2Workflow(agent,Mock(),ResponsePolicy({'automatic':True,'rules':['repeated_login_failures'],'windows':{'critical':1,'high':2}}))
    agent.l2=workflow
    yield workflow
    agent.close()

def ingest(w, severity=8, suffix='', age=0, target='10.20.0.5'):
    for i in range(5):
        event=SecurityEvent(source_type='linux_auth', hostname=__import__('socket').gethostname(),
            event_type='auth_failure',event_category='authentication',username='alice', src_ip=target,
            severity=severity,message='Failed SSH password',event_id=f'{suffix}-{i}',
            timestamp=datetime.fromtimestamp(w.clock()-age,timezone.utc).isoformat())
        w.agent.service.buffer.enqueue(event,'linux_auth'); w.agent.service.pipeline.process_one()
    w.tick(); return w.cases()[0]

def review(w,case,action='block_ip',confidence=.99):
    w.results.put((case['id'],case['severity'],{'action':action,'confidence':confidence,'target':'10.20.0.5','guardrail':{'rule':'repeated_login_failures'}},None))
    w.tick()

def due(w,case):
    w.clock=lambda:case['deadline']+.01
    w.tick()

@pytest.mark.parametrize('data',[{'automatic':'yes'},{'rules':['sustained_cpu_temporary_network']},{'windows':{'critical':3600}},{'windows':{'high':True}},{'windows':{'low':1}},{'windows':{'critical':60,'high':2}},{'unknown':1}])
def test_bad_policy(data):
    with pytest.raises(ValueError): ResponsePolicy(data)

def test_deadline_block_audit_revert(workflow):
    w=workflow; case=ingest(w); review(w,case)
    w.agent.protection.firewall.block.assert_not_called()
    due(w,case)
    case=w.cases()[0]; assert case['state']=='executed'
    assert 'l2-revert' in w.notices()[-1]['body']
    w.agent.command('l2-revert '+case['id'])
    assert w.cases()[0]['state']=='reverted'
    assert w.agent.protection.firewall.undo.called
    w.tick(); assert w.agent.protection.firewall.block.call_count==1

def test_repeat_does_not_reset_and_upgrade_shortens(workflow):
    w=workflow; case=ingest(w); original=case['deadline']
    w.tick(); assert w.cases()[0]['deadline']==original
    w.policy.windows['critical']=0
    ingest(w,9,'critical'); case=w.cases()[0]
    assert case['severity']=='critical' and case['deadline'] < original
    assert case['brief'] is None

@pytest.mark.parametrize('operation',['ack','defer'])
def test_ack_bounded_once(workflow,operation):
    w=workflow; case=ingest(w)
    w.control(operation,case['id'],'investigating')
    deadline=w.cases()[0]['deadline']
    with pytest.raises(ValueError): w.control(operation,case['id'],'again')
    assert w.cases()[0]['deadline']==deadline

@pytest.mark.parametrize('mode',['reject','stop','stale','low_confidence','advice_only','no_rule','failure','protected'])
def test_fail_closed(workflow,mode):
    w=workflow; case=ingest(w)
    if mode=='failure': w.results.put((case['id'],case['severity'],None,True)); w.tick()
    else: review(w,case,confidence=.5 if mode=='low_confidence' else .99)
    if mode=='reject': w.control('reject',case['id'],'benign test')
    if mode=='stop': w.control('stop')
    if mode=='stale': w.clock=lambda:case['deadline']+60
    if mode=='advice_only': w.policy.automatic=False
    if mode=='no_rule': w.policy.rules=[]
    if mode=='protected': w.agent.protection.scope=ContainmentScope(['10.20.0.0/24'],['10.20.0.5'])
    if mode!='stale': due(w,case)
    else: w.tick()
    w.agent.protection.firewall.block.assert_not_called()

def test_pending_model_still_alerts_at_deadline(workflow):
    w=workflow; case=ingest(w); due(w,case)
    assert 'L2 is pending' in w.notices()[-1]['body']
    w.agent.protection.firewall.block.assert_not_called()

def test_failure_never_claims_success(workflow):
    w=workflow; case=ingest(w); review(w,case)
    w.agent.protection.firewall.block.side_effect=OSError('denied')
    due(w,case)
    assert w.cases()[0]['state']=='needs_review'
    assert 'failed' in w.notices()[-1]['body']

def test_stop_and_deadline_persist(workflow):
    w=workflow; case=ingest(w); w.control('stop')
    other=L2Workflow(w.agent,Mock(),w.policy)
    assert other.halted() and other.cases()[0]['deadline']==case['deadline']

def test_reason_required(workflow):
    case=ingest(workflow)
    with pytest.raises(ValueError): workflow.control('defer',case['id'])



def test_interrupted_execution_not_replayed(workflow):
    w=workflow; case=ingest(w); case['state']='executing'; w.save(case)
    other=L2Workflow(w.agent,Mock(),w.policy)
    assert other.cases()[0]['state']=='needs_review'
    other.tick(); w.agent.protection.firewall.block.assert_not_called()

def test_old_review_cannot_authorize_upgraded_case(workflow):
    w=workflow; case=ingest(w); w.policy.windows['critical']=0
    ingest(w,9,'upgraded')
    w.results.put((case['id'],'high',{'action':'block_ip','confidence':1,'target':'10.20.0.5'},None))
    w.tick(); assert w.cases()[0]['brief'] is None
    w.agent.protection.firewall.block.assert_not_called()

def test_unverified_malware_correlation_not_authorized():
    policy=ResponsePolicy({'automatic':True,'rules':['malware_process_network']})
    row={'analysis':{'correlation':[{'rule':'malware_process_network'}]}}
    assert not policy.permits(row)
    row['analysis']['correlation'][0]['verified_tool_source']=True
    assert policy.permits(row)

@pytest.mark.parametrize('data',[False,[],{'windows':[]},{'rules':[{}]}])
def test_malformed_policy(data):
    with pytest.raises(ValueError): ResponsePolicy(data)

def test_background_worker_notices_and_deadline(workflow):
    import time
    w=workflow; notifications=[]; w.notify=notifications.append
    w.brain.review.return_value={'action':'block_ip','confidence':.99,'guardrail':{'rule':'repeated_login_failures'}}
    ingest(w); w.start()
    deadline=time.monotonic()+5
    while time.monotonic()<deadline and w.cases()[0]['state']!='executed': time.sleep(.05)
    assert w.cases()[0]['state']=='executed'
    assert any('Revert:' in n['notification'] for n in notifications)

def test_backlog_not_lost_outside_latest_hundred(workflow):
    w=workflow
    for index in range(105):
        event=SecurityEvent(source_type='linux_auth',hostname=__import__('socket').gethostname(),
            event_type='auth_failure',event_category='authentication',username='user'+str(index),
            severity=8,message='Failed SSH password',event_id='backlog-'+str(index))
        w.agent.service.buffer.enqueue(event,'linux_auth'); w.agent.service.pipeline.process_one()
    w.tick(); assert len(w.cases())==100
    w.tick(); assert len(w.cases())==105

def test_critical_scheduler_bypasses_busy_model(workflow):
    import socket
    from arbiter.l2 import L2Brain
    w=workflow; w.policy.rules=['malware_process_network']; w.policy.windows['critical']=0
    w.brain=L2Brain('fixture-14b'); w.brain.backend.generate=Mock(side_effect=TimeoutError)
    for source,kind,extra in [
        ('defender','malware_detection',{'file_path':r'C:\Temp\sample.exe'}),
        ('sysmon','network_connection',{'process_name':r'C:\Temp\sample.exe','dst_ip':'10.20.0.5'})]:
        event=SecurityEvent(source_type=source,hostname=socket.gethostname(),event_type=kind,
            severity=9,message='Synthetic critical fixture',event_id=source+'-critical',**extra)
        w.agent.service.buffer.enqueue(event,source); w.agent.service.pipeline.process_one()
    w.tick()
    case=next(c for c in w.cases() if c['event_id']=='sysmon-critical')
    assert case['state']=='executed' and case['deep_queued']
    assert case['brief']['route']=='verified_critical_fast_path'
    w.brain.backend.generate.assert_not_called()
