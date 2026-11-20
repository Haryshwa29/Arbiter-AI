"""Dashboard API shares the five-stage review without rewriting L1 evidence."""
import json
import threading
from unittest.mock import Mock

import pytest

from arbiter.api.server import Ctx,Hub,build_httpd
from arbiter.iam import IAM
from arbiter.ingestion.service import IngestionService
from arbiter.ingestion.protection import Protection
from arbiter.ingestion.response_workflow import ResponseWorkflow
from arbiter.l2_transport import L2Transport
from arbiter.memory import Memory
from arbiter.schema import Verdict,Decision,Tier
from arbiter.store import AuditStore
from tests.test_api import Client
from tests.test_l2_final_review import candidate
from tests.test_review_pipeline import event,wait_for


@pytest.fixture
def dashboard(tmp_path,monkeypatch):
    audit=AuditStore(tmp_path/'audit.db');memory=Memory(tmp_path/'memory.db')
    iam=IAM(tmp_path/'iam.db',secret=b'x'*32)
    iam.create_user('owner','test password','admin');iam.create_user('reader','test password','analyst')
    ingestion=IngestionService(tmp_path/'events.db',memory,audit,'ollama','qwen3.5:4b',ollama_url='http://127.0.0.1:43891')
    protection=Protection(ingestion.buffer,audit,firewall=Mock(),verify=True)
    monkeypatch.setattr(L2Transport,'verify',Mock(return_value={}))
    ingestion.enable_final_review('gemma4:12b',protection,10)
    ingestion.pipeline.engine.triage=Mock(side_effect=lambda e: Verdict(e.id,e.signature,Decision.ESCALATE,4,Tier.LLM,'First opinion','Recorded observation'))
    brain=ingestion.final_review.brain
    brain.backend.generate=Mock(side_effect=lambda prompt,*a,**kw:json.dumps(
        {'accept':True,'objections':[],'citations':['F1']} if 'recommendation' in json.loads(prompt) else candidate()))
    responses=ResponseWorkflow(ingestion.buffer,audit,protection,project=ingestion.project)
    ctx=Ctx(audit,iam,memory,Hub(),backend='ollama',ingestion=ingestion,protection=protection,responses=responses)
    httpd=build_httpd(ctx,'127.0.0.1',0)
    thread=threading.Thread(target=httpd.serve_forever,daemon=True);thread.start()
    ingestion.pipeline.start()
    try:yield ctx,httpd.server_address[1]
    finally:
        httpd.shutdown();httpd.server_close();thread.join()
        responses.close();ingestion.stop();iam.close();memory.close();audit.close()


def login(port,name='owner'):
    client=Client(port);client.get('/api/me')
    assert client.post('/api/login',{'username':name,'password':'test password'})[0]==200
    return client


def test_dashboard_projects_both_reviews_and_rejection_is_admin_csrf_protected(dashboard):
    ctx,port=dashboard;service=ctx.ingestion
    assert Client(port).get('/api/ingestion/status')[0]==401
    client=login(port)
    service.buffer.enqueue(event(),'wazuh')
    wait_for(lambda: service.buffer.detail('one')['state']=='done')
    code,row=client.get('/api/event?id=one')
    assert code==200 and row['analysis']['decision']=='suppress'
    assert row['analysis']['first_stage']['decision']=='escalate'
    assert row['analysis']['second_stage']['model']=='gemma4:12b'
    assert row['response_case'] is None and row['protection_proposal'] is None
    assert client.get('/api/events')[1]['events'][0]['analysis']['decision']=='suppress'
    assert service.buffer.detail('one')['analysis']['decision']=='escalate'
    ctx.responses.tick();assert ctx.responses.status()['cases']==[]
    status=client.get('/api/ingestion/status')[1]
    assert status['l2']['enabled'] and status['l2']['counts']['suppressed']==1
    assert len(status['pipeline_workers'])==5 and status['worker_alive']
    assert service.final_review.brain.backend.base_url==service.ollama_url
    assert client.get('/health')[1]['ingestion']
    payload={'event_id':'one','reason':'More investigation needed'}
    assert client.post('/api/l2/reject',payload,csrf=False)[0]==403
    assert login(port,'reader').post('/api/l2/reject',payload)[0]==403
    assert client.post('/api/l2/reject',payload)[0]==200
    retained=client.get('/api/event?id=one')[1]['analysis']
    assert retained['decision']=='escalate' and retained['second_stage_status']=='human-rejected-alert-retained'
    ctx.protection.firewall.block.assert_not_called()


def test_stale_second_review_does_not_quiet_another_dashboard_event(dashboard):
    ctx,port=dashboard;service=ctx.ingestion;client=login(port)
    service.buffer.enqueue(event(),'wazuh');wait_for(lambda:service.buffer.detail('one')['state']=='done')
    case=service.final_review.cases()[0]
    case['brief']['reviewed_event_id']='different-event'
    service.final_review.save(case)
    row=client.get('/api/event?id=one')[1]
    assert row['analysis']['decision']=='escalate'
    assert row['analysis']['second_stage_status']=='invalid-review-alert-retained'


def test_final_suppression_blocks_response_approval_even_when_l1_proposed_an_action(dashboard):
    ctx,_=dashboard;service=ctx.ingestion
    service.buffer.enqueue(event(),'wazuh');wait_for(lambda:service.buffer.detail('one')['state']=='done')
    ctx.protection.proposal=Mock(return_value={'target':'8.8.8.8'})
    with pytest.raises(ValueError,match='final review'):
        ctx.protection.approve('one','owner')
    ctx.protection.firewall.block.assert_not_called()


@pytest.mark.parametrize('endpoint',[
    'http://example.com:11434','http://8.8.8.8:11434','https://127.0.0.1:11434',
    'http://owner@127.0.0.1:11434','http://127.0.0.1:11434/api',
    'http://127.0.0.1:11434?remote=1','http://127.0.0.1:11434#remote',
    'http://127.0.0.1.example.com:11434'])
def test_second_model_endpoint_must_stay_local(endpoint):
    with pytest.raises(ValueError):L2Transport('gemma4:12b',base_url=endpoint)
