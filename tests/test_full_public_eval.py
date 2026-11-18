"""Full-data replay must stream, preserve evidence and resume without hidden retries."""
from collections import Counter
import json
from types import SimpleNamespace
from unittest.mock import Mock
import zipfile

import pytest

from tools import full_public_eval as full
from arbiter.llm import LLMVerdict
from arbiter.schema import Decision


def raw_event():
    return {'rule':{'description':'Unclassified observation','id':'100','level':4,'groups':['test']},
        'agent':{'ip':'10.0.0.1','id':'1','name':'test'},
        '@timestamp':'2022-01-21T00:02:27Z','id':'original','full_log':'test observation'}


def item():
    return {'sample_id':'test:1','expected_attack':False,'label':'-'}


def brains(decision):
    backend = SimpleNamespace(model='qwen3.5:4b',triage=Mock(return_value=
        LLMVerdict(decision,.99,'Recorded explanation','Recorded facts')))
    second = SimpleNamespace(backend=SimpleNamespace(usage=[]),review_event=Mock())
    def review(*args):
        second.backend.usage.extend([{'eval_count':10},{'eval_count':5}])
        return {'review_status':'accepted','alert_decision':'suppress'}
    second.review_event.side_effect = review
    return backend,second


def test_real_l1_only_escalations_reach_second_stage_and_labels_stay_out(tmp_path):
    backend,second = brains(Decision.ESCALATE)
    row = full.evaluate(raw_event(),item(),backend,second,tmp_path/'audit.jsonl')
    assert row['decision']=='suppress' and row['decision_source']=='gemma'
    assert row['action_executed'] is False
    packet = row['l2_packet']
    assert 'first_review' not in packet
    assert not any(k in json.dumps(packet) for k in ('expected_attack','event_label','time_label'))
    counts = Counter()
    full.count_result(counts,row)
    assert (counts['l1_fp'],counts['final_tn'],counts['gemma_reviews'],counts['gemma_model_calls_completed'])==(1,1,1,2)
    assert counts['gemma_attack_inputs']==0
    second.review_event.reset_mock()
    backend.triage.return_value.decision=Decision.SUPPRESS
    other=full.evaluate(raw_event(),item(),backend,second,tmp_path/'audit.jsonl')
    second.review_event.assert_not_called()
    assert other['decision']=='suppress' and other['usage']==[]
    assert all(call.args[2]=='first occurrence of this signature' for call in backend.triage.call_args_list)


def test_completed_model_errors_are_counted_and_l2_never_hides_them(tmp_path):
    backend,second=brains(Decision.ESCALATE)
    second.review_event.side_effect=TimeoutError('local model unavailable')
    row=full.evaluate(raw_event(),item(),backend,second,tmp_path/'audit.jsonl')
    counts=Counter()
    full.count_result(counts,row)
    assert row['decision']=='escalate' and counts['l2_errors']==1
    assert counts['gemma_reviews']==0 and counts['consecutive_model_errors']==1
    backend.triage.side_effect=TimeoutError('qwen unavailable')
    second.review_event.reset_mock()
    row=full.evaluate(raw_event(),item(),backend,second,tmp_path/'audit.jsonl')
    second.review_event.assert_not_called()
    full.count_result(counts,row)
    assert counts['qwen_errors']==1 and counts['consecutive_model_errors']==2


def test_resume_keeps_completed_results_and_journals_interrupted_attempts(tmp_path):
    backend,second=brains(Decision.ESCALATE)
    row=full.evaluate(raw_event(),item(),backend,second,tmp_path/'audit.jsonl')
    db,counts=full.journal(tmp_path/'results.db')
    with db:
        attempt=db.execute("INSERT INTO attempts (seq,started,status) VALUES (1,?,'running')",(full.utc(),)).lastrowid
    full.finish(db,1,attempt,row,counts)
    with db:
        db.execute("INSERT INTO attempts (seq,started,status) VALUES (2,?,'running')",(full.utc(),))
    db.close()
    db,counts=full.journal(tmp_path/'results.db')
    assert counts['completed']==1 and counts['gemma_reviews']==1
    assert db.execute('SELECT seq,status FROM attempts ORDER BY id').fetchall()==[(1,'completed'),(2,'interrupted')]
    saved=json.loads(db.execute('SELECT payload FROM results').fetchone()[0])
    assert saved==row
    with db:
        attempt=db.execute("INSERT INTO attempts (seq,started,status) VALUES (2,?,'running')",(full.utc(),)).lastrowid
    full.finish(db,2,attempt,{**row,'sample_id':'test:2'},counts)
    full.progress(tmp_path,db,counts,'running')
    assert json.loads((tmp_path/'progress.json').read_text())['counts']['completed']==2
    assert 'Processed: 2 /' in (tmp_path/'STATUS.txt').read_text()
    assert db.execute('SELECT count(*) FROM attempts').fetchone()[0]==3
    db.close()


def test_archive_stream_alignment_and_aminer_exclusion(tmp_path,monkeypatch):
    monkeypatch.setattr(full,'SCENARIOS',('test',))
    monkeypatch.setattr(full,'SUPPORTED',1)
    with zipfile.ZipFile(tmp_path/'ait_ads.zip','w') as z:
        z.writestr('test_wazuh.json',json.dumps(raw_event())+'\n')
    def labels(ip):
        with zipfile.ZipFile(tmp_path/'alerts_csv.zip','w') as z:
            z.writestr('alerts_csv/test_alerts.txt','name,ip,event_label\nWazuh: Unclassified observation,'+ip+',-\nAMiner: example,10.0.0.1,-\n')
    labels('10.0.0.1')
    provenance={'alignment':{'test':{'matched_supported_alerts':1,'excluded_aminer':1}}}
    rows=list(full.alerts(tmp_path,provenance))
    assert len(rows)==1 and rows[0][0]==1 and rows[0][2]['label_row']==2
    labels('10.0.0.2')
    with pytest.raises(ValueError,match='do not align'):
        list(full.alerts(tmp_path,provenance))
