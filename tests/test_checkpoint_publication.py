"""Raw publication must preserve publisher bytes and refuse unfinished checkpoints."""
import copy
import hashlib
import json
import zipfile

import pytest

from tools.checkpoint_publication import raw_subset, prepare


def test_raw_subset_preserves_bytes_and_matches_per_record_labels(tmp_path):
    cache=tmp_path/'cache';cache.mkdir();destination=tmp_path/'out';destination.mkdir()
    one=b'{ "rule": {"description":"Example"}, "agent":{"ip":"10.0.0.1"} }\r\n'
    two=b'{"rule":{"description":"Example"},"agent":{"ip":"10.0.0.1"}}\n'
    with zipfile.ZipFile(cache/'ait_ads.zip','w') as z:
        z.writestr('fox_wazuh.json',one+b'The average number excluded\n'+two)
    with zipfile.ZipFile(cache/'alerts_csv.zip','w') as z:
        z.writestr('alerts_csv/fox_alerts.txt','name,ip,event_label\nWazuh: Example,10.0.0.1,-\nWazuh: Example,10.0.0.1,attack\n')
    selected=[{'record':1,'sample_id':'fox:1','scenario':'fox','raw_line':1,'label_row':2,'label':'-'},
              {'record':2,'sample_id':'fox:3','scenario':'fox','raw_line':3,'label_row':3,'label':'attack'}]
    assert raw_subset(cache,selected,destination)==2
    assert (destination/'raw-events.jsonl').read_bytes()==one+two
    assert hashlib.sha256(one).hexdigest() in (destination/'raw-record-index.csv').read_text(encoding='utf-8-sig')
    bad=copy.deepcopy(selected);bad[1]['label']='-'
    with pytest.raises(ValueError,match='scoring-label mismatch'):
        raw_subset(cache,bad,destination)


def test_publication_refuses_unconfirmed_stop(tmp_path):
    run=tmp_path/'run';package=tmp_path/'package';run.mkdir();package.mkdir()
    (run/'export-ready.json').write_text(json.dumps({'summary':str(package/'summary.json')}))
    (package/'summary.json').write_text(json.dumps({'completed':4,'stop':{'target':26000,'worker_exit_confirmed':False}}))
    (package/'run.json').write_text('{}')
    with pytest.raises(ValueError,match='has not been verified'):
        prepare(run,tmp_path/'work',tmp_path/'public',tmp_path/'cache')
    assert not (tmp_path/'public').exists()


def test_complete_publication_contains_raw_inputs_and_preserves_a_missed_attack(tmp_path):
    from datetime import datetime,timezone
    from types import SimpleNamespace
    from unittest.mock import Mock
    from tools.full_public_eval import journal,finish,evaluate
    from tools.stop_public_eval_at import export_run
    from tools.public_dataset_eval import digest
    from arbiter.llm import LLMVerdict
    from arbiter.schema import Decision
    run=tmp_path/'run';cache=tmp_path/'cache';run.mkdir();cache.mkdir()
    raw={'@timestamp':'2022-01-21T00:02:27Z','rule':{'description':'Example','id':'100','level':4,'groups':['test']},
        'agent':{'ip':'10.0.0.1','id':'1','name':'lab'},'full_log':'Recorded observation'}
    originals=[]
    backend=SimpleNamespace(model='qwen3.5:4b',triage=Mock(return_value=LLMVerdict(Decision.SUPPRESS,.99,'Controlled reply','Recorded fact')))
    second=SimpleNamespace(backend=SimpleNamespace(usage=[]),review_event=Mock())
    db,counts=journal(run/'results.db')
    for seq,attack in [(1,False),(2,True),(3,False)]:
        if seq==3:
            backend.triage.return_value=LLMVerdict(Decision.ESCALATE,.9,'Controlled alert','Recorded fact')
            def review(*args):
                second.backend.usage[:]=[{},{}]
                return {'decision':'suppress','alert_decision':'suppress','review_status':'accepted',
                    'decision_reason':'Controlled test reply','prefilter':{'rule':None}}
            second.review_event.side_effect=review
        data={**raw,'id':str(seq)};originals.append(json.dumps(data).encode()+b'\n')
        item={'sample_id':f'fox:{seq}','scenario':'fox','raw_line':seq,'label_row':seq+1,
            'label':'attack' if attack else '-','expected_attack':attack}
        row=evaluate(data,item,backend,second,run/'audit.jsonl')
        row.update(l1_elapsed_s=2.,l2_elapsed_s=30. if seq==3 else 0.,elapsed_s=32. if seq==3 else 2.)
        with db:attempt=db.execute("INSERT INTO attempts (seq,started,status) VALUES (?,?,'running')",(seq,datetime.now(timezone.utc).isoformat())).lastrowid
        finish(db,seq,attempt,row,counts)
    db.close()
    with zipfile.ZipFile(cache/'ait_ads.zip','w') as z:z.writestr('fox_wazuh.json',b''.join(originals))
    with zipfile.ZipFile(cache/'alerts_csv.zip','w') as z:z.writestr('alerts_csv/fox_alerts.txt','name,ip,event_label\nWazuh: Example,10.0.0.1,-\nWazuh: Example,10.0.0.1,attack\nWazuh: Example,10.0.0.1,-\n')
    (run/'run.json').write_text(json.dumps({'dataset':{'dataset_sha256':digest(cache/'ait_ads.zip'),'labels_sha256':digest(cache/'alerts_csv.zip')}}))
    receipt={'target':3,'actual_completed':3,'worker_exit_confirmed':True,'stopped_utc':datetime.now(timezone.utc).isoformat()}
    ready=export_run(run,tmp_path/'snapshot',receipt)
    (run/'export-ready.json').write_text(json.dumps(ready))
    publication=tmp_path/'public'
    prepare(run,tmp_path/'work',publication,cache)
    analysis=json.loads((publication/'summary.json').read_text())
    assert analysis['final']['attack_labels_quieted']==1
    assert analysis['attack_labels_quieted_ids']==['fox:2']
    scenarios=analysis['performance_estimates']['corrected_routing_scenarios']
    assert scenarios[0]['serial_inference_records_per_minute']==pytest.approx(5.)
    assert scenarios[0]['ideal_stage_overlap_records_per_minute']==pytest.approx(6.)
    assert scenarios[-1]['serial_inference_records_per_minute']==pytest.approx(20.)
    assert scenarios[-1]['ideal_stage_overlap_records_per_minute']==pytest.approx(30.)
    with zipfile.ZipFile(publication/'checkpoint-data.zip') as z:
        assert z.read('raw-events.jsonl')==b''.join(originals)
        assert z.testzip() is None and 'results.db' in z.namelist()
    report=(publication/'README.md').read_text()
    assert 'false negative' in report and 'No commercial system was run' in report
