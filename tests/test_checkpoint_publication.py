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
