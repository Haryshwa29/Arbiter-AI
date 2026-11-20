import json
import os
from pathlib import Path
import sqlite3

import pytest

from tools.after_checkpoint_eval import alive,recoverable
from tools import after_checkpoint_eval as handoff
from tools.report_public_checkpoint import report


def test_final_report_rejects_a_partial_run(tmp_path):
    (tmp_path/'progress.json').write_text(json.dumps({'status':'running','target':26000,'counts':{'completed':17500}}))
    with pytest.raises(ValueError,match='finish before'):report(tmp_path,tmp_path/'report')


@pytest.mark.skipif(os.name!='nt',reason='Windows process supervision')
def test_windows_process_probe_does_not_terminate_the_process():
    assert alive(os.getpid())
    assert alive(os.getpid())
    assert not alive(os.getpid(),'1900-01-01T00:00:00Z')


def test_recovery_requires_preserved_alerts_and_stops_on_three_consecutive_bad_l2_replies(tmp_path):
    workers={name:{'errors':0} for name in ('gateway','l1','l2_prefilter','l2','final_guardrail')}
    workers['l2']['errors']=1
    progress={'error':'Worker error; inspect isolated events and L2 cases','workers':workers}
    with sqlite3.connect(tmp_path/'events.db') as db:
        db.executescript('CREATE TABLE l2_cases(body TEXT); CREATE TABLE telemetry(state TEXT,event_id TEXT,analysis TEXT);')
        db.execute('INSERT INTO l2_cases VALUES(?)',(json.dumps({'event_id':'a','review_failed':True,'review_error':'ValueError'}),))
        db.execute('INSERT INTO telemetry VALUES(?,?,?)',('done','a',json.dumps({'completed_at':'2026-11-19T00:00:00Z'})))
    assert recoverable(tmp_path,progress)
    with sqlite3.connect(tmp_path/'events.db') as db:
        db.execute('UPDATE l2_cases SET body=?',(json.dumps({'event_id':'a','review_failed':True,'review_error':'HTTPError'}),))
    assert recoverable(tmp_path,progress)
    with sqlite3.connect(tmp_path/'events.db') as db:
        for key in ('b','c'):
            db.execute('INSERT INTO l2_cases VALUES(?)',(json.dumps({'event_id':key,'review_failed':True,'review_error':'ValueError'}),))
            db.execute('INSERT INTO telemetry VALUES(?,?,?)',('done',key,json.dumps({'completed_at':'2026-11-19T00:00:00Z'})))
    assert not recoverable(tmp_path,progress)
    workers['l1']['errors']=1
    assert not recoverable(tmp_path,progress)


def test_waiting_handoff_does_not_apply_upgrade_install_packages_or_start_models(tmp_path,monkeypatch):
    baseline=tmp_path/'baseline';baseline.mkdir()
    (baseline/'progress.json').write_text(json.dumps({'status':'running','counts':{'completed':5}}))
    plan={'repo':str(tmp_path),'baseline':str(baseline),'next_run':str(tmp_path/'next'),'files':{}}
    path=tmp_path/'plan.json';path.write_text(json.dumps(plan))
    def unexpected(*args,**kwargs):raise AssertionError('No subprocess may run before baseline completion')
    monkeypatch.setattr(handoff.subprocess,'run',unexpected)
    class Interrupted(BaseException):pass
    def stop_wait(*args):raise Interrupted()
    monkeypatch.setattr(handoff.time,'sleep',stop_wait)
    with pytest.raises(Interrupted):handoff.main(path)
    result=json.loads((tmp_path/'handoff-progress.json').read_text())
    assert result['baseline_completed']==5
    assert not (tmp_path/'next').exists()
