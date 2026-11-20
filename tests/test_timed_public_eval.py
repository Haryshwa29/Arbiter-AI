from datetime import datetime,timezone,timedelta
from types import SimpleNamespace
from collections import Counter
import json
import time

from tools import timed_public_eval as timed
from tests.test_full_public_eval import raw_event
from tests.test_l2_final_review import candidate


def test_deadline_excludes_late_final_decisions():
    deadline=datetime.now(timezone.utc)
    row={'first_stage':{},'final_analysis':{'completed_at':(deadline+timedelta(seconds=1)).isoformat()}}
    assert not timed.classify_completion(row,deadline.isoformat())
    row['final_analysis']['completed_at']=deadline.isoformat()
    assert timed.classify_completion(row,deadline.isoformat())


def test_qwen_success_cannot_hide_repeated_gemma_failures():
    counts=Counter()
    failed={'first_stage':{'benchmark':{'calls':[{'brain':'gemma'}]}},'final_analysis':{'second_stage_status':'failed-alert-retained'}}
    qwen={'first_stage':{'backend':'ollama','benchmark':{'calls':[{'brain':'qwen'}]}},'final_analysis':{}}
    for _ in range(3):
        timed.support.error_streaks(counts,failed);timed.support.error_streaks(counts,qwen)
    assert counts['gemma_consecutive_errors']==3 and counts['qwen_consecutive_errors']==0


def test_timed_intake_runs_independently_and_stops_without_counting_backlog_as_work(tmp_path,monkeypatch):
    monkeypatch.setattr(timed.support,'verify',lambda out:None)
    monkeypatch.setattr(timed.support,'frozen_imports',lambda out:None)
    monkeypatch.setattr(timed.support,'model_identity',lambda:{'controlled':'identity'})
    monkeypatch.setattr(timed.support,'request',lambda *args:{})
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.verify',lambda self,*args:{})
    prompts=[]
    def qwen(self,prompt,*args,**kwargs):
        prompts.append(prompt);time.sleep(.03)
        return json.dumps(dict(decision='escalate',confidence=.99,evidence='Recorded observation',rationale='Inspect recorded behavior'))
    def gemma(self,prompt,*args,**kwargs):
        prompts.append(prompt);time.sleep(.03)
        if 'recommendation' in json.loads(prompt):return json.dumps(dict(accept=True,objections=[],citations=['F1']))
        answer=candidate();answer['assertions'][0]['value']='security_finding'
        return json.dumps(answer)
    monkeypatch.setattr('arbiter.llm.OllamaBackend.generate',qwen)
    monkeypatch.setattr('arbiter.l2_transport.L2Transport.generate',gemma)
    def source(*args):
        i=0
        while True:
            i+=1
            yield raw_event(),dict(scenario='fixture',sample_id=f'fixture:{i}',timestamp='2022-01-21T00:02:27+00:00',
                label='-',expected_attack=False,raw_sha256='a'*64)
    monkeypatch.setattr(timed,'records',source)
    (tmp_path/'input-provenance.json').write_text('{}');(tmp_path/'frozen-files.json').write_text('{}')
    before=time.monotonic()
    timed.run(SimpleNamespace(out=tmp_path,duration=1.2))
    elapsed=time.monotonic()-before
    result=json.loads((tmp_path/'progress.json').read_text())
    assert result['status']=='completed-window'
    assert result['accepted']>result['completed_within_window']
    assert result['accepted']==result['completed_within_window']+result['completed_after_cutoff']+result['unfinished']
    assert result['unfinished_at_cutoff']==result['accepted']-result['completed_within_window']
    assert result['device_actions']==0 and result['window_duration_s']==1.2
    assert elapsed<5
    assert all('expected_attack' not in p for p in prompts)
