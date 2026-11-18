"""Checkpoint exports preserve exact results and protect spreadsheet readers."""
from collections import Counter
import csv
import json
from pathlib import Path
import zipfile

from tools.full_public_eval import journal, finish
from tools.stop_public_eval_at import csv_text, export_run
from tools.public_dataset_eval import digest


def test_export_preserves_results_totals_and_snapshot(tmp_path):
    source=tmp_path/'run';source.mkdir()
    db,counts=journal(source/'results.db')
    for seq,attack,decision in [(1,False,'suppress'),(2,True,'escalate')]:
        first={'decision':decision,'tier':'llm','backend':'ollama','model':'qwen3.5:4b',
            'rationale':'Recorded finding','policy_fallback':False,'final_guardrail':{'veto':None}}
        second={'review_status':'prefilter','prefilter':{'rule':'TEST_RISK'},'proposed_decision':'escalate','decision_reason':'Keep for review'} if attack else None
        row={'sample_id':f'fox:{seq}','scenario':'fox','raw_line':seq,'label':'attack' if attack else '-',
            'expected_attack':attack,'event':{'host':'lab','id':str(seq),'timestamp':'2026-11-18T00:00:00+00:00','message':'=1+1'},
            'first_stage':first,'second_stage':second,'usage':[],'l2_error':None,
            'decision':decision,'decision_source':'l2-prefilter' if attack else 'llm',
            'l1_elapsed_s':1.0,'l2_elapsed_s':0.0,'action_executed':False}
        with db:
            attempt=db.execute("INSERT INTO attempts (seq,started,status) VALUES (?,?,'running')",(seq,'now')).lastrowid
        finish(db,seq,attempt,row,counts)
    db.close()
    (source/'run.json').write_text('{}')
    receipt={'target':2,'actual_completed':2}
    result=export_run(source,tmp_path/'export',receipt)
    summary=json.loads(Path(result['summary']).read_text())
    assert summary['completed']==2 and summary['final']['attack_label_recall_percent']==100
    rows=[json.loads(x) for x in (tmp_path/'export/decisions.jsonl').read_text().splitlines()]
    assert rows[0]['event']['message']=='=1+1'
    with (tmp_path/'export/results.csv').open(encoding='utf-8-sig',newline='') as f:
        flat=list(csv.DictReader(f))
    assert flat[0]['event_message']=="'=1+1" and flat[0]['label']=="'-"
    with zipfile.ZipFile(result['archive']) as z:
        assert z.testzip() is None and 'results.db' in z.namelist()
    for line in (tmp_path/'export/SHA256SUMS.txt').read_text().splitlines():
        checksum,name=line.split(None,1)
        assert digest(tmp_path/'export'/name.strip())==checksum
    db,after=journal(source/'results.db')
    assert after==counts
    db.close()


def test_csv_escapes_formulas_without_changing_nonformula_text():
    for value in ('=1+1',' +SUM(A1)','@value','-1','\tformula','\rformula'):
        assert csv_text(value)=="'"+value
    assert csv_text('ordinary text')=='ordinary text'
    assert csv_text(42)==42
