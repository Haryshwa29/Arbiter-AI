"""Build a public checkpoint bundle with verbatim source records and honest comparisons."""
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
import argparse
import csv
import hashlib
import json
import shutil
import sqlite3
import zipfile

ROOT=Path(__file__).resolve().parents[1]
import sys
sys.path.insert(0,str(ROOT))
from tools.public_dataset_eval import check_match, digest, label_rows
from tools.stop_public_eval_at import csv_text
from tools.two_brain_eval import timing

QUOTE='raising alerts which look suspicious without proper context is better than suppressing them and getting true negative'
REFERENCES=[
    {'title':'Enterprise ingestion processing documentation','url':'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time',
     'metric':'Under 10 seconds after the collection endpoint to query availability; upload buffering and source delays can add time.',
     'scope':'Log availability, not per-alert AI classification or containment.'},
    {'title':'Enterprise near-real-time detection rules','url':'https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules',
     'metric':'Queries scheduled once per minute with a documented two-minute delay.',
     'scope':'Query cadence and data window, not one alert processed per minute.'},
    {'title':'Published guided-response architecture, 2024','url':'https://arxiv.org/html/2407.09017v1',
     'metric':'15-minute inference-job interval; batch latency of a few minutes while handling very large daily incident volumes.',
     'scope':'Distributed incident-level recommendation batches, not an isolated single-alert timing on our hardware.'}]


def raw_subset(cache, selected, destination):
    """Copy original JSON lines and independently check their published-label alignment."""
    selected_by_scenario=defaultdict(dict)
    for item in selected:selected_by_scenario[item['scenario']][item['raw_line']]=item
    seen=[]
    with zipfile.ZipFile(cache/'ait_ads.zip') as source, zipfile.ZipFile(cache/'alerts_csv.zip') as labels, (destination/'raw-events.jsonl').open('wb') as output, (destination/'raw-record-index.csv').open('w',encoding='utf-8-sig',newline='') as index:
        columns=['record','sample_id','scenario','raw_line','label_row','label','original_line_sha256']
        writer=csv.DictWriter(index,fieldnames=columns);writer.writeheader()
        for scenario,targets in selected_by_scenario.items():
            published=iter(label_rows(labels,scenario));label_number=1
            with source.open(f'{scenario}_wazuh.json') as stream:
                for line_number,line in enumerate(stream,1):
                    if not line.strip() or b'The average number' in line:continue
                    label=next(published);label_number+=1
                    if line_number not in targets:continue
                    item=targets[line_number];raw=json.loads(line);check_match(raw,label)
                    if item['label_row']!=label_number or item['label']!=label['event_label']:
                        raise ValueError('Original raw record / scoring-label mismatch')
                    if not line.endswith(b'\n'):raise ValueError('Expected an original JSONL line separator')
                    output.write(line);seen.append(item['record'])
                    values={k:item[k] for k in columns if k!='original_line_sha256'}
                    values['original_line_sha256']=hashlib.sha256(line).hexdigest()
                    writer.writerow({k:csv_text(v) for k,v in values.items()})
                    if len(seen)==sum(len(v) for v in selected_by_scenario.values()):break
    if seen!=[item['record'] for item in selected]:
        raise ValueError('Raw subset did not preserve the complete scored-record order')
    return len(seen)


def prepare(run,work,publication,cache):
    ready=json.loads((run/'export-ready.json').read_text())
    package=Path(ready['summary']).parent
    summary=json.loads((package/'summary.json').read_text())
    meta=json.loads((package/'run.json').read_text())
    if not summary['stop']['worker_exit_confirmed'] or summary['completed']<summary['stop']['target']:
        raise ValueError('Requested checkpoint stop has not been verified')
    if work.exists() or publication.exists():raise ValueError('Use new work/publication directories')
    if digest(Path(ready['archive']))!=ready['archive_sha256']:
        raise ValueError('Completed checkpoint ZIP hash mismatch')
    for name,key in [('ait_ads.zip','dataset_sha256'),('alerts_csv.zip','labels_sha256')]:
        if digest(cache/name)!=meta['dataset'][key]:raise ValueError('Pinned source archive mismatch')
    work.mkdir(parents=True);publication.mkdir(parents=True)
    for line in (package/'SHA256SUMS.txt').read_text().splitlines():
        checksum,name=line.split(None,1);name=name.strip()
        if Path(name).name!=name or digest(package/name)!=checksum:
            raise ValueError('Checkpoint manifest path/hash mismatch')
        shutil.copy2(package/name,work/name)
    hardware={}
    if (run/'hardware-observed.json').exists():
        hardware=json.loads((run/'hardware-observed.json').read_text(encoding='utf-8-sig'))
        (work/'hardware-observed.json').write_text(json.dumps(hardware,indent=2)+'\n',encoding='utf-8')
    selected=[];values=defaultdict(list);actors=defaultdict(Counter);examples={};misses=[];noisy_sources=Counter()
    with sqlite3.connect(package/'results.db') as db:
        started=db.execute('SELECT started FROM attempts ORDER BY id LIMIT 1').fetchone()[0]
        for seq,payload in db.execute('SELECT seq,payload FROM results ORDER BY seq'):
            row=json.loads(payload);first=row['first_stage'];second=row['second_stage'] or {}
            selected.append({'record':seq,**{k:row[k] for k in ('sample_id','scenario','raw_line','label_row','label')}})
            total=row['l1_elapsed_s']+row['l2_elapsed_s']
            values['all_records'].append(total)
            values['qwen_l1' if first['tier']=='llm' else 'rules_only'].append(row['l1_elapsed_s'])
            if row['usage']:
                values['gemma_review'].append(row['l2_elapsed_s']);values['gemma_record_total'].append(total)
            actor=row['decision_source'];outcome=('attack_' if row['expected_attack'] else 'unannotated_')+row['decision']
            actors[actor][outcome]+=1
            if not row['expected_attack'] and row['decision']=='escalate':
                finding=row['event'].get('fields',{}).get('_tool_finding',{})
                noisy_sources[finding.get('name') or row['event']['event_type']]+=1
            if actor not in examples:
                examples[actor]={'record':seq,'id':row['sample_id'],'decision':row['decision'],
                    'reason':second.get('decision_reason',first['rationale'])[:700]}
            if row['expected_attack'] and row['decision']=='suppress':misses.append(row['sample_id'])
    n=summary['completed']
    if len(selected)!=n:raise ValueError('Incomplete checkpoint export')
    raw_subset(cache,selected,work)
    elapsed=(datetime.fromisoformat(summary['stop']['stopped_utc'])-datetime.fromisoformat(started)).total_seconds()
    latency={k:timing(v) for k,v in values.items()}
    analysis={'completed':n,'scope':summary['scope'],'by_scenario':summary['by_scenario'],
        'l1':summary['l1'],'final':summary['final'],'layers':summary['layers'],
        'latency':latency,'wall_elapsed_s':elapsed,'observed_records_per_minute':n*60/elapsed,
        'final_actor_counts':dict(actors),'examples':examples,'attack_labels_quieted_ids':misses,
        'l2_rules':summary['l2_rules'],'retained_unannotated_sources':dict(noisy_sources.most_common()),
        'hardware':hardware,'reference_checked_date':'2026-11-18','corporate_references':REFERENCES,
        'comparison_result':'No matched commercial single-alert benchmark was run; no superiority or speedup factor is established.'}
    final=summary['final'];c=summary['layers'];attacks=final['attack_labels_flagged']+final['attack_labels_quieted']
    negative=final['unannotated_flagged']+final['unannotated_quieted']
    first_noise=summary['l1']['unannotated_flagged'];cleared=first_noise-final['unannotated_flagged']
    lines=[f'# Arbiter AI: {n:,}-record public-data checkpoint','',
        '**This is a user-requested partial checkpoint, not the completed 2.6-million-record evaluation.**','',
        f"The run stopped after {n:,} committed records from {summary['by_scenario']}. Input was sequential original file order, one scenario at a time, with empty history for each record. It was not randomized or balanced. No live device actions were enabled.",'',
        '## Our safety policy','',f'> {QUOTE}','',
        '**Terminology correction:** suppressing a real attack is a false negative. A true negative is correctly quieting a harmless record and is desirable. The intended policy is: keep suspicious alerts visible when the available evidence does not justify suppression.','',
        'That policy is implemented through uncertain/error escalation, L2 context-required routing, known-risk vetoes, suppression-confidence checks and the shared final guardrail. It is a design requirement, not a guarantee that model reasoning never fails. Conservative policy does not turn a benchmark false positive into a successful detection.','',
        '## Dataset and raw data','',
        'AIT Alert Data Set (AIT-ADS) v1, Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Publisher / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Cite *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).','',
        'The whole archive has 2,655,821 records from eight simulated networks. The adapter supports 2,600,263 Wazuh/Suricata records and excludes 55,558 AMiner records. This checkpoint covers only its initial prefix.','',
        'The simulated networks contain ordinary activity alongside staged attacks, including scanning, password attacks, privilege escalation, remote commands, web shells, data theft and service disruption. A security-tool alert is a warning about an observation; it is not automatically a confirmed attack. The mix in this checkpoint is reported below rather than assumed to match the whole archive.','',
        '`checkpoint-data.zip` contains verbatim publisher JSONL records, a source-line/label index, all normalized inputs and L1/L2 outcomes, readable CSV, SQLite snapshot, model/source/input provenance and checksums. Per-line hashes verify the original raw bytes. Scoring labels remained outside the model inputs.','',
        '## Measured outcomes','',
        '| Outcome | L1 rules + Qwen | After L2 + final checks |','|---|---:|---:|',
        f"| Attack-labelled records examined | {attacks:,} | {attacks:,} |",
        f"| Attack-labelled records kept flagged | {summary['l1']['attack_labels_flagged']:,} | {final['attack_labels_flagged']:,} |",
        f"| Attack-labelled records quieted | {summary['l1']['attack_labels_quieted']:,} | {final['attack_labels_quieted']:,} |",
        f"| Unannotated records quieted | {summary['l1']['unannotated_quieted']:,} | {final['unannotated_quieted']:,} |",
        f"| Unannotated records still flagged | {summary['l1']['unannotated_flagged']:,} | {final['unannotated_flagged']:,} |",
        f"| Agreement with publisher labels | {summary['l1']['label_agreement_percent']:.2f}% | {final['label_agreement_percent']:.2f}% |",'',
        ('**No attack-labelled records were processed. Attack-detection recall and missed-attack performance are unmeasured; do not publish the agreement percentage as overall attack accuracy.**' if not attacks else f"Attack-label recall: {final['attack_label_recall_percent']:.2f}% on {attacks:,} selected records; not a production detection rate."),'',
        f"The {final['unannotated_flagged']:,} retained unannotated records count as false positives under this label-based scoring convention ({100*final['unannotated_flagged']/negative:.2f}% of unannotated records). Missing attack annotations do not independently certify harmlessness. These flags remain an unresolved noise cost, not successes excused by the safety policy.",'',
        '## What worked, and what remains weak','',
        f"- Qwen reviews: {c['qwen_reviews']:,}; L2 inputs: {c['l2_inputs']:,}; L2 decisions without Gemma: {c['l2_rule_decisions']:,}.",
        f"- Actual Gemma reviews with replies: {c['gemma_reviews']:,}; additional warnings quieted by Gemma: {c['gemma_suppressions']:,}.",
        f"- L2 reduced unannotated warnings by {cleared:,} out of {first_noise:,} ({100*cleared/first_noise if first_noise else 0:.2f}%). This is the reduction in label-defined unwanted warnings, not an attack-detection score.",
        f"- Qwen errors: {c['qwen_errors']:,}; L2 errors: {c['l2_errors']:,}. Successful completion/format validation is not a semantic-correctness score.",
        '- Both model stages and final vetoes are preserved. Alerts lacking enough context remain visible; no containment permission was granted.',
        '- Many retained warnings still lack useful independent flow/login context. This checkpoint does not establish strong noise reduction by L2.',
        '- The separate context-upgrade development probe found unsupported Gemma suppressions accepted by its critic. Those different synthetic checks are preserved separately and are not mixed into these scores. The upgrade was not installed into this frozen run.','',
        '### Where the unwanted alerts came from','',
        'The final deciding-layer table below separates who left each warning visible. Qwen can raise a concern, then the L2 prefilter can retain it because supporting context is absent; in that case Gemma never sees it. This is conservative routing, not evidence that Gemma reviewed and agreed with every warning. It also means the current L2 policy often cannot reduce noise on isolated records. More context must support a specific ordinary explanation, rather than simply instructing the model to suppress more.','',
        '| L2 rule | Records | Share of L2 inputs |','|---|---:|---:|']
    for rule,count in summary['l2_rules'].items():
        lines.append(f"| {rule} | {count:,} | {100*count/c['l2_inputs']:.2f}% |")
    lines+=['','`L2_CONTEXT_REQUIRED` means: keep the warning visible because this isolated record does not explain why the activity is ordinary. It avoids a model call that would only repeat the same incomplete evidence. A guardrail can block an unsupported quiet decision, but passing a check does not prove the model understood the event correctly.','',
        '| Most frequent retained, unannotated warning types | Records |','|---|---:|']
    for name,count in noisy_sources.most_common(8):
        lines.append(f"| {name.replace('|','/')} | {count:,} |")
    lines+=['',
        '| Final deciding layer | Unannotated quieted | Unannotated flagged | Attack quieted | Attack flagged |','|---|---:|---:|---:|---:|']
    for actor,counts in actors.items():
        lines.append(f"| {actor} | {counts['unannotated_suppress']:,} | {counts['unannotated_escalate']:,} | {counts['attack_suppress']:,} | {counts['attack_escalate']:,} |")
    lines+=['','Examples below identify actual scored records, not a separately scored explanation-quality study.','']
    for actor,e in examples.items():lines.append(f"- {actor}, record {e['record']} ({e['id']}), {e['decision']}: {e['reason']}")
    lines+=['','## Per-record latency: what was actually timed','',
        '| Measured path | Records | Mean | Median | 95th percentile |','|---|---:|---:|---:|---:|']
    path_names={'all_records':'All records, including fast rules','rules_only':'L1 rules without Qwen','qwen_l1':'Qwen stage on model-reviewed records','gemma_review':'Gemma assessment + challenge','gemma_record_total':'Complete classification on Gemma-reviewed records'}
    for key,t in latency.items():lines.append(f"| {path_names[key]} | {t['n']:,} | {t['mean_s']:.4f}s | {t['p50_s']:.4f}s | {t['p95_s']:.4f}s |")
    lines+=['',f"Local hardware snapshot: {hardware.get('cpu','see bundle')}; {hardware.get('ram_bytes',0)/1024**3:.1f} GiB RAM; GPU/model-memory/driver report: {hardware.get('gpu','see bundle')}. Models: Qwen3.5:4b (L1), Gemma4:12b (L2), with exact installed digests and requested options in run.json. This is not matched hardware against an enterprise cluster."]
    lines+=['',f"Observed complete-run rate: **{n*60/elapsed:.2f} saved records/minute** over {elapsed/3600:.2f} elapsed hours. The earlier rough 50/minute estimate is not substituted for the final measured rate.",'',
        'This is one sequential replay worker. On a Gemma case, the next record waits for both its assessment and challenge. The normal source agent has separate L1/L2 queues/workers, but that concurrent mode was not measured here. Timings exclude live collector/network delay and pre-processing queue residence; they are not ingestion-to-containment times. This historical replay executes no response actions. Other desktop/development activity shared the machine.','',
        '## Corporate reference points: context, not a matched speed benchmark','',
        'No commercial system was run on these same records, hardware, context, quality targets and forced one-record workflow. A claim that enterprise products would be slower one-by-one is therefore untested. The proposed 1–3 alerts/minute figure has not been established as a universal automated corporate standard and is not used to claim superiority.','',
        '| Published reference | Number and unit | Why it is not our same measurement |','|---|---|---|']
    for ref in REFERENCES:lines.append(f"| [{ref['title']}]({ref['url']}) | {ref['metric']} | {ref['scope']} |")
    lines+=['','References checked November 18, 2026. A one-minute query schedule is not a one-alert-per-minute throughput ceiling. A distributed batch can process many incidents together; its interval cannot be divided or multiplied into an invented isolated-alert latency. Fast local classification is a measured property of this replay, not proof of faster corporate investigation, ingestion, correlation, or response.','',
        '## Next steps','',
        'Use a separate frozen, balanced attack/routine comparison or a complete attack-containing timeline; preserve scoring labels outside prompts. Test the actual concurrent agent with persistent scoped context, case grouping and realistic arrival bursts. Compare identical isolated records and quality requirements on both systems if a true one-to-one commercial benchmark is required. Improve independently supported ordinary explanations, inspect unsupported suppressions, and test live queue delay before publishing response-time claims.','',
        'The original data and completed decisions were not rewritten or selectively retried. A last unfinished attempt can be interrupted by the requested stop and is not scored as a completed result. The dataset and source hashes identify the exact run; the ZIP manifest protects the downloadable bytes.','']
    report='\n'.join(lines)
    (publication/'README.md').write_text(report,encoding='utf-8')
    (work/'REPORT.md').write_text(report,encoding='utf-8')
    (work/'analysis.json').write_text(json.dumps(analysis,indent=2)+'\n',encoding='utf-8')
    (publication/'summary.json').write_text(json.dumps(analysis,indent=2)+'\n',encoding='utf-8')
    (work/'SHA256SUMS.txt').write_text(''.join(digest(p)+'  '+p.name+'\n' for p in sorted(work.iterdir()) if p.is_file() and p.name!='SHA256SUMS.txt'),encoding='utf-8')
    archive=publication/'checkpoint-data.zip'
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for p in sorted(work.iterdir()):z.write(p,p.name)
    with zipfile.ZipFile(archive) as z:
        if z.testzip() is not None:raise ValueError('Public ZIP validation failed')
    if archive.stat().st_size>=99*1024*1024:raise ValueError('Use split assets: checkpoint ZIP exceeds safe Git file size')
    (publication/'SHA256SUMS.txt').write_text(''.join(digest(p)+'  '+p.name+'\n' for p in sorted(publication.iterdir()) if p.is_file() and p.name!='SHA256SUMS.txt'),encoding='utf-8')
    print(json.dumps({'records':n,'publication':str(publication),'archive_bytes':archive.stat().st_size,'raw_records':len(selected)}))


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run',type=Path,required=True);p.add_argument('--work',type=Path,required=True)
    p.add_argument('--publication',type=Path,required=True)
    p.add_argument('--cache',type=Path,default=ROOT/'output/public-eval/ait-ads')
    a=p.parse_args();prepare(a.run.resolve(),a.work.resolve(),a.publication.resolve(),a.cache.resolve())
