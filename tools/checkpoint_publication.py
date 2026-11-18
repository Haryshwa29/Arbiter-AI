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
WORKLOAD_REFERENCES=[
    {'title':'Prophet Security 2025 survey, all organizations','daily_alerts':960,
     'url':'https://www.prophetsecurity.ai/blog/6-key-takeaways-from-the-ai-in-soc-survey-report'},
    {'title':'Prophet Security 2025 survey, enterprises with 20,000+ employees','daily_alerts':3181,
     'url':'https://www.prophetsecurity.ai/blog/6-key-takeaways-from-the-ai-in-soc-survey-report'},
    {'title':'Vectra AI 2023 survey of 2,000 SecOps analysts','daily_alerts':4484,
     'url':'https://www.vectra.ai/about/news/research-reveals-significant-disconnect-between-security-operations-teams-and-the-effectiveness-of-threat-detection-tools-in-preventing-cyber-attacks'}]
REFERENCES=[
    {'title':'Published automated per-alert triage claim',
     'url':'https://d3security.com/siem-triage-automation/',
     'metric':'Under 2 minutes for up to 95% of alerts, advertised with L2+ investigation depth.',
     'scope':'Vendor claim including cross-stack enrichment/investigation, not our isolated-record classification test; no matched inputs or independently reproduced quality/latency.'},
    {'title':'Enterprise ingestion processing documentation','url':'https://learn.microsoft.com/en-us/azure/azure-monitor/logs/data-ingestion-time',
     'metric':'Under 10 seconds after the collection endpoint to query availability; upload buffering and source delays can add time.',
     'scope':'Log availability, not per-alert AI classification or containment.'},
    {'title':'Enterprise near-real-time detection rules','url':'https://learn.microsoft.com/en-us/azure/sentinel/near-real-time-rules',
     'metric':'Queries scheduled once per minute with a documented two-minute delay.',
     'scope':'Query cadence and data window, not one alert processed per minute.'},
    {'title':'Published guided-response architecture, 2024','url':'https://arxiv.org/html/2407.09017v1',
     'metric':'15-minute inference-job interval; batch latency of a few minutes while handling very large daily incident volumes.',
     'scope':'Distributed incident-level recommendation batches, not an isolated single-alert timing on our hardware.'},
    {'title':'Managed SOC observed workload, reported March 2026',
     'url':'https://investors.n-able.com/news/news-details/2026/N-able-Report-Reveals-Why-AI-Powered-Layered-Cyber-Defense-Is-Essential-for-Business-Resilience/default.aspx',
     'metric':'Average two alerts/minute during March-December 2025, as reported by the provider.',
     'scope':'Observed operational volume, not an ideal rate, measured maximum capacity or isolated-alert latency.'},
    {'title':'Published automated workflow capacity claim',
     'url':'https://d3security.com/resources/event-pipeline-automate-handling-of-hundreds-of-alerts-per-minute/',
     'metric':'Up to 200 alerts/minute advertised for automated tier-one workflows.',
     'scope':'Vendor-reported capacity with normalization, deduplication, triage and enrichment; no matched AIT-ADS quality/hardware test or single-alert latency.'}]


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
            total=row['elapsed_s']
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
    layers=summary['layers'];l1_mean=layers['l1_elapsed_s']/n;l2_mean=layers['l2_elapsed_s']/n
    projections=[]
    overlap_gain=100*((l1_mean+l2_mean)/max(l1_mean,l2_mean)-1)
    if 'gemma_review' in latency:
        review_mean=latency['gemma_review']['mean_s'];eligible_share=layers['l2_inputs']/n
        for suppress_share in (0,.5,.75,.9):
            l2_cost=eligible_share*(1-suppress_share)*review_mean
            projections.append({'assumed_l2_prefilter_suppression_percent':100*suppress_share,
                'serial_inference_records_per_minute':60/(l1_mean+l2_cost),
                'ideal_stage_overlap_records_per_minute':60/max(l1_mean,l2_cost)})
    analysis={'completed':n,'scope':summary['scope'],'by_scenario':summary['by_scenario'],
        'l1':summary['l1'],'final':summary['final'],'layers':summary['layers'],
        'latency':latency,'wall_elapsed_s':elapsed,'observed_records_per_minute':n*60/elapsed,
        'final_actor_counts':dict(actors),'examples':examples,'attack_labels_quieted_ids':misses,
        'l2_rules':summary['l2_rules'],'retained_unannotated_sources':dict(noisy_sources.most_common()),
        'hardware':hardware,'reference_checked_date':'2026-11-18','corporate_references':REFERENCES,
        'workload_references':[{**ref,'average_arrivals_per_minute':ref['daily_alerts']/1440} for ref in WORKLOAD_REFERENCES],
        'performance_estimates':{'unchanged_routing_ideal_stage_overlap_gain_percent':overlap_gain,
            'corrected_routing_scenarios':projections,'measured':False},
        'comparison_result':'No matched commercial single-alert benchmark was run; no superiority or speedup factor is established.'}
    final=summary['final'];c=summary['layers'];attacks=final['attack_labels_flagged']+final['attack_labels_quieted']
    negative=final['unannotated_flagged']+final['unannotated_quieted']
    first_noise=summary['l1']['unannotated_flagged'];cleared=first_noise-final['unannotated_flagged']
    kept=final['unannotated_flagged']+final['attack_labels_flagged']
    context_kept=summary['l2_rules'].get('L2_CONTEXT_REQUIRED',0)
    wall_seconds=round(elapsed)
    scenario_text=', '.join(f'{name.title()} ({count:,} records)' for name,count in summary['by_scenario'].items())
    layer_names={'prefilter':'L1 quick rules','llm':'Qwen, L1','guardrail':'L1 safety rules',
        'l2-prefilter':'L2 quick rules','gemma':'Gemma, L2','l2-failure-policy':'L2 failure policy'}
    lines=[f'# Arbiter AI: {n:,}-record public-data checkpoint','',
        '**This is a user-requested partial checkpoint, not the completed 2.6-million-record evaluation.**','',
        f"**Arbiter kept {100*kept/n:.2f}% of the records visible for review ({kept:,}/{n:,}). Its policy is to raise a warning when activity looks suspicious and the available evidence does not justify suppressing it.**",'',
        f"Of the retained warnings, {context_kept:,} ({100*context_kept/kept if kept else 0:.2f}%) were explicitly retained by L2's context-required rule after Qwen raised a concern. The other deciding layers are broken down below. These are requests for investigation; independent evidence is needed to establish whether an attack occurred.",'',
        f"The run stopped after {n:,} saved decisions from {scenario_text}. Input was sequential original file order, one scenario at a time, with empty history for each record. It was not randomized or balanced. No live device actions were enabled.",'',
        f"**Time to this checkpoint: {wall_seconds//3600} hours, {(wall_seconds%3600)//60} minutes, {wall_seconds%60} seconds.** The first record attempt started at {datetime.fromisoformat(started).strftime('%Y-%m-%d %H:%M:%S UTC')}; the stop was confirmed at {datetime.fromisoformat(summary['stop']['stopped_utc']).strftime('%Y-%m-%d %H:%M:%S UTC')}. This elapsed time includes model work and ordinary pauses/overhead during the run, rather than adding up inference durations alone.",'',
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
        f"The {final['unannotated_flagged']:,} retained unannotated records count as false positives under this label-based scoring convention ({100*final['unannotated_flagged']/negative:.2f}% of unannotated records). Missing attack annotations do not independently certify harmlessness. The conservative policy explains why warnings remain visible; they still create review work and retain their benchmark scores.",'',
        '## What worked, and what remains weak','',
        f"- Qwen reviews: {c['qwen_reviews']:,}; L2 inputs: {c['l2_inputs']:,}; L2 decisions without Gemma: {c['l2_rule_decisions']:,}.",
        f"- Actual Gemma reviews with replies: {c['gemma_reviews']:,}; additional warnings quieted by Gemma: {c['gemma_suppressions']:,}.",
        f"- L2 reduced unannotated warnings by {cleared:,} out of {first_noise:,} ({100*cleared/first_noise if first_noise else 0:.2f}%). This is the reduction in label-defined unwanted warnings, not an attack-detection score.",
        f"- Qwen errors: {c['qwen_errors']:,}; L2 errors: {c['l2_errors']:,}. Successful completion/format validation is not a semantic-correctness score.",
        '- Both model stages and final vetoes are preserved. Alerts lacking enough context remain visible; no containment permission was granted.',
        '- Many retained warnings still lack useful independent flow/login context. This checkpoint does not establish strong noise reduction by L2.',
        '- Routing limitation: the current L2 prefilter retained context-poor alerts without letting Gemma investigate. This saved model calls but did not follow the requested suppress-or-pass-to-Gemma handoff. The separate upgrade corrects that routing; its prefilter must independently justify routine suppressions, and unresolved cases go to Gemma before the final guardrail. These corrected decisions are not part of this checkpoint.',
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
        lines.append(f"| {layer_names.get(actor,actor)} | {counts['unannotated_suppress']:,} | {counts['unannotated_escalate']:,} | {counts['attack_suppress']:,} | {counts['attack_escalate']:,} |")
    lines+=['','Examples below identify actual scored records, not a separately scored explanation-quality study.','']
    for actor,e in examples.items():lines.append(f"- {layer_names.get(actor,actor)}, record {e['record']} ({e['id']}), {e['decision']}: {e['reason']}")
    lines+=['','## Per-record latency: what was actually timed','',
        'Mean means average time. Median is the middle record. The 95th percentile is the time within which 95% of records on that measured path finished. These are classification times, not proof that a protective action occurred.','',
        '| Measured path | Records | Mean | Median | 95th percentile |','|---|---:|---:|---:|---:|']
    path_names={'all_records':'All records, including fast rules','rules_only':'L1 rules without Qwen','qwen_l1':'Qwen stage on model-reviewed records','gemma_review':'Gemma assessment + challenge','gemma_record_total':'Complete classification on Gemma-reviewed records'}
    for key,t in latency.items():lines.append(f"| {path_names[key]} | {t['n']:,} | {t['mean_s']:.4f}s | {t['p50_s']:.4f}s | {t['p95_s']:.4f}s |")
    if 'gemma_record_total' in latency:
        mean=latency['gemma_record_total']['mean_s']
        lines+=['',f"**L2 is the expensive path:** if every incoming record required the same average complete Gemma path seen here ({mean:.2f}s), a sequential worker would classify roughly {60/mean:.2f} records/minute before additional queue/journal overhead. This is a mix-based estimate, not another measured run or a maximum hardware limit. The overall replay rate must not be advertised as the rate for two full model reviews on every record."]
    lines+=['',f"Local hardware snapshot: {hardware.get('cpu','see bundle')}; {hardware.get('ram_bytes',0)/1024**3:.1f} GiB RAM; GPU/model-memory/driver report: {hardware.get('gpu','see bundle')}. Models: Qwen3.5:4b (L1), Gemma4:12b (L2), with exact installed digests and requested options in run.json. This is not matched hardware against an enterprise cluster."]
    lines+=['',f"Observed checkpoint wall-clock rate: **{n*60/elapsed:.2f} saved records/minute** over {elapsed/3600:.2f} hours from the first journalled attempt to the confirmed stop. The earlier rough 50/minute estimate is not substituted for the final measured rate.",'',
        'This is one sequential replay worker. On a Gemma case, the next record waits for both its assessment and challenge. The normal source agent has separate L1/L2 queues/workers, but that concurrent mode was not measured here. Timings exclude live collector/network delay and pre-processing queue residence; they are not ingestion-to-containment times. This historical replay executes no response actions. Other desktop/development activity shared the machine.','',
        '## Reported corporate workload: daily intake converted to minutes','',
        'The supplied 1-3 alerts/minute comparison comes from daily incoming volume divided by 1,440 minutes. That arithmetic describes average demand over a full day. It does not measure maximum processing capacity or how long one investigation takes. These are different surveys and years, not a universal ideal.','',
        '| Survey and population | Reported incoming alerts/day | Average incoming alerts/minute |','|---|---:|---:|']
    for ref in WORKLOAD_REFERENCES:
        lines.append(f"| [{ref['title']}]({ref['url']}) | {ref['daily_alerts']:,} | {ref['daily_alerts']/1440:.2f} |")
    lines+=['',f"Arbiter saved **{n*60/elapsed:.2f} records/minute** on this replay. That exceeds these reported average arrival rates for the tested mix, suggesting processing headroom if arrivals and case costs were similar. This is an inference about workload scale, not a demonstrated deployment capacity: real bursts, heavier attack cases, persistent context, device actions and shared queues were not tested.",'',
        'The 4,484/day figure is also repeated in the supplied D3 article; the primary attribution above is Vectra\'s 2023 survey. The 28-tool figure belongs to Prophet\'s large-enterprise survey and is not attached to the older survey. The supplied 960-11,000/day range is not represented here as a verified original SANS result because its original survey table was not established.','',
        '## Corporate latency reference points: context, not a matched speed benchmark','',
        'No commercial system was run on these same records, hardware, context, quality targets and forced one-record workflow. A claim that enterprise products would be slower one-by-one is therefore untested. The verified daily-intake conversions above are not used as a per-alert latency baseline.','',
        '| Published reference | Number and unit | Why it is not our same measurement |','|---|---|---|']
    for ref in REFERENCES:lines.append(f"| [{ref['title']}]({ref['url']}) | {ref['metric']} | {ref['scope']} |")
    lines+=['','References checked November 18, 2026. A one-minute query schedule is not a one-alert-per-minute throughput ceiling. The reported two-alerts/minute workload is not a processing limit; the 200/minute automation claim also prevents treating 1-3/minute as a universal corporate capacity. An under-two-minute claim is an upper bound, not an exact measured latency from which to invent a speedup factor. Vendor claims are attributed, not independently reproduced here. A distributed batch can process many incidents together; its interval cannot be divided or multiplied into an invented isolated-alert latency. Fast local classification is a measured property of this replay, not proof of faster corporate investigation, ingestion, correlation, or response.','',
        '## Upcoming upgrade: estimated performance, not measured improvement','',
        'The proposed terminal pipeline has five workers: gateway, L1, L2 prefilter, L2 and final guardrail. Controlled software tests can establish that the stages overlap; they do not establish real-GPU speedup. The checkpoint above remains the original sequential architecture.','',
        f"With the existing routing and the same stage costs, perfect independent overlap of L1 and L2 would reduce their serial bottleneck enough for at most about **{overlap_gain:.2f}% higher stage-work throughput**. This calculation compares summed stage time with the slower stage, not with an enterprise product. It excludes queue/database overhead and is not a promised wall-clock gain.",'',
        'The routing fix is a separate change: it sends unresolved Qwen escalations to Gemma instead of treating missing context as a terminal flag. A stronger independent L2 prefilter can quiet supported routine cases, but its suppression rate has not been established. More Gemma reviews can outweigh the benefit of parallel workers.','',
        'The upcoming prefilter uses independently checked reasons, including exact human-corrected process context and a narrow native Wazuh resolved-vulnerability notification check. It does not copy Qwen\'s opinion or promise to suppress most escalations. The final guardrail still protects risky or unsupported exits. These are software-tested rules, not measured improvements on this public checkpoint.','',
        '| Assumed share of L1 escalations safely quieted by L2 prefilter | Serial inference scenario, records/min | Ideal independent-stage overlap, records/min |','|---|---:|---:|']
    for projection in projections:
        lines.append(f"| {projection['assumed_l2_prefilter_suppression_percent']:.0f}% | {projection['serial_inference_records_per_minute']:.2f} | {projection['ideal_stage_overlap_records_per_minute']:.2f} |")
    lines+=['','These are planning scenarios, not tested outcomes or guaranteed bounds. Each assumes this checkpoint\'s mean L1 cost, fraction of eligible L1 escalations and mean Gemma review time remain unchanged; every unsuppressed eligible escalation reaches Gemma. The first column is an assumption, not a suppression target. The serial scenario adds average stage costs; the ideal overlap scenario uses the slower stage. Shared-GPU contention, reloads, longer context, extra enrichment, bursts and storage can make real throughput worse than either estimate. Overlapping different records does not by itself shorten one Gemma assessment/challenge. Do not force unsafe suppressions to reach a desired percentage. No estimated accuracy gain is claimed before a separate attack-containing evaluation.','',
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
