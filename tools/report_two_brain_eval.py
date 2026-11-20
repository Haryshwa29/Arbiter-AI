"""Verify and explain a completed Qwen L1 / Gemma L2 classification replay."""
from pathlib import Path
import argparse
from collections import Counter
import csv
import hashlib
import json

ROOT=Path(__file__).resolve().parents[1]

def load(path):return json.loads(path.read_text(encoding='utf-8-sig'))
def rows(path):return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines()]
def pct(n,d):return f'{100*n/d:.1f}%' if d else 'undefined'
def matrix(data):
    c=Counter((r['expected_attack'],r['decision']) for r in data)
    return {k:c[v] for k,v in {'tp':(True,'escalate'),'fn':(True,'suppress'),'fp':(False,'escalate'),'tn':(False,'suppress')}.items()}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);a=p.parse_args();out=a.directory.resolve()
    meta=load(out/'run.json');summary=load(out/'summary.json');sample=rows(out/'sample.jsonl')
    first=rows(out/'primary.jsonl');second=rows(out/'secondary.jsonl');final=rows(out/'final.jsonl');packets=rows(out/'secondary-inputs.jsonl')
    assert hashlib.sha256((out/'sample.jsonl').read_bytes()).hexdigest()==meta['sample_sha256']
    assert len(first)==len(sample)==len(final)==meta['sample_size']
    assert [(s['sample_id'],s['label']) for s in sample]==[(r['sample_id'],r['label']) for r in first]
    selected=[r for r in first if r['decision']=='escalate' and r['tier']=='llm' and r['backend']=='ollama' and not r['policy_fallback']]
    assert [r['sample_id'] for r in selected]==[r['sample_id'] for r in second]==[r['sample_id'] for r in packets]
    by_id={r['sample_id']:r for r in second};sources={r['sample_id']:r for r in sample}
    for r in second:
        assert r['action_executed'] is False
        assert r['final_alert_decision'] in {'escalate','suppress'}
        if r['brief']:
            b=r['brief'];assert b['action']=='human_review' and b['action_authority'] is False
            assert b['reviewed_event_id']==sources[r['sample_id']]['event']['id']
            assert b['alert_decision']==r['final_alert_decision']
            if b['decision']=='suppress':
                assert b['confidence']>=.9 and b['review_status']=='accepted' and b['outlook']=='routine_looking'
        else:assert r['error'] and r['final_alert_decision']=='escalate'
    for original,result in zip(first,final):
        assert original['sample_id']==result['sample_id']
        assert result['decision']==(by_id[original['sample_id']]['final_alert_decision'] if original['sample_id'] in by_id else original['decision'])
    for name,h in meta['code_sha256'].items():
        actual=(ROOT/name).read_bytes();assert hashlib.sha256(actual.replace(b'\r\n',b'\n')).hexdigest()==h['canonical_lf'],name
    for data,key in [(first,'first_stage'),(final,'visible_final_alerts')]:
        for k,value in matrix(data).items():assert summary[key][k]==value
    f=summary['first_stage'];z=summary['visible_final_alerts'];pos=f['tp']+f['fn'];neg=f['fp']+f['tn'];n=len(first);m=len(second)
    q=summary['timing']['qwen_engine'];g=summary['timing']['gemma_review']
    hardware=load(out/'hardware.json')
    quiet=[r for r in second if r['final_alert_decision']=='suppress']
    attack_quiet=[r for r in quiet if r['expected_attack']]
    errors=Counter((r['error']['type'],r['error']['message']) for r in second if r['error'])
    primary_by=Counter((r['tier'],r['expected_attack'],r['decision']) for r in first)
    reviewed_attack=sum(r['expected_attack'] for r in second)
    lines=['# Qwen L1 and Gemma L2: public attack-data results','',
        '**Qwen decides what to escalate. Gemma receives only those escalations and may keep the warning or suppress it with a written reason. No device action was authorized or executed.**','',
        f"**Measured result:** after both stages, {z['tp']}/{pos} attack-annotated records remained flagged ({pct(z['tp'],pos)}), and {z['tn']}/{neg} records without attack annotations were quieted ({pct(z['tn'],neg)}). Gemma removed {len(quiet)} Qwen warnings, including {len(attack_quiet)} attack-annotated records.",
        '',
        '**L2 did not reduce the warning count in this run.** It completed its reviews but added substantial processing time.' if not quiet else 'The table below separates L1 outcomes from the added effect of L2.',
        '',
        '## What we built, in everyday terms','',
        f"**Qwen (`{meta['primary']['name']}`) is L1, the first reviewer.** Existing quick rules handle clear cases. Qwen reads the unclear ones and either keeps them quiet or escalates them.",
        '',
        f"**Gemma (`{meta['secondary']['name']}`) is L2, the second reviewer.** It never receives the raw incoming stream directly. It receives only alerts successfully escalated by Qwen. It assesses the facts, then a separate Gemma call challenges that assessment. This is two passes by the same second model, not an independent third model.",
        '',
        '**Gemma can suppress a Qwen alert**, but only when it proposes suppression, describes the record as routine-looking, reports confidence of at least 0.9, supplies checked facts and a written reason, and passes the challenge. Otherwise the warning stays flagged. Errors also retain it. Mandatory safety-rule warnings stay flagged outside this model-review route.',
        '',
        'Both models run locally. Their metadata reports '+meta['primary']['details']['parameter_size']+' parameters for Qwen and '+meta['secondary']['details']['parameter_size']+' for Gemma; B means billion. Both use compressed '+meta['secondary']['details']['quantization_level']+' weights. Confidence is a model self-report, not a measured probability of correctness.',
        '',
        'The [ready-to-run terminal version](TWO-BRAIN-SETUP.md) implements this mode. Its event list shows the final decision alongside Qwen\'s original review; `l2-cases` stores the second review. Original audit totals retain first-stage decisions. The installed/portable dashboard application was not replaced, and this test does not establish dashboard integration or live queue performance.',
        '',
        '## What public dataset did we use?','',
        '**AIT Alert Data Set (AIT-ADS), version 1**, by Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Original dataset / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), licensed **CC BY 4.0**. The publisher requests citation of *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).',
        '',
        'Think of it as security-tool reports from eight simulated company networks. It mixes staged scanning, web exploitation, password attacks, privilege changes, command execution and data theft with routine logins and software activity. We use Wazuh and Suricata-via-Wazuh reports; unsupported AMiner reports are excluded.',
        '',
        f'This run uses **{n} frozen records: {pos} with publisher attack annotations and {neg} without attack annotations**. It reruns the same additional-sample cases from the previous comparison, not all 2.6 million supported records. The scoring uses the publisher\'s per-record `event_label`, not a broad attack time window. The model prompts do not receive these scoring labels.',
        '',
        '**A record without an attack annotation is not certified harmless.** These selected cases come from the same known public scenarios; they are not an independent new-campaign test or a production detection-rate estimate.',
        '',
        '## What were the actual numbers?','',
        '| Outcome on the same records | After L1 rules + Qwen | After Gemma L2 |','|---|---:|---:|',
        f"| Attack-annotated records flagged | {f['tp']}/{pos} ({pct(f['tp'],pos)}) | {z['tp']}/{pos} ({pct(z['tp'],pos)}) |",
        f"| Attack-annotated records wrongly quieted | {f['fn']}/{pos} ({pct(f['fn'],pos)}) | {z['fn']}/{pos} ({pct(z['fn'],pos)}) |",
        f"| Records without attack annotations quieted | {f['tn']}/{neg} ({pct(f['tn'],neg)}) | {z['tn']}/{neg} ({pct(z['tn'],neg)}) |",
        f"| Records without attack annotations still flagged | {f['fp']}/{neg} ({pct(f['fp'],neg)}) | {z['fp']}/{neg} ({pct(z['fp'],neg)}) |",
        f"| All visible warnings | {f['tp']+f['fp']}/{n} | {z['tp']+z['fp']}/{n} |",'',
        f"Gemma quieted **{len(quiet)} of the {m} Qwen escalations ({pct(len(quiet),m)})**: {len(quiet)-len(attack_quiet)} records without attack annotations and {len(attack_quiet)} attack-annotated records. This measures the added effect of L2 on this run; it must not be credited to a new prefilter.",
        '',
        '## Which layer succeeded or failed?','',
        '| Stage | What the test found |','|---|---|',
        f"| Quick prefilter | Quieted {primary_by['prefilter',False,'suppress']} unannotated records and {primary_by['prefilter',True,'suppress']} attack-annotated records. |",
        f"| Mandatory guardrails | Flagged {primary_by['guardrail',True,'escalate']} attack-annotated records before Qwen/Gemma. These are rule coverage, not Gemma successes. |",
        f"| Qwen L1 | Sent {m} alerts to Gemma, including {reviewed_attack} attack-annotated records; {summary['first_stage_errors']} model-failure policy fallbacks. |",
        f"| Gemma L2 decisions | Wrongly suppressed {len(attack_quiet)} of its {reviewed_attack} attack-annotated inputs ({pct(len(attack_quiet),reviewed_attack)}). |",
        f"| Gemma response reliability | {summary['secondary_validated']}/{m} reviews passed structure/fact checks ({pct(summary['secondary_validated'],m)}); {summary['secondary_errors']}/{m} failed ({pct(summary['secondary_errors'],m)}). |",
        f"| Challenge pass | Accepted {summary['secondary_status'].get('accepted',0)} assessments; challenged {summary['secondary_status'].get('challenged',0)}. A challenge retains the warning. |",
        '| Device response | Zero commands, network blocks or other containment actions. |','',
        'Passed checks means the reply had the required format and exact copied fields/citation IDs. It does not certify every conclusion or sentence. A model-generated ordinary explanation can still be wrong. Neither confidence nor a second pass by the same model is a guarantee.','',
        '### What failed and why','',
        f"Gemma proposed keeping all {m} warnings; there were **zero suppression proposals** and zero suppression proposals overturned by the software. Thus the lack of reduction was its decision behavior under these frozen prompts and cold-start evidence, rather than the confidence gate rejecting attempted suppressions. This run does not isolate which prompt, model or context change would improve that behavior." if all(r['brief'] and r['brief']['proposed_decision']=='escalate' for r in second) else 'The detailed review log distinguishes model proposals from any decision retained by the checks.',
        '',
        'The code\'s suppression branch is covered by controlled-response regression tests. This public run did not exercise suppression by the real model, because Gemma made no suppression proposals.' if not quiet else 'The detailed outputs retain every model proposal and final decision for inspecting suppression behavior.',
        '',
        'The inspected examples exposed explanation problems even when a final flag matched its label. In `fox:12977`, Gemma treated a high-numbered network port as a listening service; the source instead shows traffic from port 443 to port 41262, which could be a client receiving a reply. The standalone fields omit the source port for this older wrapper, although the original message retains it. This needs both better field extraction and a more careful model interpretation.' if (out/'case-review.md').exists() else 'No independently scored explanation-quality study was performed for this run.',
        '',
        'In `fox:447150`, Gemma retained an attack-annotated session record but overstated what an administrator-level system process proved about privilege escalation. Its own challenge accepted both explanations. These selected examples are qualitative findings, not a measured error percentage for all explanations. A useful counterexample is `harrison:12719`, where Gemma found a concrete file-name-like clue inside a long DNS query; the quoted query was verified against the record.' if (out/'case-review.md').exists() else 'Structure/fact validation must not be reported as a semantic explanation score.',
        '']
    if errors:
        lines+=['| Failure reported by the checks | Count |','|---|---:|']
        for (kind,message),count in errors.most_common():lines.append(f'| `{kind}: {message.replace(chr(124),"/")}` | {count} |')
        lines+=['', 'An unsupported assertion means a copied fact name, value or type did not match the supplied evidence. Other schema/decision errors mean the reply did not meet the agreed response format. Transport/timeouts are availability failures. These are L2 model/response failures, not prefilter suppressions. Every failed review kept its alert flagged. The error log records the validator reason and token/timing metadata; raw rejected text is not retained, so it cannot establish the exact wording of each rejected claim.','']
    if attack_quiet:
        lines+=['The following attack-annotated records were quieted by Gemma. Its stated reason is reproduced as the explanation to investigate, not accepted as ground truth.','', '| Record | Publisher attack label | Gemma suppression reason |','|---|---|---|']
        for r in attack_quiet:lines.append(f"| `{r['sample_id']}` | `{r['label']}` | {r['brief']['decision_reason'].replace(chr(124),'/')} |")
        lines+=['','These misses belong to Gemma\'s final judgment on an L1 escalation. They were not removed by the quick prefilter.','']
    else:lines+=['Gemma did not suppress an attack-annotated record in this run. That is a result on its selected inputs, not proof that it cannot miss attacks.','']
    lines+=['## What improved, and what still needs work?','',
        'The earlier hardening added rules for web reconnaissance, retained important source-tool details and narrowly recognized routine mail/update observations. This iteration adds the requested L1-to-L2 handoff, final L2 decisions with written reasons, a separate challenge, strict fact checks, event-bound decisions and retention of warnings on errors. It does not retrain either model or make quieting infallible.',
        '',
        '1. **Inspect the advice and any wrong suppressions.** Check invented causes, mistaken attribution and ordinary explanations that the actual record does not support. A formal independently scored explanation-quality study is still needed.',
        '2. **Test whether L2 can distinguish ordinary activity from attacks.** Use development pairs with a concrete ordinary explanation and a similar-looking attack. Improve missing source fields and surrounding context, then freeze fresh evaluation cases. Keep response checks and retain failures; do not tune on the scored answers or retry them until they pass.',
        '3. **Test complete sequences and the live queue.** Measure time to the first useful warning, time to L2, backlog, repeated-event handling and restarts. The terminal scheduler coalesces related cases; this isolated replay reviews individual alerts and does not validate that scheduling behavior under load.',
        '4. **Test unfamiliar scenarios and repeat runs.** Compare Qwen alone with the cascade, including missed attacks, remaining warnings, reliable completion and speed. This sample has already been used in earlier development comparisons.',
        '5. **Finish the operational integration.** Test dashboard presentation and clearly separated L1/L2 counts. L2 decisions currently live in terminal cases; L1 audit and learned history are preserved. Decide how human-confirmed L2 corrections should update learning before allowing repeated automatic quieting.',
        '6. **Keep alert classification separate from device actions.** Suppressing an alert does not grant permission to block traffic, kill processes or run commands.','',
        '## How long did it take?','',
        f"Hardware: {hardware['cpu']}, {hardware['ram_bytes']/2**30:.1f} GiB usable RAM, {hardware['gpu']} with {hardware['gpu_memory_mib']:,} MiB GPU memory. Local Python {meta['python']} on Windows.",
        '',
        f"- Qwen/rule stage: {q['total_s']/60:.2f} minutes of measured work across {n} records.",
        f"- Half of Gemma reviews finished within {g.get('p50_s',0):.2f} seconds; 95% within {g.get('p95_s',0):.2f} seconds; longest {g.get('max_s',0):.2f} seconds.",
        f"- Total Gemma work: {g.get('total_s',0)/60:.2f} minutes across {m} inputs, including failures.",
        '- This is staged: all fresh Qwen decisions first, then every eligible Gemma review. It is not a live arrival-rate, queue-delay or breach-detection-time measurement.',
        '- Gemma uses two bounded calls, JSON-schema response formats, temperature 0.1, internal thinking off, an 8,192-token context request and a 1,536-token generation cap per call. Overall budget: 180 seconds; each inference request retains a 90-second cap. Explicit assessment and challenge text is saved; hidden thinking is not.',
        '- Compatibility probes used one previously seen public record. A thinking-enabled probe timed out; later probes exposed fact-field and prompt compatibility problems. Those fixes and settings were frozen before this scored run. An advice-only pilot was stopped after five reviews when the owner clarified that L2 should make final decisions. None of those pilot reviews count here.','',
        '## Inspect or reproduce the result','',
        '```text','python tools/two_brain_eval.py --out evals/your-qwen-gemma-run','python tools/report_two_brain_eval.py evals/your-qwen-gemma-run','```','',
        f"Input SHA-256: `{meta['sample_sha256']}`. The run records both model digests, raw and canonical-LF source hashes, options and the runner hash. Source was evaluated in a working tree on parent `{meta['git_parent']}`; those hashes identify its exact state.",'',
        '`sample.jsonl` is the frozen input. `input-provenance.json` preserves the sampling method, archive hashes and publisher-label revision. `primary.jsonl` preserves each L1 decision; `secondary-inputs.jsonl` holds label-free evidence packets; `secondary.jsonl` retains L2 results/errors; `final.jsonl` holds all final decisions. `summary.json` contains percentages and timings; CSV exports make the outcomes easier to inspect. Hardware and source-agent setup checks are recorded separately. `SHA256SUMS.txt` protects artifact bytes.','']
    if (out/'case-review.md').exists():lines+=['[Read the inspected examples and explanation limits](../'+out.relative_to(ROOT).as_posix()+'/case-review.md).','']
    if (out/'efficiency.json').exists():
        e=load(out/'efficiency.json');work=sum(e[k] for k in ('model_loading_s','model_prompt_processing_s','model_generation_s'))
        lines+=['## Efficiency review','',
            f"The local model runner reported {work:.2f} seconds of loading, prompt processing and generation, about {100*work/e['measured_review_s']:.1f}% of measured Gemma review time. This accounting comparison points to inference as the main cost; it is not an operating-system profile or a live-load benchmark. Rewriting small Python helpers would not address that cost.",'',
            'The existing scheduler, local transport and validators were reused. No runtime package or extra service was added, and the evaluated source was kept unchanged. A faster configuration needs a separate measured test of speed and missed attacks.',
            '', '[Read the efficiency measurements and review scope](../'+out.relative_to(ROOT).as_posix()+'/efficiency-review.md).','']
    report='\n'.join(lines)
    (ROOT/'docs/TWO-BRAIN-PUBLIC-EVAL.md').write_text(report,encoding='utf-8')
    readme=report.replace('(TWO-BRAIN-SETUP.md)','(../../docs/TWO-BRAIN-SETUP.md)')
    readme=readme.replace('(../'+out.relative_to(ROOT).as_posix()+'/case-review.md)','(case-review.md)')
    readme=readme.replace('(../'+out.relative_to(ROOT).as_posix()+'/efficiency-review.md)','(efficiency-review.md)')
    (out/'README.md').write_text(readme,encoding='utf-8')
    with (out/'primary.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=['sample_id','scenario','label','expected_attack','decision','tier','latency_s','rationale','evidence'],extrasaction='ignore');writer.writeheader();writer.writerows(first)
    with (out/'final.csv').open('w',newline='',encoding='utf-8') as stream:
        fields=['sample_id','scenario','label','expected_attack','first_decision','first_tier','first_reason','final_decision','final_decision_source','final_reason','final_evidence','qwen_latency_s','gemma_latency_s','gemma_error']
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for r in final:
            s=r.get('second_stage') or {};b=s.get('brief') or {}
            writer.writerow({**{k:r[k] for k in ('sample_id','scenario','label','expected_attack')},
                'first_decision':r['first_stage_decision'],'first_tier':r['tier'],'first_reason':r['rationale'],
                'final_decision':r['decision'],'final_decision_source':r['decision_source'],
                'final_reason':b.get('decision_reason') or ('Gemma review failed; original alert retained.' if s.get('error') else r['rationale']),
                'final_evidence':b.get('evidence',r['evidence']),
                'qwen_latency_s':r['latency_s'],'gemma_latency_s':s.get('latency_s',''),
                'gemma_error':json.dumps(s['error']) if s.get('error') else ''})
    with (out/'secondary.csv').open('w',newline='',encoding='utf-8') as stream:
        fields=['sample_id','scenario','label','expected_attack','final_alert_decision','review_status','proposed_decision','confidence','outlook','latency_s','decision_reason','assessment','gaps','error']
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for r in second:
            b=r['brief'] or {};writer.writerow({**{k:r[k] for k in fields if k in r and k!='error'},**{k:b.get(k,'') for k in fields if k not in r},'error':json.dumps(r['error']) if r['error'] else ''})
    print('Verified the full L1/L2 replay and wrote the plain-English report.')

if __name__=='__main__':main()
