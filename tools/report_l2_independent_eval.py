"""Verify and explain the independent L2 evaluation without changing old evidence."""
from pathlib import Path
from collections import Counter
import argparse
import csv
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from tools.report_two_brain_eval import load, rows, pct, matrix


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory',type=Path)
    out=parser.parse_args().directory.resolve()
    meta=load(out/'run.json');summary=load(out/'summary.json')
    sample=rows(out/'sample.jsonl');primary=rows(out/'primary.jsonl')
    second=rows(out/'secondary.jsonl');final=rows(out/'final.jsonl')
    packets=rows(out/'secondary-inputs.jsonl')
    assert hashlib.sha256((out/'sample.jsonl').read_bytes()).hexdigest()==meta['sample_sha256']
    assert len(sample)==len(primary)==len(final)==meta['sample_size']
    identities=[r['sample_id'] for r in sample]
    assert len(set(identities))==len(identities)
    assert identities==[r['sample_id'] for r in primary]==[r['sample_id'] for r in final]
    previous=set()
    for path in ['evals/2026-11-17-ait-ads/sample.jsonl','evals/2026-11-17-ait-ads-hardening/holdout/sample.jsonl']:
        previous.update(r['sample_id'] for r in rows(ROOT/path))
    assert not previous.intersection(identities)
    selected=[r for r in primary if r['decision']=='escalate' and r['tier']=='llm' and not r['policy_fallback']]
    assert [r['sample_id'] for r in selected]==[r['sample_id'] for r in second]==[r['sample_id'] for r in packets]
    indexed={r['sample_id']:r for r in second}
    sources={r['sample_id']:r for r in sample}
    for r,p in zip(second,packets):
        packet=dict(p['packet']);expected=packet.pop('digest')
        assert hashlib.sha256(json.dumps(packet,sort_keys=True).encode()).hexdigest()==expected
        assert 'first_review' not in packet
        assert r['action_executed'] is False
        b=r['brief']
        if not b:
            assert r['error'] and r['final_alert_decision']=='escalate'
            continue
        assert b['action_authority'] is False and b['action']=='human_review' and b['target'] is None
        assert b['reviewed_event_id']==sources[r['sample_id']]['event']['id']
        assert b['guardrail']['version']=='shared-final-v1'
        assert b['decision']==b['guardrail']['decision']==r['final_alert_decision']
        if b['decision']=='suppress':
            assert not b['guardrail']['veto'] and b['confidence']>=.9
            if b['review_status']=='prefilter':
                assert not r['usage'] and b['prefilter']['rule']=='L2_EXACT_HUMAN_FEEDBACK'
            else:assert r['usage'] and b['review_status']=='accepted' and b['challenge']['accept']
    for first,last in zip(primary,final):
        assert first['final_guardrail']['version']=='shared-final-v1'
        assert first['final_guardrail']['decision']==first['decision']
        review=indexed.get(first['sample_id'])
        assert last['decision']==(review['final_alert_decision'] if review else first['decision'])
    for data,key in [(primary,'first_stage'),(final,'visible_final_alerts')]:
        assert all(summary[key][k]==v for k,v in matrix(data).items())
    for name,h in meta['code_sha256'].items():
        assert hashlib.sha256((ROOT/name).read_bytes().replace(b'\r\n',b'\n')).hexdigest()==h['canonical_lf'],name
    assert hashlib.sha256((ROOT/'tools/two_brain_eval.py').read_bytes()).hexdigest()==meta['runner_sha256']
    model=[r for r in second if r['usage']]
    rules=[r for r in second if r['brief'] and r['brief']['review_status']=='prefilter']
    assert summary['gemma_reviews']==len(model)
    assert summary['l2_prefilter_decisions']==len(rules)
    before=summary['first_stage'];after=summary['visible_final_alerts']
    pos=after['tp']+after['fn'];neg=after['tn']+after['fp']
    model_quiet=[r for r in model if r['final_alert_decision']=='suppress']
    errors=[r for r in second if r['error']]
    misses=[r for r in final if r['expected_attack'] and r['decision']=='suppress']
    rule_counts=Counter(r['brief']['prefilter']['rule'] for r in rules)
    model_attack=sum(r['expected_attack'] for r in model)
    packet_index={r['sample_id']:r['packet'] for r in packets}
    missing_dns=[r for r in model_quiet if not packet_index[r['sample_id']]['facts'][0].get('dns_query')]
    timing=summary['timing'];n=len(sample);m=len(second)
    text=['# Independent L2 review: results and limits','',
        f"**Diagnostic limitation:** {len(missing_dns)} of the {len(model_quiet)} model suppressions lacked an extracted DNS question. Their label agreement does not establish a justified benign judgment. A stricter evidence-gated follow-up is required; this is not a production-readiness claim.",
        '',
        '**Qwen is L1. Only its escalations enter L2. Separate L2 rules decide whether Gemma adds useful work; a shared final guardrail checks L1 and L2 decisions.**','',
        f"On {n} fresh public alert records, L2 called Gemma {len(model)} times, settled {len(rules)} records without the model, and quieted {len(model_quiet)} warnings through Gemma. Final attack annotations flagged: {after['tp']}/{pos} ({pct(after['tp'],pos)}).",'',
        '## Why the earlier second brain was not earning its cost','',
        'The earlier 202-record test sent 97 Qwen escalations through Gemma, cleared none and added 50.51 minutes of L2 work. That route lacked the separate noise-oriented L2 pre-filter and complete shared final exit requested by the owner. Gemma also saw Qwen\'s opinion and had to provide two overlapping classification fields, which could disagree.',
        '',
        'Development checks changed several things together, so they do not prove that anchoring alone caused the old result. A less restrictive blind prompt did produce different decisions, but also quieted attack-annotated root-session and encoded-DNS records. Those failures were retained as development findings, not hidden or counted as new independent accuracy.',
        '',
        '## What changed','',
        '1. **Separate L2 pre-filter.** Known risk stays flagged without spending a model call. Isolated protocol/login alerts that lack the context needed to settle them also stay flagged without paying Gemma to repeat the same evidence. Exact process history can quiet a case only after at least five explicit human false-alarm corrections and no unresolved risk. Broad history and the model\'s own earlier answers are insufficient.',
        '2. **Independent model judgment.** Gemma receives the original facts without Qwen\'s rationale or conclusion text. It returns one classification. The compatibility outlook field is derived instead of asking for a contradictory second decision.',
        '3. **Better evidence.** Older text-wrapped IDS source/destination ports and single-question DNS arrays are preserved. Conflicting endpoints and incompletely represented multi-question DNS records retain review.',
        '4. **Separate L2 safety rules.** Explicit sudo/root session activity, source-classified attacks and encoded-looking DNS payloads stay protected. A normal-looking session closing log does not excuse the earlier privileged operation.',
        '5. **One final safety gate.** L1 model decisions, L1 rule shortcuts, L2 pre-filter decisions and Gemma outputs use the shared suppression veto. Written reasons, fact checks, a successful model challenge and the 0.9 model-suppression threshold remain. Classification grants no device-action rights.',
        '',
        '## Public dataset and test design','',
        '**AIT Alert Data Set (AIT-ADS), version 1**, by Max Landauer, Florian Skopik and Markus Wurzenberger, AIT Austrian Institute of Technology. [Publisher / DOI 10.5281/zenodo.8263181](https://zenodo.org/records/8263181), **CC BY 4.0**. Cite *Introducing a New Alert Data Set for Multi-Step Attack Analysis* (2024) and *Maintainable Log Datasets for Evaluation of Intrusion Detection Systems* (2023).',
        '',
        'This is security-tool reporting from eight simulated company networks, containing routine activity and staged scanning, exploitation, password attacks, privilege changes, remote commands and data theft. We use Wazuh and Suricata-via-Wazuh; unsupported AMiner data is excluded.',
        '',
        f"The new frozen sample has {n} records: {pos} attack annotations and {neg} without attack annotations. All 416 previously selected raw records, including the development controls, were excluded before sampling. The seed and publisher-label revision are in input-provenance.json. These are different records from the same eight public scenarios, not independent new organizations or campaigns.",
        '',
        'The publisher\'s per-record event_label supplies scoring after inference. No scoring labels reach either model. A missing attack annotation does not certify harmlessness. Each record starts with empty history; therefore the human-feedback shortcut is covered by regression tests, not exercised as a learned company profile in this dataset. This is classification in shadow mode, not live collection or verified attack blocking.',
        '',
        '## Measured decisions','',
        '| Outcome | L1 rules + fresh Qwen | After L2 and final checks |','|---|---:|---:|',
        f"| Attack annotations flagged | {before['tp']}/{pos} ({pct(before['tp'],pos)}) | {after['tp']}/{pos} ({pct(after['tp'],pos)}) |",
        f"| Attack annotations quieted | {before['fn']} | {after['fn']} |",
        f"| Records without attack annotations quieted | {before['tn']}/{neg} ({pct(before['tn'],neg)}) | {after['tn']}/{neg} ({pct(after['tn'],neg)}) |",
        f"| Records without attack annotations still flagged | {before['fp']} | {after['fp']} |",
        f"| Total warnings | {before['tp']+before['fp']} | {after['tp']+after['fp']} |",'',
        'Compare the two columns on the same new input to measure L2\'s added effect. Comparing headline percentages with the older sample is not a controlled estimate of improvement, because the selected records differ.',
        '',
        '## Which layer did the work?','',
        f'- Qwen escalations reaching the L2 stage: **{m}**.',
        f'- L2 decisions made without calling Gemma: **{len(rules)}**.',
        f'- Records actually sent to Gemma: **{len(model)}** ({pct(len(model),m)} of L2 inputs).',
        f'- Gemma inputs with attack annotations: **{model_attack}**. Do not credit Gemma for attacks retained by rules before it.',
        f'- Warnings quieted by Gemma: **{len(model_quiet)}**.',
        f'- Invalid/unavailable L2 outcomes: **{len(errors)}**; each retains its warning.',
        '- Device actions: **0**.','',
        '| Independent L2 rule | Records |','|---|---:|']
    descriptions={'L2_CONTEXT_REQUIRED':'Missing flow/login context: retain without repeating inference',
        'L2_PRIVILEGED_SESSION':'Recorded sudo/root session: retain for review',
        'L2_DNS_PAYLOAD':'Encoded-looking DNS payload: retain for review',
        'L2_SOURCE_ATTACK_CLASS':'Source tool classifies an attack behavior: retain',
        'L2_ENDPOINT_CONFLICT':'Conflicting source/destination details: retain',
        'L2_MULTIPLE_DNS_QUESTIONS':'Multiple DNS questions need contextual review',
        'L2_EXACT_HUMAN_FEEDBACK':'Exact, human-corrected process context: quiet'}
    for name,count in rule_counts.most_common():
        text.append(f'| {descriptions.get(name,name)} (`{name}`) | {count} |')
    text+=['','A context-required outcome is an unresolved warning retained cheaply, not a false positive successfully removed. Checked fact references do not certify every sentence. The challenge is a second pass by Gemma, not a third independent model.','',
        '## Where it failed','']
    if misses:
        text+=['| Quieted attack-annotated record | Final deciding layer | Publisher label |','|---|---|---|']
        for r in misses:text.append(f"| {r['sample_id']} | {r['decision_source']} | {r['label']} |")
    else:text+=['No attack-annotated record was quieted in this selected run. That does not establish a production detection rate.']
    for r in errors:text.append(f"- {r['sample_id']}: {r['error']['type']}: {r['error']['message']}")
    text+=['',
        f"There are still **{after['fp']} warnings without attack annotations**. Retaining them is not evidence that L2 has solved noise. The next work is useful connection/login context and independent checks of the written explanations, not another blanket pass over the same isolated evidence.",
        '',
        '## Processing cost','',
        f"- L1 rules plus Qwen: {timing['qwen_engine']['total_s']/60:.2f} minutes of measured work across {n} records.",
        f"- Complete L2 stage: {timing['l2_stage'].get('total_s',0)/60:.2f} minutes across {m} inputs.",
        f"- Actual Gemma reviews: half finished within {timing['gemma_review'].get('p50_s',0):.2f}s, 95% within {timing['gemma_review'].get('p95_s',0):.2f}s; {timing['gemma_review'].get('total_s',0)/60:.2f} minutes in total.",
        '- Qwen runs first, then eligible L2 reviews. This does not measure concurrent operation, live queue delay or time to detect a breach.',
        '- Gemma settings remain local, internal thinking off, temperature 0.1, 8,192 context tokens and a 1,536-token generation cap per call. An assessment and separate challenge are retained. New prompts, evidence and routing are frozen in run.json and source hashes. Hidden thinking is not stored.',
        '',
        '## Small-code review and next steps','',
        'The change reuses the local transport, validators, scheduler and SQLite memory. No runtime package, extra model, service or cache was added. The measurable saving comes from avoiding unhelpful model reviews. A separate small fix drains bounded rejected POST bodies so Windows clients receive authentication/CSRF denials instead of intermittent connection resets; the authorization rules are unchanged.',
        '',
        'Next: test full chronological attack stories and richer independent context; inspect wrong quieting and unsupported explanations; repeat on fresh complete scenarios or another public dataset; measure live queue load and restart behavior. Test safe lookalikes and attack lookalikes together. A larger model or a successful reply format is not a substitute for these checks.',
        '',
        'The terminal event view preserves both stages and their deciding actor. Original ingestion/audit totals retain first-stage evidence. An installed/portable dashboard build was not replaced. Native containment defaults and executor permissions remain separate and unchanged.',
        '',
        '## Reproduce and inspect','',
        '```text',f'python tools/two_brain_eval.py --sample {out.relative_to(ROOT).as_posix()}/sample.jsonl --out evals/your-new-run',
        'python tools/report_l2_independent_eval.py evals/your-new-run','```','',
        f"Frozen sample SHA-256: {meta['sample_sha256']}. run.json identifies model digests, source hashes, runner hash and settings. SHA256SUMS.txt covers the archived files. Complete outcomes and readable final.csv preserve L1, L2 route, model proposal, final decision and actor.",'',
        'Development controls are separately labelled, reuse older Qwen escalations, and are not included in the new scored totals. See development-notes.md for the diagnostic failures and the boundary of what was tested.','']
    report='\n'.join(text)
    (ROOT/'docs/L2-INDEPENDENT-REVIEW.md').write_text(report,encoding='utf-8')
    (out/'README.md').write_text(report,encoding='utf-8')
    fields=['sample_id','label','expected_attack','l1_decision','l1_tier','l2_rule','gemma_called','l2_proposal','final_decision','final_actor','final_reason','error']
    with (out/'final.csv').open('w',newline='',encoding='utf-8') as stream:
        writer=csv.DictWriter(stream,fieldnames=fields);writer.writeheader()
        for first,last in zip(primary,final):
            r=indexed.get(first['sample_id']) or {};b=r.get('brief') or {}
            writer.writerow({**{k:first[k] for k in ('sample_id','label','expected_attack')},
                'l1_decision':first['decision'],'l1_tier':first['tier'],
                'l2_rule':b.get('prefilter',{}).get('rule',''),'gemma_called':bool(r.get('usage')),
                'l2_proposal':b.get('proposed_decision',''),'final_decision':last['decision'],
                'final_actor':last['decision_source'],
                'final_reason':b.get('decision_reason',first['rationale']),
                'error':json.dumps(r['error']) if r.get('error') else ''})
    print('Verified independent L2 routing, shared final checks and paired outcome counts.')

if __name__=='__main__':main()
