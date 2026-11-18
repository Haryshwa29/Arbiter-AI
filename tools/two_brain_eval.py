"""Run frozen public alerts through Qwen L1 and Gemma L2 final alert decisions."""
from pathlib import Path
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import math
import platform
import statistics
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from arbiter.l2_advisory import packet_for
from arbiter.l2_final_review import FinalReviewL2Brain, eligible
from arbiter.llm import OllamaBackend, SYSTEM_PROMPT
from arbiter.memory import Memory
from arbiter.schema import Event
from arbiter.triage import TriageEngine
from arbiter.guardrails import final_guardrail_check
from tools.public_dataset_eval import digest, metrics, ollama_json, save


def read_rows(path):
    return [json.loads(x) for x in path.read_text(encoding='utf-8').splitlines()] if path.exists() else []


def timing(values):
    values=sorted(values)
    return {'n':len(values),'p50_s':statistics.median(values),'p95_s':values[math.ceil(.95*len(values))-1],
        'mean_s':statistics.mean(values),'max_s':max(values),'total_s':sum(values)} if values else {'n':0}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample',type=Path,default=ROOT/'evals/2026-11-17-ait-ads-hardening/holdout/sample.jsonl')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--primary',default='qwen3.5:4b')
    parser.add_argument('--secondary',default='gemma4:12b')
    parser.add_argument('--review-seconds',type=int,default=180)
    parser.add_argument('--resume',action='store_true')
    parser.add_argument('--reuse-primary',type=Path,help='Reuse frozen L1 outputs only after input/model and current final-gate parity checks')
    args=parser.parse_args()
    if args.primary==args.secondary:parser.error('the two brains must use distinct models')
    args.sample=args.sample.resolve()
    out=args.out.resolve();out.mkdir(parents=True,exist_ok=True)
    sample=read_rows(args.sample)
    if not sample:parser.error('empty sample')
    second=FinalReviewL2Brain(args.secondary,args.review_seconds)
    details=second.backend.verify()
    tags=ollama_json('/api/tags')
    models={m['name']:m for m in tags.get('models',[]) if isinstance(m,dict)}
    if args.primary not in models or args.secondary not in models:parser.error('both local models must be installed')
    if any(models[m].get('remote_host') or models[m].get('remote_model') for m in (args.primary,args.secondary)):
        parser.error('remote model aliases are forbidden')
    reused=None
    if args.reuse_primary:
        reused=args.reuse_primary.resolve()
        previous=json.loads((reused/'run.json').read_text())
        prior_rows=read_rows(reused/'primary.jsonl')
        if (previous['sample_sha256']!=digest(args.sample)
                or previous['primary']['digest']!=models[args.primary]['digest']
                or [(r['sample_id'],r['label']) for r in prior_rows]!=[(s['sample_id'],s['label']) for s in sample]):
            parser.error('frozen L1 input/model identity mismatch')
        if any(final_guardrail_check(Event(**s['event']),r['decision']) for s,r in zip(sample,prior_rows)):
            parser.error('a frozen L1 decision fails the current final gate; run L1 fresh')
    code={p.relative_to(ROOT).as_posix():{'raw':digest(p),'canonical_lf':hashlib.sha256(p.read_bytes().replace(b'\r\n',b'\n')).hexdigest()}
          for p in sorted((ROOT/'arbiter').rglob('*')) if p.suffix in {'.py','.json'}}
    meta={'sample_sha256':digest(args.sample),'sample_size':len(sample),'sample_source':args.sample.relative_to(ROOT).as_posix(),
        'dataset':'AIT-ADS v1, DOI 10.5281/zenodo.8263181','primary':models[args.primary],'secondary':models[args.secondary],
        'secondary_verified_details':details,'git_parent':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
        'code_sha256':code,'runner_sha256':digest(__file__),'python':platform.python_version(),
        'protocol':{'mode':'historical classification replay; Gemma may confirm or suppress successful Qwen escalations; no device actions',
            'route':'successful L1 escalations enter independent L2 prefilter; known risk or insufficient isolated protocol/auth context retains without Gemma; exact human feedback may quiet; other cases go to Gemma',
            'first_stage':'reused frozen Qwen outputs, current final-gate parity checked; no Qwen calls' if reused else 'fresh independent memory per alert; unchanged Qwen prompt',
            'primary_reused_from':reused.relative_to(ROOT).as_posix() if reused else None,
            'second_stage':'L2 prefilter, independent Gemma assessment without L1 prose when needed, separate challenge, and shared final guardrail used by L1 and L2',
            'staging':'all Qwen decisions first, then all eligible Gemma reviews; not a live queue-delay measurement',
            'review_budget_s':args.review_seconds,'gemma_options':{'think':False,'num_ctx':8192,'num_predict':1536,'temperature':.1},
            'suppression_policy':'one Gemma classification, confidence >=0.9, accepted challenge and shared risk veto; compatibility outlook is derived, not a second independent model decision',
            'output_format':'JSON schemas for assessment and critic, then independent Python evidence/decision validation',
            'development':'known old cases exposed anchoring, duplicate-decision inconsistency, missing DNS/port fields and dangerous quieting of root/DNS attack records; these cases were used for development and excluded from the new sample',
            'grounding_limit':'exact assertions/citation IDs are checked; semantic truth of all prose is not certified'},
        'started_utc':datetime.now(timezone.utc).isoformat()}
    meta_path=out/'run.json'
    if meta_path.exists():
        if not args.resume:raise SystemExit('Refusing to overwrite a run; use --resume to continue identical frozen inputs and code')
        prior=json.loads(meta_path.read_text())
        for key in ('sample_sha256','primary','secondary','code_sha256','runner_sha256','protocol'):
            if prior[key]!=meta[key]:raise SystemExit('Resume provenance mismatch: '+key)
    else:
        save(meta_path,meta)
        (out/'sample.jsonl').write_bytes(args.sample.read_bytes())
        if reused:
            (out/'primary.jsonl').write_bytes((reused/'primary.jsonl').read_bytes())
            (out/'primary-audit.jsonl').write_bytes((reused/'primary-audit.jsonl').read_bytes())
    primary=read_rows(out/'primary.jsonl')
    if [r['sample_id'] for r in primary] != [r['sample_id'] for r in sample[:len(primary)]]:
        raise ValueError('primary checkpoint does not match frozen sample')
    backend=OllamaBackend(args.primary,'http://127.0.0.1:11434')
    with (out/'primary.jsonl').open('a',encoding='utf-8') as stream:
        for i,item in enumerate(sample[len(primary):],len(primary)+1):
            memory=Memory(':memory:');engine=TriageEngine(memory,backend,out/'primary-audit.jsonl',shadow=True)
            started=time.perf_counter()
            try:v=engine.triage(Event(**item['event']))
            finally:elapsed=time.perf_counter()-started;memory.close()
            row={k:v for k,v in item.items() if k!='event'}
            row.update(json.loads(v.to_json()),latency_s=elapsed,
                final_guardrail=getattr(v,'final_guardrail',{}),
                policy_fallback=v.rationale.startswith('LLM tier failed ('),backend='ollama',model=args.primary)
            primary.append(row);stream.write(json.dumps(row,allow_nan=False)+'\n');stream.flush()
            print(f"Qwen {i}/{len(sample)} {item['sample_id']} -> {row['decision']} [{row['tier']}] {elapsed:.2f}s",flush=True)
    selected=[(s,r) for s,r in zip(sample,primary) if eligible(r)]
    reviews=read_rows(out/'secondary.jsonl')
    if [r['sample_id'] for r in reviews] != [s['sample_id'] for s,r in selected[:len(reviews)]]:
        raise ValueError('secondary checkpoint does not match eligible primary alerts')
    with (out/'secondary.jsonl').open('a',encoding='utf-8') as stream,(out/'secondary-inputs.jsonl').open('a',encoding='utf-8') as packets:
        for i,(item,first) in enumerate(selected[len(reviews):],len(reviews)+1):
            event=Event(**item['event']);second.backend.usage.clear()
            packets.write(json.dumps({'sample_id':item['sample_id'],'packet':packet_for(event,first,True,final_review=True)},allow_nan=False)+'\n');packets.flush()
            started=time.perf_counter()
            try:
                brief=second.review_event(event,first,True)
                row={'sample_id':item['sample_id'],'scenario':item['scenario'],'label':item['label'],
                    'expected_attack':item['expected_attack'],'brief':brief,'error':None}
            except Exception as exc:
                row={'sample_id':item['sample_id'],'scenario':item['scenario'],'label':item['label'],
                    'expected_attack':item['expected_attack'],'brief':None,'error':{'type':type(exc).__name__,'message':str(exc)[:500]}}
            row.update(latency_s=time.perf_counter()-started,usage=list(second.backend.usage),final_alert_decision=row['brief']['alert_decision'] if row['brief'] else 'escalate',action_executed=False)
            reviews.append(row);stream.write(json.dumps(row,allow_nan=False)+'\n');stream.flush()
            status=row['brief']['review_status']+':'+row['brief']['outlook'] if row['brief'] else 'ERROR:'+row['error']['type']
            actor='Gemma' if row['usage'] else 'L2 rules'
            print(f"{actor} {i}/{len(selected)} {item['sample_id']} {status} {row['latency_s']:.2f}s; final={row['final_alert_decision']}",flush=True)
            save(out/'progress.json',{'primary_done':len(primary),'primary_total':len(sample),'secondary_done':len(reviews),'secondary_total':len(selected),
                'secondary_errors':sum(r['error'] is not None for r in reviews)})
    by_id={r['sample_id']:r for r in reviews}
    final=[]
    for first in primary:
        review=by_id.get(first['sample_id'])
        final.append({**first,'decision':review['final_alert_decision'] if review else first['decision'],
            'first_stage_decision':first['decision'],'second_stage':review,
            'decision_source':('l2-prefilter' if review['brief']['review_status']=='prefilter' else 'gemma') if review and review['brief'] else 'l2-failure-policy' if review else 'shared-final-guardrail' if first.get('final_guardrail',{}).get('veto') else first['tier']})
    with (out/'final.jsonl').open('w',encoding='utf-8') as stream:
        for row in final:stream.write(json.dumps(row,allow_nan=False)+'\n')
    summary={'first_stage':metrics(primary),'visible_final_alerts':metrics(final),
        'first_stage_tiers':dict(Counter(r['tier'] for r in primary)),
        'first_stage_errors':sum(r['policy_fallback'] for r in primary),
        'secondary_eligible':len(selected),'secondary_completed':len(reviews),
        'secondary_validated':sum(r['brief'] is not None for r in reviews),
        'secondary_errors':sum(r['error'] is not None for r in reviews),
        'l2_prefilter_routes':dict(Counter(r['brief']['prefilter']['route'] if r['brief'] else 'error' for r in reviews)),
        'gemma_reviews':sum(bool(r['usage']) for r in reviews),
        'l2_prefilter_decisions':sum(r['brief'] is not None and r['brief']['review_status']=='prefilter' for r in reviews),
        'first_stage_final_guardrail_vetoes':dict(Counter(r['final_guardrail']['veto'] for r in primary if r['final_guardrail'].get('veto'))),
        'secondary_status':dict(Counter(r['brief']['review_status'] if r['brief'] else 'unavailable' for r in reviews)),
        'advisory_outlooks':dict(Counter(r['brief']['outlook'] if r['brief'] else 'unavailable' for r in reviews)),
        'advisory_by_label_class':{name:dict(Counter(r['brief']['outlook'] if r['brief'] else 'unavailable' for r in reviews if r['expected_attack']==flag))
                                  for name,flag in [('attack_annotation',True),('no_attack_annotation',False)]},
        'timing':{'qwen_engine':timing([r['latency_s'] for r in primary]),
            'l2_stage':timing([r['latency_s'] for r in reviews]),
            'gemma_review':timing([r['latency_s'] for r in reviews if r['usage']])},
        'actions_executed':0,'alert_decisions_changed_by_gemma':sum(r['final_alert_decision']=='suppress' for r in reviews),
        'gemma_decisions_by_label_class':{name:dict(Counter(r['final_alert_decision'] for r in reviews if r['expected_attack']==flag))
            for name,flag in [('attack_annotation',True),('no_attack_annotation',False)]},
        'caution':'Selected alert-label replay, not live breach detection; unannotated records are not certified benign; checks do not certify every prose claim.'}
    save(out/'summary.json',summary)
    print(json.dumps(summary,indent=2),flush=True)


if __name__=='__main__':main()
