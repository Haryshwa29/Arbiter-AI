"""Recompute the stopped checkpoint without model calls or source mutations."""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import sqlite3
import statistics
import zipfile


def sha(path):
    with path.open('rb') as f:
        return hashlib.file_digest(f, 'sha256').hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8-sig'))


def stats(values):
    values=sorted(v for v in values if isinstance(v,(int,float)) and math.isfinite(v))
    if not values:return {'n':0}
    return dict(n=len(values),mean_s=statistics.mean(values),median_s=statistics.median(values),
        p95_s=values[math.ceil(.95*len(values))-1],max_s=values[-1],total_s=sum(values))


def connect(path):
    return sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)


def main(args):
    run,out,initial,intermediate=map(Path,(args.run,args.out,args.initial,args.intermediate))
    out.mkdir(parents=True,exist_ok=True)
    progress,cohort,metadata=map(read,(run/'progress.json',run/'cohort.json',run/'run.json'))
    assert progress['status']=='stopped-error' and not any(w['alive'] for w in progress['workers'].values())
    for name,expected in read(run/'frozen-files.json').items():assert sha(run/name)==expected,name
    base=read(initial/'summary.json')
    with zipfile.ZipFile(initial/'checkpoint-data.zip') as z:
        initial_models={m['name']:m['digest'] for m in json.loads(z.read('run.json'))['models']}
    assert initial_models=={name:model['digest'] for name,model in metadata['models'].items()}
    old={}
    with connect(intermediate/'results.db') as db:
        for seq,payload in db.execute('SELECT seq,payload FROM results'):
            r=json.loads(payload);old[seq]=(r['event_id'],r['expected_attack'],r['decision'])
    counters=Counter();families=defaultdict(Counter);actors=defaultdict(Counter)
    times=defaultdict(list);usage=defaultdict(list);critic=Counter();veto=Counter();paired=Counter()
    saved=set();index_ids={};source_times=[];misses=[];failed_rows=[];paired_rows=[];hourly=defaultdict(Counter)
    calls=Counter();one_two=Counter();special_model_attacks=[]
    with connect(run/'events.db') as db:
        errors={}
        for body, in db.execute('SELECT body FROM l2_cases'):
            case=json.loads(body)
            if case.get('review_error'):
                errors[case['event_id']]={k:case[k] for k in ('review_error','review_error_detail','review_error_stage')}
        telemetry_count=db.execute('SELECT count(*) FROM telemetry').fetchone()[0]
    with connect(run/'results.db') as db, (out/'decisions.csv').open('w',newline='',encoding='utf-8') as f:
        assert db.execute('PRAGMA quick_check').fetchone()[0]=='ok'
        writer=csv.DictWriter(f,fieldnames=['record','event_id','label','attack_labelled','l1_decision','final_decision','l1_tier','gemma_attempted','processing_error','receipt_to_final_s','source_timestamp'])
        writer.writeheader()
        for seq,payload in db.execute('SELECT seq,payload FROM results ORDER BY seq'):
            r=json.loads(payload);saved.add(seq);index_ids[seq]=r['event_id']
            a=r['first_stage'];b=r['final_analysis'];second=b.get('second_stage') or {}
            attack=r['expected_attack'];flag=r['decision']=='escalate'
            outcome=('tp' if attack else 'fp') if flag else ('fn' if attack else 'tn')
            counters['completed']+=1;counters[outcome]+=1
            families[r['label']][outcome]+=1
            families[r['label']]['records']+=1
            first_outcome=('tp' if attack else 'fp') if a['decision']=='escalate' else ('fn' if attack else 'tn')
            counters['l1_'+first_outcome]+=1
            c=a.get('benchmark',{}).get('calls',[])
            q=[x for x in c if x['brain']=='qwen'];g=[x for x in c if x['brain']=='gemma']
            counters['qwen_attempted']+=bool(q);counters['gemma_attempted']+=bool(g)
            counters['qwen_attack_attempts']+=bool(q) and attack
            counters['gemma_attack_attempts']+=bool(g) and attack
            if g:one_two[len(g)]+=1
            failure=a.get('backend')=='policy-fallback' or b.get('second_stage_status')=='failed-alert-retained' or r['state']=='failed'
            counters['failed_records']+=failure
            if failure:
                detail=errors.get(r['event_id'],dict(review_error='HTTPError',review_error_detail=a.get('rationale'),review_error_stage='l1'))
                failed_rows.append(dict(record=seq,event_id=r['event_id'],label=r['label'],final_decision=r['decision'],**detail))
                assert flag
            if attack and not flag:
                misses.append(dict(record=seq,event_id=r['event_id'],label=r['label'],source_timestamp=r['timestamp'],
                    l1_decision=a['decision'],l1_reason=a['rationale'],l2_reason=second.get('decision_reason'),
                    confidence=second.get('confidence'),challenge=second.get('challenge'),guardrail=second.get('guardrail')))
            if attack and g:
                special_model_attacks.append(dict(record=seq,label=r['label'],decision=r['decision']))
            actor='gemma' if second.get('backend')=='ollama' else 'model_failure_retained' if failure else a['tier']
            actors[actor][outcome]+=1
            counters['l2_unannotated_quieted']+=not attack and a['decision']=='escalate' and not flag
            counters['l2_attack_quieted']+=attack and a['decision']=='escalate' and not flag
            counters['l2_prefilter_suppressions']+=second.get('review_status')=='prefilter' and not flag
            counters['l1_learned_hits']+='L1 learned exact routine pattern' in a.get('rationale','')
            counters['l2_learned_hits']+='L2_LEARNED_EXACT_PATTERN' in json.dumps(second)
            ch=second.get('challenge') or {}
            if ch.get('skipped'):critic['retained_alert_skipped']+=1
            elif ch:
                critic['checks']+=1;critic['accepted']+=ch.get('accept') is True;critic['rejected']+=ch.get('accept') is False
            guard=second.get('guardrail') or {}
            if guard.get('veto'):veto[guard['veto']]+=1
            if second.get('proposed_decision')=='suppress' and flag:
                counters['proposed_suppressions_blocked']+=1
                counters['suppression_confidence_below_0_9']+=second.get('confidence',1)<.9
            source_times.append(datetime.fromisoformat(r['timestamp'].replace('Z','+00:00')))
            times['receipt_to_final_all'].append(r.get('receipt_to_final_s'))
            times['pipeline_elapsed_all'].append(r.get('processing_pipeline_s'))
            path='gemma_routed' if g else 'qwen_without_gemma' if q else 'rules_only'
            times['receipt_to_final_'+path].append(r.get('receipt_to_final_s'))
            done=datetime.fromisoformat((b.get('completed_at') or a['completed_at']).replace('Z','+00:00'))
            bucket=done.replace(minute=0,second=0,microsecond=0).isoformat()
            hourly[bucket]['finalized']+=1;hourly[bucket][path]+=1
            for j,call in enumerate(g):
                part='assessment' if j==0 else 'challenge'
                times['gemma_'+part+'_call_wall'].append(call['elapsed_s'])
                if call['status']=='replied':
                    u=call.get('usage') or {}
                    for key,value in u.items():
                        if isinstance(value,(int,float)):
                            usage[part+'.'+key].append(value/1e9 if key.endswith('_duration') else value)
            if g:times['gemma_sum_call_wall_per_record'].append(sum(x['elapsed_s'] for x in g))
            for call in c:
                calls[call['brain']+'_calls']+=1;calls[call['brain']+'_errors']+=call['status']!='replied'
                if call['brain']=='qwen':times['qwen_call_wall'].append(call['elapsed_s'])
            if seq in old:
                identity,old_attack,decision=old[seq]
                assert identity==r['event_id'] and old_attack==attack
                paired['records']+=1
                old_key=('tp' if attack else 'fp') if decision=='escalate' else ('fn' if attack else 'tn')
                paired['old_'+old_key]+=1;paired['new_'+outcome]+=1
                paired['prior_attack_misses_now_retained']+=attack and decision=='suppress' and flag
                paired_rows.append(dict(record=seq,event_id=r['event_id'],attack_labelled=attack,old_decision=decision,new_decision=r['decision']))
            writer.writerow(dict(record=seq,event_id=r['event_id'],label=r['label'],attack_labelled=attack,
                l1_decision=a['decision'],final_decision=r['decision'],l1_tier=a['tier'],gemma_attempted=bool(g),
                processing_error=failure,receipt_to_final_s=r.get('receipt_to_final_s'),source_timestamp=r['timestamp']))
    expected=progress['counts']
    for actual,key in [('completed','completed'),('tp','final_tp'),('fn','final_fn'),('tn','final_tn'),('fp','final_fp'),('failed_records','failed_records'),('qwen_attempted','qwen_records'),('gemma_attempted','gemma_records')]:
        assert counters[actual]==expected.get(key,0),(actual,counters[actual],expected.get(key))
    assert telemetry_count==len(saved)+progress['in_flight']
    assert len(saved)==sum(f['records'] for f in families.values())==sum(counters[k] for k in ('tp','fn','tn','fp'))
    assert len(old)==paired['records']
    attacks=counters['tp']+counters['fn'];unannotated=counters['tn']+counters['fp']
    wall=(datetime.fromisoformat(progress['updated_utc'])-datetime.fromisoformat(progress['started_utc'])).total_seconds()
    rates=dict(attack_retention_percent=100*counters['tp']/attacks,unannotated_quiet_percent=100*counters['tn']/unannotated,
        unannotated_retained_percent=100*counters['fp']/unannotated,label_agreement_percent=100*(counters['tp']+counters['tn'])/len(saved),
        l2_unannotated_warning_reduction_percent=100*counters['l2_unannotated_quieted']/counters['l1_fp'],
        overall_records_per_min=60*len(saved)/wall,completion_percent=100*len(saved)/cohort['records'])
    result=dict(records=len(saved),planned=cohort['records'],remaining=cohort['records']-len(saved),unfinished_admitted=progress['in_flight'],
        first_source_utc=min(source_times).isoformat(),last_source_utc=max(source_times).isoformat(),source_span_s=(max(source_times)-min(source_times)).total_seconds(),
        sequence_min=min(saved),sequence_max=max(saved),counts=dict(counters),rates=rates,families=dict(families),actors=dict(actors),
        started_utc=progress['started_utc'],finished_utc=progress['updated_utc'],wall_elapsed_s=wall,active_elapsed_s=progress['active_elapsed_s'],
        latency={k:stats(v) for k,v in times.items()},usage_mean={k:statistics.mean(v) for k,v in usage.items()},calls=dict(calls),
        gemma_calls_per_record=dict(one_two),critic=dict(critic),final_vetoes=dict(veto),misses=misses,failed_reviews=failed_rows,
        model_reviewed_attacks=special_model_attacks,paired_development_checkpoint=dict(paired),initial_published=base,
        source=dict(dataset=cohort,run=metadata,runtime_sha256=sha(run/'runtime.pyz'),results_sha256=sha(run/'results.db'),
            decisions_sha256=sha(run/'decisions.jsonl'),progress_sha256=sha(run/'progress.json'),
            initial_summary_sha256=sha(initial/'summary.json'),initial_archive_sha256=sha(initial/'checkpoint-data.zip'),
            intermediate_results_sha256=sha(intermediate/'results.db'),intermediate_runtime_sha256=sha(intermediate/'runtime.pyz')),
        caveats=['Stopped partial checkpoint with noncontiguous completed sequence numbers; unfinished rows excluded.',
            'Unannotated rows are not independently certified benign.',
            'Published baseline contains zero attack-labelled records; this checkpoint contains 17,305. The comparison table records each run\'s attack and unannotated counts.',
            'Paired intermediate checkpoint was used in development; it is not held-out validation.',
            'Nearly all attack records are repeated scans handled by rules; model-only attack sample has five records.',
            'A checking call uses Gemma again; it is not an independent model or human adjudicator.'])
    result['comparison']=dict(
        unannotated_quiet_difference_pp=rates['unannotated_quiet_percent']-base['final']['unannotated_quieted_percent'],
        unannotated_warning_rate_relative_difference_percent=100*(1-rates['unannotated_retained_percent']/(100-base['final']['unannotated_quieted_percent'])),
        observed_mix_throughput_difference_percent=100*(rates['overall_records_per_min']/base['observed_records_per_minute']-1),
        gemma_attempt_count_ratio=counters['gemma_attempted']/base['layers']['gemma_reviews'])
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    if Path(__file__).resolve()!=(out/'analyze.py').resolve():
        (out/'analyze.py').write_bytes(Path(__file__).read_bytes())
    for name,rows in [('failed-reviews',failed_rows),('missed-attacks',misses),('paired-development',paired_rows),('hourly-completions',[dict(utc_hour=k,**v) for k,v in sorted(hourly.items())])]:
        with (out/(name+'.csv')).open('w',newline='',encoding='utf-8') as f:
            fields=list(dict.fromkeys(k for r in rows for k in r))
            writer=csv.DictWriter(f,fieldnames=fields);writer.writeheader();writer.writerows([{k:json.dumps(v) if isinstance(v,(dict,list)) else v for k,v in r.items()} for r in rows])
    archive=out/'checkpoint-data.next.zip'
    with zipfile.ZipFile(archive,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=6) as z:
        for name in ('decisions.jsonl','runtime.pyz','run_eval.py','supervise.ps1','cohort.json','frozen-files.json','source-provenance.json','run.json','progress.json','hardware.json','raw.jsonl','events.jsonl','scorer-index.jsonl'):
            z.write(run/name,name)
        for filename in ('raw.jsonl','events.jsonl','scorer-index.jsonl'):
            with (run/filename).open('rb') as src,z.open('completed-'+filename,'w') as dst:
                for seq,line in enumerate(src,1):
                    if seq in saved:
                        if filename=='scorer-index.jsonl':assert json.loads(line)['event_id']==index_ids[seq]
                        dst.write(line)
        for name in ('decisions.csv','summary.json','failed-reviews.csv','missed-attacks.csv','paired-development.csv','hourly-completions.csv'):z.write(out/name,name)
        for name in ('README.md','runtime-errors.txt','analyze.py'):
            if (out/name).exists():z.write(out/name,name)
    with zipfile.ZipFile(archive) as z:
        assert z.testzip() is None
        for name,expected in read(run/'frozen-files.json').items():
            with z.open(name) as f:assert hashlib.file_digest(f,'sha256').hexdigest()==expected,name
        for filename in ('decisions.jsonl','completed-raw.jsonl','completed-events.jsonl','completed-scorer-index.jsonl'):
            with z.open(filename) as f:assert sum(1 for _ in f)==len(saved),filename
    archive.replace(out/'checkpoint-data.zip')
    print(json.dumps({k:result[k] for k in ('records','rates','comparison','counts','families','actors','critic','final_vetoes','paired_development_checkpoint')},indent=2))
    print('Archive bytes:',(out/'checkpoint-data.zip').stat().st_size)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('run','out','initial','intermediate'):parser.add_argument('--'+name,required=True)
    main(parser.parse_args())
