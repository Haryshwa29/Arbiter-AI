"""Summarize a completed public checkpoint and gate a separate candidate retest."""
from pathlib import Path
from collections import Counter,defaultdict
import argparse
import json
import sqlite3
import sys
from datetime import datetime


def report(baseline,out,candidate=None):
    progress=json.loads((baseline/'progress.json').read_text())
    if progress['status']!='completed' or progress['counts']['completed']!=progress['target']:
        raise ValueError('Baseline must finish before final analysis or the next benchmark')
    if candidate:
        sys.path.insert(0,str(candidate))
    from arbiter.ingestion.schema import SecurityEvent
    from arbiter.guardrails import final_guardrail_check
    try:
        from public_benchmark_input import native_from_raw
    except ModuleNotFoundError:
        from tools.public_benchmark_input import native_from_raw
    counts=Counter();families=defaultdict(Counter);failures=[];uncovered=[];new_veto_on_unannotated=0
    uri=(baseline/'results.db').resolve().as_uri()+'?mode=ro'
    with sqlite3.connect(uri,uri=True) as db:
        total,low,high=db.execute('SELECT COUNT(*),MIN(seq),MAX(seq) FROM results').fetchone()
        if (total,low,high)!=(progress['target'],1,progress['target']):
            raise ValueError('Incomplete or non-contiguous final results')
        for seq,payload in db.execute('SELECT seq,payload FROM results ORDER BY seq'):
            row=json.loads(payload);first=row['first_stage'];second=row['final_analysis'].get('second_stage') or {}
            flag=row['decision']=='escalate';attack=row['expected_attack']
            outcome=('tp' if attack else 'fp') if flag else ('fn' if attack else 'tn')
            counts[outcome]+=1;families[row['label']][outcome]+=1
            qwen=first.get('tier')=='llm' and first.get('backend')=='ollama'
            gemma=second.get('backend')=='ollama' or any(c['brain']=='gemma' for c in first.get('benchmark',{}).get('calls',[]))
            counts['qwen_reviewed_records']+=qwen;counts['gemma_reviewed_records']+=gemma
            if qwen:
                l1_flag=first['decision']=='escalate'
                counts['qwen_stage_'+(('tp' if attack else 'fp') if l1_flag else ('fn' if attack else 'tn'))]+=1
            if second.get('backend')=='ollama':counts['gemma_stage_'+outcome]+=1
            counts['interrupted_timing_records']+=row['timing_interrupted']
            counts['failed_records']+=first.get('backend')=='policy-fallback' or row['final_analysis'].get('second_stage_status')=='failed-alert-retained' or row['state']=='failed'
            if candidate and row['decision']=='suppress':
                # Re-normalize original public evidence; old derived markers are not new adapter output.
                native=native_from_raw(row['event']['raw_event'])
                hit=final_guardrail_check(native.to_event(),'suppress')
                if not attack and hit:new_veto_on_unannotated+=1
            else:hit=None
            if attack and not flag:
                stage='Gemma' if first['decision']=='escalate' else 'Qwen' if qwen else 'L1 rules'
                failure={'seq':seq,'label':row['label'],'stage':stage,'l1_reason':first.get('rationale'),
                    'l2_reason':second.get('decision_reason'),'candidate_veto':hit.code if hit else None}
                failures.append(failure)
                if candidate and not hit:uncovered.append(seq)
    out.mkdir(parents=True,exist_ok=True)
    attacks=counts['tp']+counts['fn'];unannotated=counts['tn']+counts['fp']
    result={'records':total,'counts':dict(counts),'families':dict(families),
        'operational_findings':[json.loads(p.read_text(encoding='utf-8-sig')) for p in sorted((baseline/'interruptions').glob('*/operational-findings.json'))],
        'started_utc':progress['started_utc'],'finished_utc':progress['updated_utc'],
        'active_elapsed_s':progress.get('active_elapsed_s'),
        'wall_elapsed_s':(datetime.fromisoformat(progress['updated_utc'])-datetime.fromisoformat(progress['started_utc'])).total_seconds(),
        'label_agreement_percent':100*(counts['tp']+counts['tn'])/total,
        'attack_retention_percent':100*counts['tp']/attacks if attacks else None,
        'unannotated_quiet_percent':100*counts['tn']/unannotated if unannotated else None,
        'misses':failures,'candidate_uncovered_misses':uncovered,
        'candidate_vetoes_on_previously_quiet_unannotated':new_veto_on_unannotated,
        'candidate_retest':'Deterministic gates applied to seen frozen proposals; not a new model accuracy measurement',
        'model_subset_limit':'Qwen-stage and Gemma-stage counters cover different routed subsets after their gates; failed model replies count separately and are not correct model classifications',
        'timing':'Initial attempt shared GPU; resumption, downtime and interrupted rows prevent an isolated full-run speed claim',
        'label_caveat':'Unannotated is not certified benign; the cohort is dominated by directory scans'}
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    text=(f'# Completed AIT-ADS checkpoint: plain-language findings\n\n'
        'Source: [AIT Alert Data Set v1](https://zenodo.org/records/8263181), by Max Landauer, Florian Skopik and Markus Wurzenberger. '
        'This checkpoint contains public Wazuh/Suricata alerts; unsupported AMiner records are excluded.\n\n'
        f'{total:,} public records were classified. {counts["tp"]:,} attack-labelled records remained flagged; '
        f'{counts["fn"]:,} were wrongly quieted. {counts["tn"]:,} unannotated records were quieted and '
        f'{counts["fp"]:,} retained. Missing attack labels do not prove harmlessness.\n\n'
        f'Active processing time: {result["active_elapsed_s"]/3600:.2f} hours; wall time including interruptions: {result["wall_elapsed_s"]/3600:.2f} hours. '
        'The initial segment shared GPU use; this is not an isolated latency claim.\n\n'
        f'Agreement with publisher labels: {result["label_agreement_percent"]:.2f}%. '
        f'Attack retention: {result["attack_retention_percent"]:.2f}%. Most attacks are repeated scans; these are not broad real-world accuracy claims.\n\n'
        'The models sometimes treated blocked or unsuccessful attempts as harmless. Native web alerts using an alternate source group were not recognized by the web guard. '
        'Incomplete HTTP requests could be dismissed as harmless parsing errors. Aggregate model history was sometimes treated as confirmed benign history. '
        'See summary.json for every missed record and its responsible stage.\n\n'
        'Operational failures are separate from classification mistakes. A rejected L2 reply was retained as an alert; another incident was an Ollama CUDA runtime failure returning HTTP 500. '
        'The underlying CUDA cause is unproven. Failed outcomes and recovery interruptions remain recorded rather than being retried until successful.\n\n'
        'The candidate strengthens those evidence checks, identifies previous decisions as unverified, fixes a redundant counter in exact-pattern keys and retains useful validation error details. '
        f'Its deterministic retest still leaves {len(uncovered)} missed records uncovered and would also retain {new_veto_on_unannotated} previously quiet unannotated records. '
        'That is a safety/noise trade-off, not proof that every additional warning is an attack.\n\n'
        'Gemma generation and its separate challenge are the main observed bottleneck. The AWS SDK adds connector support, not LLM acceleration. '
        'The current full-run timing was affected by dashboard competition and interruptions. The next experiment measures a fresh 10-hour window, with queued records separated from final decisions.\n\n'
        'This report stays local pending owner review before publication.\n')
    (out/'README.md').write_text(text,encoding='utf-8')
    if candidate and uncovered:
        raise ValueError('Candidate does not cover all observed missed attacks; review required: '+str(uncovered))
    return result


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--baseline',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True);ap.add_argument('--candidate',type=Path)
    args=ap.parse_args();report(args.baseline,args.out,args.candidate)
