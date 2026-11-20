"""Virtual FIFO arrivals with frozen measured costs; never starts a model."""
import argparse
import csv
from datetime import datetime,timezone
import hashlib
import json
from pathlib import Path
import zipfile


def simulate(records):
    finish=None;previous=None;result=[];hours={}
    for record in records:
        stamp=datetime.fromisoformat(record['event']['timestamp'].replace('Z','+00:00'))
        if stamp.tzinfo is None:raise ValueError('arrival timestamp needs a timezone')
        arrival=stamp.timestamp();cost=record['elapsed_s']
        if previous is not None and arrival<previous:raise ValueError('records must be chronological')
        if not isinstance(cost,(float,int)) or isinstance(cost,bool) or not 0<=cost<float('inf'):
            raise ValueError('invalid measured cost')
        previous=arrival;start=max(arrival,finish) if finish is not None else arrival;finish=start+cost
        row={'record':record['record'],'sample_id':record['sample_id'],'arrival_utc':stamp.isoformat(),
            'virtual_start_utc':datetime.fromtimestamp(start,timezone.utc).isoformat(),
            'virtual_finish_utc':datetime.fromtimestamp(finish,timezone.utc).isoformat(),
            'measured_service_s':cost,'simulated_queue_wait_s':start-arrival,
            'simulated_end_to_end_s':finish-arrival}
        result.append(row)
        hour=stamp.astimezone(timezone.utc).replace(minute=0,second=0,microsecond=0).isoformat()
        group=hours.setdefault(hour,dict(records=0,qwen_reviews=0,gemma_reviews=0,service_s=0.,l1_s=0.,l2_s=0.))
        group['records']+=1;group['qwen_reviews']+=int(record['first_stage']['tier']=='llm')
        second=record.get('second_stage') or {}
        group['gemma_reviews']+=int(second.get('review_status') in {'accepted','challenged'})
        for target,field in [('service_s','elapsed_s'),('l1_s','l1_elapsed_s'),('l2_s','l2_elapsed_s')]:
            group[target]+=record[field]
    if not result:raise ValueError('empty checkpoint')
    return result,{'assumptions':['one FIFO worker','empty queue at first arrival',
        'original dataset arrival times','frozen per-record elapsed_s costs',
        'no collector/network delay','no batching, caching, priority or changed model costs',
        'simulation only; the original replay did not have this live queue'],
        'records':len(result),'first_arrival':result[0]['arrival_utc'],'last_arrival':result[-1]['arrival_utc'],
        'dataset_span_s':previous-datetime.fromisoformat(result[0]['arrival_utc']).timestamp(),
        'maximum_simulated_wait':max(result,key=lambda r:r['simulated_queue_wait_s']),
        'maximum_simulated_end_to_end':max(result,key=lambda r:r['simulated_end_to_end_s']),
        'hours':hours}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkpoint',type=Path,default=Path('evals/2026-11-18-26k-checkpoint/checkpoint-data.zip'))
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    if (args.out/'simulation.json').exists():raise SystemExit('Use a fresh output directory')
    with zipfile.ZipFile(args.checkpoint) as z:
        rows,summary=simulate(json.loads(line) for line in z.open('decisions.jsonl'))
    summary['checkpoint_sha256']=hashlib.sha256(args.checkpoint.read_bytes()).hexdigest()
    (args.out/'simulation.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8',newline='\n')
    with (args.out/'simulated-queue.csv').open('w',encoding='utf-8',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)
    names=['simulation.json','simulated-queue.csv']
    (args.out/'SHA256SUMS.txt').write_text(''.join(hashlib.sha256((args.out/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names),encoding='utf-8',newline='\n')
    print(json.dumps({key:summary[key] for key in ('records','dataset_span_s','maximum_simulated_wait')}))


if __name__=='__main__':main()
