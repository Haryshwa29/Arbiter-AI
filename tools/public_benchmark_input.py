"""Stream pinned publisher records and labels; never put labels into an event."""
import copy
import csv
import hashlib
import io
import ipaddress
import json
import zipfile

SCENARIOS=('fox','harrison','russellmitchell','santos','shaw','wardbeck','wheeler','wilson')


def native_from_raw(raw):
    from arbiter.ingestion.normalization import normalize
    data=copy.deepcopy(raw);data['timestamp']=data.get('timestamp') or data['@timestamp']
    detail=data.get('data',{})
    for prefix in ('src','dst'):
        value=detail.get(prefix+'ip','')
        if isinstance(value,str) and value.count(':')==1:
            address,port=value.rsplit(':',1)
            if port.isdigit() and 0<=int(port)<=65535:
                ipaddress.IPv4Address(address);detail[prefix+'ip']=address
                detail.setdefault(prefix+'port',int(port))
    return normalize(data,'wazuh')


def records(directory,provenance,fox_start='2022-01-18T12:37:00+00:00'):
    from arbiter.ingestion.schema import timestamp
    from datetime import datetime
    with zipfile.ZipFile(directory/'ait_ads.zip') as raws,zipfile.ZipFile(directory/'alerts_csv.zip') as labelzip:
        for scenario in SCENARIOS:
            with labelzip.open(f'alerts_csv/{scenario}_alerts.txt') as labelstream:
                labels=iter(csv.DictReader(io.TextIOWrapper(labelstream,encoding='utf-8')))
                count=0;previous=None
                with raws.open(f'{scenario}_wazuh.json') as source:
                    for line_number,line in enumerate(source,1):
                        if not line.strip() or b'The average number' in line:continue
                        raw=json.loads(line);label=next(labels);count+=1
                        description=raw['rule']['description']
                        name=description if description.startswith('Suricata: ') else 'Wazuh: '+description
                        when=timestamp(raw['@timestamp'])
                        if (label['name']!=name or label['ip']!=raw['agent']['ip']
                                or int(label['time'])!=int(datetime.fromisoformat(when).timestamp())):
                            raise ValueError(f'Publisher alignment failure: {scenario}:{line_number}')
                        if previous and when<previous:raise ValueError('Non-chronological source: '+scenario)
                        previous=when
                        if scenario=='fox' and when<fox_start:continue
                        raw_hash=hashlib.sha256(json.dumps(raw,sort_keys=True).encode()).hexdigest()
                        item={'scenario':scenario,'sample_id':f'{scenario}:{line_number}','raw_line':line_number,
                            'label_row':count+1,'label':label['event_label'],'expected_attack':label['event_label']!='-',
                            'timestamp':when,'raw_sha256':raw_hash}
                        yield raw,item
                extra=list(labels);expected=provenance['alignment'][scenario]
                if (count!=expected['matched_supported_alerts'] or len(extra)!=expected['excluded_aminer']
                        or any(not row['name'].startswith('AMiner: ') for row in extra)):
                    raise ValueError('Scenario supported/AMiner count mismatch: '+scenario)
