"""L2-only evidence assembly and deterministic pre-assessment."""
from datetime import datetime, timezone
import hashlib
import json
import socket

LOCAL = {'windows', 'sysmon', 'defender', 'linux_auth', 'local_process'}
FIELDS = ('hostname','event_type','timestamp','username','user_id','src_ip','dst_ip',
          'process_name','process_id','file_path','action')


def dossier(row, related=(), now=None):
    now = now or datetime.now(timezone.utc)
    current = row['event']; rows = [row, *related]
    facts, seen = [], set()
    for item in rows:
        event = item['event']; identity = event['event_id']
        if identity in seen or len(facts) >= 64: continue
        if item['connector'] not in LOCAL or event.get('source_type') != item['connector']: continue
        if event['hostname'] != current['hostname'] or event.get('tags'): continue
        age = (now-datetime.fromisoformat(event['timestamp'])).total_seconds()
        if not 0 <= age <= 300: continue
        seen.add(identity)
        fact = {k:event.get(k,'') for k in FIELDS}
        if any(isinstance(v,str) and len(v)>2048 for v in fact.values()): continue
        fact.update(id='F'+str(len(facts)+1), event_id=identity, origin=item['connector'])
        if len(json.dumps(facts+[fact]))>128*1024: continue
        facts.append(fact)
    packet = {'host':current['hostname'], 'current_event':current['event_id'], 'facts':facts,
              'untrusted_observation':current.get('message','')[:4000]}
    packet['digest'] = hashlib.sha256(json.dumps(packet,sort_keys=True).encode()).hexdigest()
    return packet


def assess(packet, proposal):
    facts = packet['facts']; current = next((f for f in facts if f['event_id']==packet['current_event']), None)
    result = {'route':'investigate','rule':None,'required_facts':[], 'reason':'Insufficient independent support for containment'}
    if not current or packet['host'].casefold()!=socket.gethostname().casefold() or not proposal:
        return result
    target = proposal['target']
    def account(fact):
        sid=fact.get('user_id')
        return sid if sid and sid!='S-1-0-0' else fact.get('username') if fact.get('username') not in {'','-','unknown'} else None
    failures = [f for f in facts if f['event_type']=='auth_failure' and account(f) and
                account(f)==account(current) and f['src_ip']==target and
                f['origin'] in {'windows','linux_auth'}]
    if current['event_type']=='auth_failure' and len(failures)>=5:
        return {'route':'reason','rule':'repeated_login_failures',
                'required_facts':[f['id'] for f in failures[:5]], 'reason':'Five independently matched local authentication failures'}
    if current['event_type']=='network_connection' and current['origin']=='sysmon' and current['dst_ip']==target:
        from .ingestion.evidence import artifact
        detections = [f for f in facts if f['origin']=='defender' and f['event_type']=='malware_detection' and
                      artifact(f['file_path']) and artifact(f['file_path'])==artifact(current['process_name'])]
        if detections:
            return {'route':'verified_critical','rule':'malware_process_network',
                    'required_facts':[current['id'],detections[0]['id']],
                    'reason':'Native Defender detection and exact-path Sysmon network activity independently match'}
    return result
