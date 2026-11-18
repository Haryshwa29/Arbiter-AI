"""Bounded local L2 observations and reference knowledge; no network requests."""
from datetime import datetime
from functools import lru_cache
import hashlib
from importlib.resources import files
import json
import re

from .ingestion.schema import SecurityEvent
from .tool_policy import source_observations, verified_finding

# Background reading, not assertions that a technique occurred.
TECHNIQUES = {
    'T1110':('Brute Force','Check repeated failures, the exact account, peer and time window; one failed login does not establish password guessing.'),
    'T1078':('Valid Accounts','A successful login can be ordinary or abusive; look for account, peer and surrounding activity rather than treating success as permission.'),
    'T1046':('Network Service Discovery','Service or port enumeration needs the observed targets and sequence; a client reply port alone does not demonstrate scanning.'),
    'T1190':('Exploit Public-Facing Application','Check the source detector, request, affected application/version and follow-on behavior; an error response does not rule out an exploit attempt.'),
    'T1071.004':('Application Layer Protocol: DNS','Inspect the actual DNS question and surrounding traffic; DNS use or a domain suffix alone does not establish tunneling.'),
    'T1548.003':('Sudo and Sudo Caching','A privileged session needs the recorded actor, command and authorization context; its closure does not explain the earlier elevation.'),
    'T1505.003':('Web Shell','Look for a server-side artifact and related execution; an upload or filename alone does not prove an installed web shell.'),
}
RELATED_SOURCES = {'windows','linux_auth','wazuh'}


def timestamp(value):
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        return parsed if parsed.tzinfo else None
    except (AttributeError,ValueError):
        return None


@lru_cache(maxsize=1)
def catalog():
    raw=files('arbiter').joinpath('data/kev.json').read_bytes()
    data=json.loads(raw)
    if data.get('schema')!=1 or len(data.get('entries',{}))!=data.get('count'):
        raise ValueError('Invalid local CVE reference catalog')
    return data,hashlib.sha256(raw).hexdigest()


def account(event):
    value=event.fields.get('user_id')
    if value and value not in {'-','unknown','S-1-0-0'}:
        return ('id',value)
    value=event.fields.get('username') or event.fields.get('user')
    return ('name',value) if isinstance(value,str) and value not in {'','-','unknown'} else None


def protocol_anomaly(event):
    if not verified_finding(event,'wazuh'): return False
    signature=source_observations(event,'wazuh').get('suricata',{}).get('signature','')
    return signature.startswith('SURICATA ') or bool(re.search(
        r'\bSURICATA (?:TLS|HTTP|TCP|SSH|DNS|SMTP) ',event.message))


def conversation_for(event):
    security=source_observations(event,event.source).get('security',{})
    if not isinstance(security,dict): return False
    network=security.get('network',{})
    if not isinstance(network,dict): return False
    flow=network.get('flow',{})
    http,tls=network.get('http',{}),network.get('tls',{})
    if not all(isinstance(v,dict) for v in (flow,http,tls)): return False
    endpoints=all(event.fields.get(k) not in (None,'') for k in ('src_ip','dst_ip','src_port','dst_port'))
    packets=all(type(flow.get(k)) is int and flow[k]>0 for k in ('pkts_toserver','pkts_toclient'))
    application=(network.get('app_proto')=='tls' and bool(tls.get('sni')) and bool(tls.get('version'))
        or network.get('app_proto')=='http' and bool(http.get('http_method')) and bool(http.get('hostname'))
        and type(http.get('status')) is int and 100<=http['status']<=599)
    return bool(endpoints and packets and application and network.get('flow_id') is not None)


def context_for(event, related=()):
    observed=source_observations(event,event.source)
    security=observed.get('security',{})
    security=security if isinstance(security,dict) else {}
    current_time=timestamp(event.timestamp)
    history=[]
    seen={event.id}
    peer=event.fields.get('src_ip')
    native=event.fields.get('_telemetry',{}).get('source')==event.source and event.source in RELATED_SOURCES
    if native and current_time and peer and account(event) and event.event_type in {'auth_success','auth_failure'}:
        for row in list(related or ())[:64]:
            if not isinstance(row,dict) or row.get('connector') not in RELATED_SOURCES:
                continue
            try:
                source=SecurityEvent(**row['event'])
                other=source.to_event()
            except (KeyError,TypeError,ValueError):
                continue
            when=timestamp(other.timestamp)
            if (other.id in seen or len(other.id)>128 or source.source_type!=row['connector']
                    or source.metadata.get('normalized_by')!=source.source_type
                    or {'demo','replay'}.intersection(source.tags)
                    or other.host.casefold()!=event.host.casefold()
                    or other.event_type not in {'auth_success','auth_failure'}
                    or other.fields.get('src_ip')!=peer or account(other)!=account(event)
                    or not when or not 0<=(current_time-when).total_seconds()<=300):
                continue
            seen.add(other.id)
            history.append({'event_id':other.id,'source':other.source,'timestamp':other.timestamp,
                'event_type':other.event_type})
            if len(history)==8: break
    failures=sum(r['event_type']=='auth_failure' for r in history)
    if native and event.event_type=='auth_failure' and peer and account(event):
        failures+=1
    conversation=conversation_for(event)
    identities=set(security.get('reported_techniques',[]))
    if event.event_type in {'auth_success','auth_failure'}: identities.update(('T1110','T1078'))
    if observed.get('web_alert_review'): identities.add('T1190')
    if observed.get('privileged_session_review'): identities.add('T1548.003')
    if observed.get('dns_query') or 'dns query' in event.message.casefold(): identities.add('T1071.004')
    technique_cards=[]
    for identity in sorted(identities):
        if identity in TECHNIQUES:
            title,guidance=TECHNIQUES[identity]
            technique_cards.append({'id':identity,'name':title,'guidance':guidance,
                'source':'https://attack.mitre.org/techniques/'+identity.replace('.','/')+'/'})
        if len(technique_cards)==3: break
    cve_cards=[]
    catalog_info={}
    references=security.get('reported_cves',[])[:3]
    if references:
        data,checksum=catalog()
        catalog_info={'version':data['catalog_version'],'released':data['released'],
            'source_url':data['source_url'],'sha256':checksum}
        for identity in references:
            known=data['entries'].get(identity)
            asof=bool(known and current_time and known['date_added']<=current_time.date().isoformat())
            cve_cards.append({'id':identity,'known_exploited_as_of_event':asof,
                'scope':'Reference match is not proof of affected installation, patch state or exploitation.',
                **(known if asof else {})})
    context={'version':'l2-context-v1','event_id':event.id,
        'observed':security,'related_auth_events':history,
        'auth_failures_same_peer_5m':failures,'has_conversation_context':conversation,
        'has_related_auth_context':bool(history),'reference_catalog':catalog_info,
        'attack_reference':technique_cards,'cve_reference':cve_cards,
        'knowledge_limit':'Reference knowledge and repeated activity do not certify this event as malicious or harmless; absent CVE matches do not imply safety.'}
    if len(json.dumps(context))>6000:
        raise ValueError('L2 security context exceeds its bounded input budget')
    return context
