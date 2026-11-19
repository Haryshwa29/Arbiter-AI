"""Short-lived exact routine-pattern memory; model decisions are not allowlists."""
import hashlib
import json


def pattern_key(event, connector, memory, model, simulation=False):
    if (simulation or connector in {'api','file','replay','demo'}
            or event.metadata.get('normalized_by') in {None,'legacy'}
            # Native process learning keeps its existing five-assessment gate.
            or (event.source_type=='sysmon' and event.event_type=='process_exec')
            or event.metadata.get('correlation')):
        return None
    data=event.to_dict()
    for field in ('event_id','timestamp','received_at'):
        data.pop(field,None)
    # Only envelope identifiers vary. Do not template commands, URLs or log text.
    raw=dict(data.get('raw_event') or {}) if isinstance(data.get('raw_event'),dict) else data.get('raw_event')
    if isinstance(raw,dict):
        for field in ('id','timestamp','@timestamp'):raw.pop(field,None)
        if isinstance(raw.get('rule'),dict):
            raw['rule']=dict(raw['rule']);raw['rule'].pop('firedtimes',None)
    data['raw_event']=raw
    facts=[vars(fact) for fact in memory.facts_for(event.hostname,event.source_type)]
    scope={'version':1,'model':model,'connector':connector,'event':data,
        'criticality':memory.asset_criticality(event.hostname),'facts':facts}
    return hashlib.sha256(json.dumps(scope,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()
