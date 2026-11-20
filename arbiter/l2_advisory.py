"""Read-only second opinions on L1 alerts; historical evidence grants no authority."""
import hashlib
import json
import time

from .l2 import L2Brain, SYSTEM, CRITIC
from .l2_transport import L2Transport
from .l2_guardrails import validate
from .ingestion.schema import SecurityEvent, safe_json

ADVISORY_SYSTEM = SYSTEM + """
This is an advice-only alert review. The alert remains visible to a person.
The only permitted action is human_review and target must be null. Do not clear
or suppress the alert, grant execution authority, or propose a shell command.
Also return outlook: suspicious, routine_looking, or uncertain. That is an
advisory assessment, not a new alert decision. Missing context alone is not proof
of compromise. Consider the recorded evidence independently; the first model's
opinion is unverified context, not a fact. Historical replay timestamps stay
historical and cannot support current containment. Use one short sentence per
text field, exactly two hypotheses (one benign and one malicious), and 1-3 exact
assertions selected verbatim from evidence_packet.allowed_assertions. Use only
the provided field names and values, not fields inferred from log text. Do not
copy the whole message into an assertion. Explain conclusions concisely, not
hidden chain-of-thought."""

ADVISORY_CRITIC = CRITIC + """
This is read-only advice: no containment or alert dismissal is permitted.
If the recommendation is supported and no actual objection exists, return
accept:true and objections:[]. Do not put statements of agreement, summaries,
or praise in objections. Reject only for a concrete evidence, scope or policy
problem. Use at most two short objections when rejecting. Always cite known
fact IDs. Return only the three requested JSON fields."""


def packet_for(event, first_review, replay=False, final_review=False, security_context=None):
    if first_review.get('decision') != 'escalate':
        raise ValueError('second opinion requires an existing visible alert')
    fact = {'id':'F1', 'event_id':event.id, 'source':event.source,
        'hostname':event.host, 'event_type':event.event_type,
        'timestamp':event.timestamp, 'severity':event.severity,
        'message':event.message[:4000],
        'source_details':json.dumps(event.fields, sort_keys=True,allow_nan=False)[:6000]}
    for key in ('src_ip','dst_ip','src_port','dst_port','username','user_id','process_name','process_id','parent_process','file_path','file_hash','command_line'):
        value=event.fields.get(key)
        if isinstance(value,(str,int)) and not isinstance(value,bool) and len(str(value))<=2048:
            fact[key]=value
    finding=event.fields.get('_tool_finding',{})
    if isinstance(finding,dict):
        observed=finding.get('observations',{})
        embedded=observed.get('suricata',{}) if isinstance(observed,dict) else {}
        if isinstance(embedded,dict) and isinstance(embedded.get('signature'),str):
            fact['signature']=embedded['signature'][:512]
        if isinstance(finding.get('rule_id'),str):fact['rule_id']=finding['rule_id'][:128]
        if isinstance(observed,dict) and isinstance(observed.get('dns_query'),str):
            fact['dns_query']=observed['dns_query'][:2048]
    if final_review:
        from .ingestion.wazuh_evidence import network_tuple
        endpoints=network_tuple(event.message)
        if not any(key in fact and fact[key]!=value for key,value in endpoints.items()):
            for key,value in endpoints.items():
                if key not in fact: fact[key]=value
    packet = {'host':event.host, 'current_event':event.id, 'facts':[fact],
        'mode':'historical_replay_advice' if replay else 'alert_advice',
        'action_authority':False,
        'truncated':len(event.message)>4000 or len(json.dumps(event.fields,sort_keys=True))>6000,
        'first_review':{k:first_review[k] for k in ('decision','tier','rationale','evidence','backend','model') if k in first_review}}
    packet['allowed_assertions']=[{'fact_id':'F1','field':key,'value':value} for key,value in fact.items()
                                  if key not in {'id','message','source_details'}]
    if final_review:
        packet.pop('first_review')
        from .l2_context import context_for
        context=security_context if security_context is not None else context_for(event)
        packet['security_context']=context
        observed=context['observed']
        for name in ('reported_cves','reported_techniques'):
            if observed.get(name): fact[name]=','.join(observed[name])
        for name,value in observed.get('vulnerability',{}).items():
            fact['reported_'+name]=value
        network=observed.get('network',{})
        for name in ('flow_id','app_proto','direction'):
            if name in network: fact[name]=network[name]
        for section in ('flow','http','tls'):
            for name,value in network.get(section,{}).items():
                fact[section+'_'+name]=value
        if context['related_auth_events']:
            fact['auth_failures_same_peer_5m']=context['auth_failures_same_peer_5m']
            fact['related_auth_event_ids']=','.join(r['event_id'] for r in context['related_auth_events'])
        packet['allowed_assertions']=[{'fact_id':'F1','field':key,'value':value} for key,value in fact.items()
            if key not in {'id','message','source_details'}]
        packet['mode']='historical_final_review' if replay else 'final_alert_review'
        packet['review_policy']='Confirm or suppress a successful first-model escalation; no device action authority'
        preferred=('reported_cves','reported_package','reported_version','reported_techniques',
            'auth_failures_same_peer_5m','dns_query','signature','flow_pkts_toserver','flow_pkts_toclient',
            'http_status','tls_sni','rule_id','command_line','process_name','file_path','username',
            'src_ip','dst_ip','src_port','dst_port')
        selected=[a for key in preferred for a in packet['allowed_assertions'] if a['field']==key][:10]
        packet['allowed_assertions']=selected or [a for a in packet['allowed_assertions'] if a['field']=='event_type']
    packet['digest'] = hashlib.sha256(json.dumps(packet,sort_keys=True).encode()).hexdigest()
    return packet


class AdvisoryL2Brain(L2Brain):
    """Same independent transport and grounding checks, with no response rights."""
    advice_only = True
    model_escalations_only = True
    system = ADVISORY_SYSTEM
    critic_system = ADVISORY_CRITIC
    assessment_route = 'advisory_only'
    assessment_reason = 'Read-only investigation; the existing alert remains visible and no device action is authorized'
    assessment_format = None
    critic_format = None

    def __init__(self, model, review_seconds=180, ollama_url='http://127.0.0.1:11434'):
        super().__init__(model,review_seconds)
        # This read-only route emits explicit hypotheses and is challenged in
        # a second call. Native response reasoning retains its existing defaults.
        self.backend=L2Transport(model,think=False,num_ctx=8192,num_predict=1536,base_url=ollama_url)

    def fast_review(self, row, proposal):
        return None

    def authorize(self, brief, row, proposal):
        return False

    def review(self, row, proposal=None):
        event = SecurityEvent(**row['event']).to_event()
        replay = row.get('connector') in {'file','replay','demo'} or bool({'replay','demo'}.intersection(row['event'].get('tags',[])))
        return self.review_event(event,row['analysis'],replay=replay)

    def review_event(self, event, first_review, replay=False, security_context=None):
        started = time.monotonic()
        packet = packet_for(event,first_review,replay,final_review=getattr(self,'final_review',False) is True,
            security_context=security_context)
        assessment = {'route':self.assessment_route,'rule':None,'required_facts':[],
            'reason':self.assessment_reason}
        prompt = {'evidence_packet':packet,'independent_assessment':assessment,'supported_proposal':None}
        deadline = started+self.review_seconds
        data = self.assess(prompt,packet,assessment,deadline)
        if getattr(self,'final_review',False) is True and 'outlook' not in data:
            data['outlook']='routine_looking' if data.get('decision')=='suppress' else 'suspicious'
            data['outlook_derived_from_decision']=True
        if data['action']!='human_review' or data.get('target') is not None:
            raise ValueError('advice-only review cannot clear an alert or authorize a target')
        if data.get('outlook') not in {'suspicious','routine_looking','uncertain'}:
            raise ValueError('invalid advisory outlook')
        retain_only=getattr(self,'final_review',False) is True and data.get('decision')=='escalate'
        if retain_only:
            # A challenge cannot turn an escalation into suppression. Keep all
            # evidence validation; every proposed suppression still needs both calls.
            critic={'skipped':True,'reason':'Retain-only classification; cannot suppress or authorize device actions'}
            accepted=True;objections=[]
        else:
            critic = safe_json(self.backend.generate(json.dumps({**prompt,'recommendation':self.critic_recommendation(data)}),self.critic_system,deadline=deadline,format_schema=self.critic_format))
            if not isinstance(critic,dict) or type(critic.get('accept')) is not bool:
                raise ValueError('invalid advisory challenge')
            objections, citations = critic.get('objections'), critic.get('citations')
            known = {f['id'] for f in packet['facts']}
            if (not isinstance(objections,list) or len(objections)>16
                    or any(not isinstance(x,str) or not x.strip() or len(x)>2000 for x in objections)):
                raise ValueError('invalid advisory objections')
            if not isinstance(citations,list) or not citations or any(not isinstance(x,str) or x not in known for x in citations):
                raise ValueError('invalid advisory citations')
            accepted = critic['accept'] and not objections
        proposed = data['outlook']
        if not accepted:
            data['outlook']='uncertain'
            data['gaps']+=' | Challenge: '+'; '.join(objections or ['More investigation is required'])
        data.update(engine='l2-advisory-v1',model=self.backend.model,mode=packet['mode'],
            action='human_review',target=None,alert_decision='escalate',
            action_authority=False,proposed_outlook=proposed,challenge=critic,
            review_status='accepted' if accepted else 'challenged',
            guardrail={'version':'advisory-v1','packet_digest':packet['digest'],
                     'exact_assertions_checked':True,'critic_accepted':None if retain_only else accepted,'action_authority':False},
            review_ms=round((time.monotonic()-started)*1000,2))
        return data

    def assess(self,prompt,packet,assessment,deadline):
        return validate(safe_json(self.backend.generate(json.dumps(prompt),self.system,
            deadline=deadline,format_schema=self.assessment_format)),packet,assessment,None)

    def critic_recommendation(self,data):
        return data
