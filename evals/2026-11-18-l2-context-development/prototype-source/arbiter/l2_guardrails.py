"""L2 output grounding and action guardrails, independent of L1 verdict parsing."""
import math
import re


def review_floor(event, security_context=None):
    """L2 evidence rules also protect decisions made without the second model."""
    from .guardrails import GuardrailHit
    from .tool_policy import verified_finding, source_observations
    if (security_context and security_context.get('event_id')==event.id
            and security_context.get('auth_failures_same_peer_5m',0)>=5):
        return GuardrailHit('L2_REPEATED_AUTH_FAILURES','l2_repeated_auth_failures',
            'at least five native authentication failures match this host, account and peer within five minutes; a later successful login does not resolve them')
    if not verified_finding(event,'wazuh'):
        return None
    from .ingestion.wazuh_evidence import network_tuple
    endpoints=network_tuple(event.message)
    if any(event.fields.get(k) not in (None,'',v) for k,v in endpoints.items()):
        return GuardrailHit('L2_ENDPOINT_CONFLICT','l2_endpoint_conflict',
            'structured and original-text network endpoints disagree; do not quiet conflicting evidence')
    if re.search(r'\bsudo:\s+pam_unix\(sudo:session\):\s+session (?:opened|closed) for user root\b',event.message,re.I):
        return GuardrailHit('L2_PRIVILEGED_SESSION','l2_privileged_session',
            'a recorded sudo session for root requires review, including its closure; a normal-looking closing log does not explain the privileged action')
    observed=source_observations(event,'wazuh')
    security=observed.get('security',{})
    vulnerability=security.get('vulnerability',{})
    if (security.get('reported_cves') and vulnerability.get('package') and vulnerability.get('version')
            and vulnerability.get('status','').casefold()=='active'):
        return GuardrailHit('L2_REPORTED_VULNERABILITY','l2_reported_vulnerability',
            'the native scanner reports an active CVE for a named package and version; retain for applicability and patch review, without claiming exploitation')
    category=observed.get('suricata',{}).get('category','').casefold()
    if category in {'web application attack','attempted administrator privilege gain',
                     'attempted user privilege gain','a network trojan was detected'}:
        return GuardrailHit('L2_SOURCE_ATTACK_CLASS','l2_source_attack_class',
            'the source detector explicitly classifies an attack behavior; keep it for investigation rather than treating a failed request as harmless')
    if observed.get('multiple_dns_questions') is True:
        return GuardrailHit('L2_MULTIPLE_DNS_QUESTIONS','l2_multiple_dns_questions',
            'multiple DNS questions require contextual review; do not quiet an incompletely represented query set')
    query=observed.get('dns_query','')
    if 'dns query' in event.message.casefold() and not query:
        return GuardrailHit('L2_DNS_CONTEXT_MISSING','l2_dns_context_missing',
            'the alert does not include the DNS question; absence of attack proof cannot justify quieting an unexamined query')
    if (isinstance(query,str) and len(query)>=120
            and any(len(part)>=48 for part in query.split('.'))
            and (re.search(r'\.(?:xlsx?|docx?|csv|pdf|zip|txt|db)(?:\.|-)',query,re.I)
                 or sum(len(part)>=48 and len(set(part))>=16 for part in query.split('.'))>=2)):
        return GuardrailHit('L2_DNS_PAYLOAD','l2_dns_payload',
            'the recorded DNS question contains long encoded-looking data or a long payload with a file-name marker; investigate possible data transfer')
    return None

TEXT = ('assessment','evidence','gaps','recommendation','alternatives','recovery','urgency')

def validate(data, packet, assessment, proposal):
    if not isinstance(data,dict) or data.get('action') not in {'block_ip','human_review'}:
        raise ValueError('invalid L2 action')
    confidence = data.get('confidence')
    if type(confidence) not in (int,float) or not math.isfinite(confidence) or not 0<=confidence<=1:
        raise ValueError('invalid L2 confidence')
    for key in TEXT:
        if not isinstance(data.get(key),str) or not data[key].strip() or len(data[key])>8000:
            raise ValueError('invalid L2 brief')
    hypotheses=data.get('hypotheses')
    facts = {f['id']:f for f in packet['facts']}
    if not isinstance(hypotheses,list) or not 2<=len(hypotheses)<=6:
        raise ValueError('L2 requires competing hypotheses')
    kinds=set()
    for hypothesis in hypotheses:
        if not isinstance(hypothesis,dict) or hypothesis.get('kind') not in {'malicious','benign'}:
            raise ValueError('invalid L2 hypothesis')
        kinds.add(hypothesis['kind'])
        if not isinstance(hypothesis.get('summary'),str) or not hypothesis['summary'].strip() or len(hypothesis['summary'])>2000:
            raise ValueError('invalid hypothesis explanation')
        for key in ('supports','against'):
            refs=hypothesis.get(key)
            if not isinstance(refs,list) or len(refs)>64 or any(not isinstance(ref,str) or ref not in facts for ref in refs):
                raise ValueError('invalid hypothesis evidence')
    if kinds!={'malicious','benign'}: raise ValueError('L2 must consider benign and malicious explanations')
    assertions = data.get('assertions')
    if not isinstance(assertions,list) or not 1<=len(assertions)<=64: raise ValueError('L2 requires evidence assertions')
    facts = {f['id']:f for f in packet['facts']}; cited = set()
    for assertion in assertions:
        if not isinstance(assertion,dict): raise ValueError('invalid assertion')
        fact = facts.get(assertion.get('fact_id')); field = assertion.get('field')
        if not fact or field not in fact or field in {'id'} or type(assertion.get('value')) is not type(fact[field]) or assertion['value']!=fact[field]:
            raise ValueError('unsupported L2 evidence assertion')
        cited.add(fact['id'])
    if data['action']=='block_ip':
        if not proposal or not assessment['rule'] or not set(assessment['required_facts'])<=cited:
            raise ValueError('L2 action lacks independently grounded evidence')
        if data.get('target')!=proposal['target']: raise ValueError('L2 changed proposed target')
    return data


def receipt(packet, assessment, accepted):
    return {'version':2,'packet_digest':packet['digest'],'rule':assessment['rule'],
            'evidence_ids':[f['event_id'] for f in packet['facts'] if f['id'] in assessment['required_facts']],
            'grounded':True,'critic_accepted':accepted}
