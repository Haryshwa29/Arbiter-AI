"""L2 output grounding and action guardrails, independent of L1 verdict parsing."""
import math

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
