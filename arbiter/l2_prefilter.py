"""Independent L2 routing: protect risk, use exact human feedback, or ask Gemma."""
import re
from .guardrails import final_guardrail_check
from .tool_policy import verified_finding, source_observations
from .l2_context import context_for, protocol_anomaly


def prefilter(event, memory=None, first_review=None, security_context=None, routing_only=False):
    security_context=security_context if security_context is not None else context_for(event)
    hit=final_guardrail_check(event,'suppress',security_context=security_context)
    if hit:
        if routing_only:
            return {'route':'model','reason':'Pass the L1 escalation to Gemma for review; the final guardrail must still protect this recorded risk: '+hit.reason,
                    'rule':hit.code,'must_retain':True}
        return {'route':'escalate','reason':hit.reason,'rule':hit.code}
    finding=verified_finding(event,'wazuh')
    observed=source_observations(event,'wazuh')
    security=observed.get('security',{})
    vulnerability=security.get('vulnerability',{})
    # Wazuh 23502 reports a resolved finding, not an active vulnerability.
    if (routing_only and finding and finding.get('rule_id')=='23502'
            and event.severity<=3 and not finding.get('high_priority')
            and not event.fields.get('correlation') and not observed.get('suricata')
            and not security.get('reported_techniques')
            and len(security.get('reported_cves',[]))==1
            and vulnerability.get('status')=='Solved'
            and all(vulnerability.get(k) for k in ('cve','package','version'))
            and (memory is None or memory.history(event.signature).overruled==0)):
        return {'route':'suppress','rule':'L2_NATIVE_VULNERABILITY_RESOLVED',
            'reason':'Native Wazuh rule 23502 reports this named package/version CVE as Solved. Quiet this resolution notification only; it does not certify the whole asset safe or prove no earlier exploitation.'}
    context=event.fields.get('_context_signature','')
    # Model-generated benign history and broad host/type feedback are insufficient.
    if (memory is not None and event.source=='sysmon' and event.severity<=5
            and not event.fields.get('correlation')
            and re.fullmatch(re.escape(event.signature)+r':ctx:[0-9a-f]{64}',context)):
        if (memory.human_cleared_context(context,(first_review or {}).get('timestamp',''))
                and memory.history(event.signature).overruled==0):
            return {'route':'suppress','reason':'At least five human-overruled false alarms match this exact process hash, command, user, parent and environment context; no known risk veto.',
                    'rule':'L2_EXACT_HUMAN_FEEDBACK'}
    if verified_finding(event,'wazuh') and not event.fields.get('correlation'):
        protocol=protocol_anomaly(event)
        authentication=event.event_type in {'auth_success','auth_failure'} or 'pam_unix(' in event.message
        if ((protocol and not security_context['has_conversation_context'])
                or (authentication and not security_context['has_related_auth_context'])):
            if routing_only:
                return {'route':'model','reason':'Insufficient context for a supported routine suppression; escalate to Gemma for its own investigation.',
                        'rule':'L2_CONTEXT_REQUIRED'}
            return {'route':'escalate','reason':'This isolated protocol/login observation lacks independent flow or login context needed to justify quieting it; retain the warning without repeating the same evidence through Gemma.',
                    'rule':'L2_CONTEXT_REQUIRED'}
    return {'route':'model','reason':'No independent rule settles this alert; obtain an independent L2 assessment.','rule':None}
