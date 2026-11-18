"""Independent L2 routing: protect risk, use exact human feedback, or ask Gemma."""
import re
from .guardrails import final_guardrail_check
from .tool_policy import verified_finding, source_observations


def prefilter(event, memory=None, first_review=None):
    hit=final_guardrail_check(event,'suppress')
    if hit:
        return {'route':'escalate','reason':hit.reason,'rule':hit.code}
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
        signature=source_observations(event,'wazuh').get('suricata',{}).get('signature','')
        protocol=signature.startswith('SURICATA ') or bool(re.search(r'\bSURICATA (?:TLS|HTTP|TCP|SSH|DNS|SMTP) ',event.message))
        authentication=event.event_type in {'auth_success','auth_failure'} or 'pam_unix(' in event.message
        if protocol or authentication:
            return {'route':'escalate','reason':'This isolated protocol/login observation lacks independent flow or login context needed to justify quieting it; retain the warning without repeating the same evidence through Gemma.',
                    'rule':'L2_CONTEXT_REQUIRED'}
    return {'route':'model','reason':'No independent rule settles this alert; obtain an independent L2 assessment.','rule':None}
