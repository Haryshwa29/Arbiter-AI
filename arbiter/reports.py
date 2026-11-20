"""Local report templates; formatting never grants suppression authority."""
import hashlib
import json

TEMPLATES = {
    'authentication-v1': 'Account and session activity',
    'web-v1': 'Web activity',
    'network-v1': 'Network observation',
    'software-v1': 'Software and update activity',
    'process-v1': 'Process activity',
    'security-event-v1': 'Security observation',
}
CHECKS = {
    'authentication-v1': ['Check the account, peer and session time against authorized activity.',
        'Review surrounding account/session events; absence of failed logins does not establish authorization.'],
    'web-v1': ['Review the original request, response and related requests.',
        'A redirect or server error alone does not establish an ordinary cause.'],
    'network-v1': ['Check both endpoints, traffic direction and the recorded protocol warning.',
        'Compare related flow evidence; encryption alone does not explain an anomaly.'],
    'software-v1': ['Verify the package or update source and whether the change was authorized.',
        'Check completion separately from an update-start notification.'],
    'process-v1': ['Check the recorded executable, parent process, hash and authorization.',
        'A familiar process name alone does not establish that the binary is trusted.'],
    'security-event-v1': ['Review the original source record and related evidence.',
        'Verify the recorded explanation before taking a device action.'],
}


def template_for(event):
    kind = str(getattr(event, 'event_type', '')).lower()
    message = str(getattr(event, 'message', '')).lower()
    source = str(getattr(event, 'source', getattr(event, 'source_type', '')))
    if any(x in kind for x in ('auth', 'login', 'logon', 'session')):
        return 'authentication-v1'
    if any(x in kind for x in ('web', 'http')) or 'web server' in message:
        return 'web-v1'
    if source in {'suricata', 'zeek'} or any(x in kind for x in ('network', 'dns')) or 'suricata' in message:
        return 'network-v1'
    if any(x in kind for x in ('package', 'update', 'software')) or 'freshclam' in message:
        return 'software-v1'
    if 'process' in kind:
        return 'process-v1'
    return 'security-event-v1'


def snapshot(row):
    """Copy only report inputs; subsequent feedback produces another revision."""
    event, analysis = row['event'], row.get('analysis') or {}
    second = analysis.get('second_stage') or {}
    first = analysis.get('first_stage') or analysis
    learned = second.get('learned_pattern') or first.get('learned_pattern')
    template = (learned or {}).get('report_template') or second.get('report_template')
    if template not in TEMPLATES:
        from types import SimpleNamespace
        template = template_for(SimpleNamespace(**event))
    receipt=second.get('decision_receipt') or first.get('decision_receipt')
    receipt_reference=(dict(version=receipt['version'],format=receipt['format'],
        packet_digest=receipt.get('packet_digest') or receipt['evidence_packet']['digest']) if receipt else None)
    event_values={key:event.get(key) for key in ('event_id','hostname','source_type','event_type','timestamp','message','username','src_ip','dst_ip')}
    message=str(event_values.get('message') or '')
    if len(message)>4000:event_values['message']=message[:4000]+' … [Shortened; see original payload]'
    return dict(event_id=row['event_id'], template=template,
        event=event_values,
        decision=analysis.get('decision'), reason=analysis.get('rationale') or row.get('error') or 'Analysis is pending.',
        evidence=analysis.get('evidence',''), confidence=second.get('confidence',first.get('model_confidence')),
        reviewer=('L2 pre-filter' if learned and second else 'L1 pre-filter' if learned else
            second.get('model') or first.get('model') or first.get('tier') or 'pending'),
        review_status=analysis.get('second_stage_status',''), learned_pattern=learned,
        gaps=(f"Second review unavailable ({analysis['second_stage_error'].get('review_error','unknown error')}); the alert remains visible for human review."
            if analysis.get('second_stage_error') else second.get('gaps') or 'Authorization and the underlying cause must be checked against the original evidence.'),
        guardrail=second.get('guardrail') or analysis.get('pipeline_final_guardrail') or first.get('final_guardrail') or {},
        evidence_receipt=receipt_reference,
        completed_at=analysis.get('completed_at'), state=row['state'])


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def render(value):
    """Use saved observations and reasons, with no inference or device actions."""
    event=value['event']; learned=value.get('learned_pattern')
    origin={label:str(event[key]) for key,label in (
        ('hostname','Affected device'),('source_type','Source'),('timestamp','Occurred'),
        ('username','Account'),('src_ip','Source address'),('dst_ip','Destination address')) if event.get(key)}
    if learned:
        origin['Learned pattern origin']=str(learned['origin_event'])
        if learned.get('model'):origin['Original reviewing model']=str(learned['model'])
        origin['Current review']='Pre-filter match; the model did not review this record again'
    brief=dict(observed=event.get('message') or 'No event description was recorded.',
        why=value['reason'],origin=origin,uncertainty=value['gaps'])
    return dict(version=1,template_id=value['template'],title=TEMPLATES[value['template']],
        event_id=value['event_id'],decision=value['decision'],reviewer=value['reviewer'],
        brief=brief,evidence=value['evidence'],confidence=value['confidence'],
        guardrail=value['guardrail'],learned_pattern=learned,checks=CHECKS[value['template']],
        checks_source='template',action_authority=False)
