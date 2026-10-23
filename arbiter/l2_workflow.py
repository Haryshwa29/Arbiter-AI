"""Durable L2 deadlines and policy-controlled response, outside the triage brain."""
from datetime import datetime, timezone
import hashlib
import json
import queue
import threading
import time

WINDOWS = {'critical': 60, 'high': 300, 'medium': 1800, 'low': None}
RULES = {'repeated_login_failures', 'malware_process_network'}

class ResponsePolicy:
    def __init__(self, data=None):
        if data is None: data = {}
        if not isinstance(data, dict): raise ValueError("L2 policy must be an object")
        if not isinstance(data.get("windows", {}), dict): raise ValueError("windows must be an object")
        if set(data) - {'automatic', 'rules', 'windows'}: raise ValueError('unknown L2 policy field')
        self.automatic = data.get('automatic', False)
        if type(self.automatic) is not bool: raise ValueError('automatic must be boolean')
        self.rules = data.get('rules', [])
        if not isinstance(self.rules, list) or any(not isinstance(r, str) or r not in RULES for r in self.rules):
            raise ValueError('unapproved automatic response rule')
        self.windows = dict(WINDOWS)
        for level, seconds in data.get('windows', {}).items():
            if level not in WINDOWS or level == 'low' or type(seconds) is not int or not 0 <= seconds <= WINDOWS[level]:
                raise ValueError('invalid severity deadline')
            self.windows[level] = seconds
        if not self.windows['critical'] <= self.windows['high'] <= self.windows['medium']:
            raise ValueError('deadlines must increase with severity')

    def severity(self, row):
        independent=row.get('_l2_assessment',{})
        score=max(float(row['event']['severity']),9 if independent.get('route')=='verified_critical' else 7 if independent.get('rule')=='repeated_login_failures' else 0)
        return 'critical' if score >= 9 else 'high' if score >= 7 else 'medium' if score >= 4 else 'low'

    def permits(self, row, brief=None):
        # Model confidence is necessary but never sufficient. Only named deterministic
        # correlations are enrolled. A verified malware finding is stronger than CPU use.
        if brief is not None:
            return self.automatic and brief.get('guardrail',{}).get('rule') in self.rules
        return self.automatic and any(c.get('rule') in self.rules and
            (c['rule'] != 'malware_process_network' or c.get('verified_tool_source') is True)
            for c in row['analysis'].get('correlation', []))

class L2Workflow:
    def __init__(self, agent, brain, policy=None, clock=time.time, notify=None):
        self.agent, self.brain = agent, brain
        self.policy, self.clock = policy or ResponsePolicy(), clock
        self.notify = notify
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.jobs, self.results = queue.PriorityQueue(100), queue.Queue(100)
        self.inflight = set()
        self.threads = []
        b = agent.service.buffer
        with b.lock, b.conn:
            b.conn.execute('CREATE TABLE IF NOT EXISTS l2_seen (event_id TEXT PRIMARY KEY)')
            b.conn.execute('CREATE TABLE IF NOT EXISTS l2_cases (id TEXT PRIMARY KEY, body TEXT NOT NULL)')
            b.conn.execute('CREATE TABLE IF NOT EXISTS l2_notices (id INTEGER PRIMARY KEY, ts REAL, case_id TEXT, body TEXT)')
            b.conn.execute('CREATE TABLE IF NOT EXISTS l2_settings (key TEXT PRIMARY KEY, value TEXT)')
            b.conn.execute("INSERT OR IGNORE INTO l2_settings VALUES ('stopped','false')")
        # Crash during execution is never blindly retried.
        for case in self.cases():
            if case['state'] == 'executing':
                case['state'] = 'needs_review'; self.save(case, 'Interrupted action: inspect actions and native firewall before recovery')

    def cases(self):
        b = self.agent.service.buffer
        with b.lock: return [json.loads(r[0]) for r in b.conn.execute('SELECT body FROM l2_cases')]

    def notices(self, after=0):
        b = self.agent.service.buffer
        with b.lock:
            return [dict(r) for r in b.conn.execute('SELECT * FROM l2_notices WHERE id>? ORDER BY id LIMIT 100', (after,))]

    def save(self, case, notice=None):
        b = self.agent.service.buffer
        with b.lock, b.conn:
            b.conn.execute('INSERT OR REPLACE INTO l2_cases VALUES (?,?)', (case['id'], json.dumps(case)))
            if notice:
                b.conn.execute('INSERT INTO l2_notices(ts,case_id,body) VALUES (?,?,?)', (self.clock(), case['id'], notice))
        if notice and self.notify: self.notify({'l2_case': case['id'], 'notification': notice})
        if notice: self.agent.audit.record_iam('l2-policy', 'l2_notice', json.dumps({'case': case['id'], 'message': notice}))

    def halted(self):
        b = self.agent.service.buffer
        with b.lock: return b.conn.execute("SELECT value FROM l2_settings WHERE key='stopped'").fetchone()[0] == 'true'

    def control(self, command, case_id=None, reason=""):
        if command in {"reject", "defer"} and not reason.strip(): raise ValueError("a reason is required")
        with self.lock:
            if command in {'stop', 'resume'}:
                b = self.agent.service.buffer
                with b.lock, b.conn:
                    b.conn.execute("UPDATE l2_settings SET value=? WHERE key='stopped'", ('true' if command == 'stop' else 'false',))
                self.agent.audit.record_iam(self.agent.actor, 'l2_'+command, '')
                return {'automatic_stopped': self.halted()}
            case = next((c for c in self.cases() if c['id'] == case_id), None)
            if not case: raise ValueError('unknown L2 case')
            if command == 'revert':
                if not case.get('action_id'): raise ValueError('no action to revert')
                self.agent.protection.undo(case['action_id'], self.agent.actor)
                case['state'] = 'reverted'
            else:
                if case['state'] not in {'waiting', 'needs_review'}: raise ValueError('case is not awaiting review')
                if command == 'reject': case['state'] = 'rejected'
                elif command in {'ack', 'defer'}:
                    # One bounded extension; duplicates cannot extend it again.
                    if case.get('acknowledged'): raise ValueError('review extension already used')
                    case['acknowledged'] = True
                    window = self.policy.windows[case['severity']]
                    if window is not None: case['deadline'] = min(case['deadline'] + window, self.clock() + window)
                else: raise ValueError('unknown L2 control')
            self.save(case, f'{command} by {self.agent.actor}: {reason[:1000]}')
            return case

    def evidence_row(self, row):
        buffer = self.agent.service.buffer
        with buffer.lock:
            ids = [r[0] for r in buffer.conn.execute("SELECT event_id FROM telemetry WHERE host=? AND state='done' AND connector IN ('windows','sysmon','defender','linux_auth','local_process') AND timestamp<=? ORDER BY timestamp DESC,id DESC LIMIT 64", (row['event']['hostname'],row['event']['timestamp']))]
        prepared = {**row, '_l2_related':[buffer.detail(event_id) for event_id in ids if event_id != row['event_id']]}
        from .l2_evidence import dossier, assess
        prepared['_l2_assessment'] = assess(dossier(prepared,prepared['_l2_related']), self.agent.protection.proposal(prepared))
        return prepared

    def tick(self):
        with self.lock:
            self.agent.protection.reconcile()
            cases = {c['id']: c for c in self.cases()}
            # Observe all escalations; target/process identity prevents unrelated cases
            # from sharing deadlines. Repetition never restarts a deadline.
            buffer = self.agent.service.buffer
            with buffer.lock:
                unseen = [r[0] for r in buffer.conn.execute("SELECT event_id FROM telemetry t WHERE state='done' AND decision='escalate' AND connector NOT IN ('file','replay','demo') AND NOT EXISTS (SELECT 1 FROM l2_seen s WHERE s.event_id=t.event_id) ORDER BY priority DESC,id DESC LIMIT 100")]
            event_ids = set(unseen) | {c['event_id'] for c in cases.values() if c['state'] in {'waiting','needs_review'}}
            observations = [buffer.detail(event_id) for event_id in event_ids]
            observations = sorted((r for r in observations if r), key=lambda r:r['event']['timestamp'], reverse=True)
            for row in observations:
                row['proposal'] = self.agent.protection.proposal(row) if self.agent.scope else None
                if row['state'] != 'done' or row['analysis']['decision'] != 'escalate': continue
                row = self.evidence_row(row)
                event = row['event']
                identity = [row['connector'], event['hostname'], event['event_type'], event.get('src_ip'), event.get('dst_ip'), event.get('process_name'), event.get('username'), event.get('metadata', {}).get('process_created')]
                key = hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:24]
                level = self.policy.severity(row); window = self.policy.windows[level]
                if key not in cases:
                    case = {'id':key, 'event_id':row['event_id'], 'severity':level, 'created':self.clock(),
                        'deadline': self.clock()+window if window is not None else None,
                        'state':'waiting', 'brief':None, 'action_id':None}
                    cases[key] = case; self.save(case, 'Escalated for L2 and human review')
                case = cases[key]
                if case['state'] not in {'waiting','needs_review'}: continue
                # events() is newest first: do not replace evidence with an older row.
                old = self.agent.service.buffer.detail(case['event_id'])
                if old and event['timestamp'] < old['event']['timestamp']: continue
                case['event_id'] = row['event_id']
                if list(WINDOWS).index(level) < list(WINDOWS).index(case['severity']):
                    case['severity'] = level; case['acknowledged'] = False
                    case['deadline'] = min(case['deadline'] or float('inf'), self.clock()+window)
                    case['brief'] = None
                    self.save(case, 'Severity increased; response deadline shortened')
                else: self.save(case)
                if not case['brief'] and row['_l2_assessment']['route']=='verified_critical':
                    fast = self.brain.fast_review(row,row.get('proposal'))
                    if fast:
                        self.results.put_nowait((key,level,fast,None))
                        continue
                if not case['brief'] and key not in self.inflight and not case.get('review_failed'):
                    try: self.jobs.put_nowait((list(WINDOWS).index(level),key,self.evidence_row(row),row.get('proposal'))); self.inflight.add(key)
                    except queue.Full: pass
            while True:
                try: key, reviewed_level, brief, error = self.results.get_nowait()
                except queue.Empty: break
                self.inflight.discard(key)
                case = cases[key]
                if brief and brief.get('_follow_up'):
                    case['follow_up'] = brief
                    if case['state'] == 'waiting' and not brief.get('error'): case['brief'] = brief
                    self.save(case, 'L2 follow-up requires human review' if brief.get('error') or brief.get('action')=='human_review' else 'L2 deeper follow-up supports the recommendation; inspect evidence and objections')
                    continue
                if case['state'] not in {'waiting','needs_review'}: continue
                if reviewed_level != case['severity']: continue
                if error:
                    case['review_failed'] = True; case['state'] = 'needs_review'
                    self.save(case, 'L2 unavailable or invalid output; human review required')
                else:
                    case['brief'] = brief; self.save(case, 'L2 advice ready; inspect l2-cases')
                    if brief.get('needs_deep_review') and not case.get('deep_queued'):
                        deep_row = self.evidence_row(self.agent.service.buffer.detail(case['event_id']))
                        deep_row['_l2_deep'] = True
                        try:
                            self.jobs.put_nowait((3,key,deep_row,self.agent.protection.proposal(deep_row)))
                            case['deep_queued'] = True; self.inflight.add(key); self.save(case)
                        except queue.Full: self.save(case, 'Deeper review queue full; human follow-up required')
            for case in cases.values():
                if case['state'] == 'executed':
                    action = next((a for a in self.agent.protection.actions(case['event_id']) if a['id'] == case['action_id']), None)
                    if action and action['status'] not in {'executed', 'expiry_due'}:
                        case['state'] = action['status']
                        self.save(case, 'Containment status: '+action['status'])
                if case['state'] != 'waiting' or case['deadline'] is None or self.clock() < case['deadline']: continue
                brief = case['brief']
                row = self.agent.service.buffer.detail(case['event_id'])
                proposal = self.agent.protection.proposal(row)
                if not brief:
                    if not case.get('deadline_alerted'):
                        case['deadline_alerted'] = True
                        self.save(case, 'Response deadline reached while L2 is pending; urgent human review required')
                    continue  # slow model does not authorize a block
                age = self.clock() - datetime.fromisoformat(row['event']['timestamp']).timestamp()
                if not 0 <= age <= 30: proposal = None
                if self.halted() or not self.policy.permits(row,brief) or not proposal or brief['action'] != 'block_ip' or brief['confidence'] < .95:
                    case['state'] = 'needs_review'; self.save(case, 'Deadline reached; automatic action not authorized; human intervention required'); continue
                # Pin recommendation to its original target. Fresh evidence is also
                # required by Protection immediately before native execution.
                if brief.get('target') != proposal['target'] or not self.brain.authorize(brief,self.evidence_row(row),proposal):
                    case['state'] = 'needs_review'; self.save(case, 'Recommendation target changed; human review required'); continue
                case['state'] = 'executing'; self.save(case, 'Authorized deadline reached; attempting temporary block')
                try:
                    actions = self.agent.protection.approve(case['event_id'], 'l2-policy', expected_target=proposal['target'])
                    action = next(a for a in actions if a['status'] == 'executed')
                    case['action_id'] = action['id']; case['state'] = 'executed'
                    self.save(case, f"Temporary block applied and native rule verified; expires {action['expires_at']}. Revert: l2-revert {case['id']}. Connectivity effect requires independent verification.")
                except (ValueError, OSError):
                    case['state'] = 'needs_review'; self.save(case, 'Containment failed; inspect actions and cleanup status immediately')
            with buffer.lock, buffer.conn:
                buffer.conn.executemany('INSERT OR IGNORE INTO l2_seen VALUES (?)', [(event_id,) for event_id in unseen])

    def start(self):
        def reviewer():
            while not self.stop.is_set():
                try: _,key,row,proposal = self.jobs.get(timeout=.5)
                except queue.Empty: continue
                try:
                    brief = self.brain.review(row, proposal)
                    brief = {**brief, 'target':proposal['target'] if proposal else None, '_follow_up':bool(row.get('_l2_deep'))}
                    result = (key,self.policy.severity(row),brief,None)
                except Exception:
                    result = (key,self.policy.severity(row),{'_follow_up':True,'error':'Deeper reasoning unavailable; human investigation required'} if row.get('_l2_deep') else None,True)
                if not self.stop.is_set(): self.results.put(result)
        def scheduler():
            while not self.stop.is_set():
                try: self.tick()
                except Exception:
                    self.agent.audit.record_iam('l2-policy','l2_scheduler_failed','Automatic processing paused; restart and inspect')
                    if self.notify: self.notify({'notification':'L2 scheduler failed; automatic processing stopped. Inspect audit and restart.'})
                    self.stop.set()
                self.stop.wait(1)
        self.threads = [threading.Thread(target=reviewer,daemon=True),threading.Thread(target=scheduler,daemon=True)]
        for thread in self.threads: thread.start()

    def close(self):
        self.stop.set()
        # Reviewer never writes SQLite; the scheduler must finish any native
        # operation before Agent closes its database connections.
        if self.threads: self.threads[1].join()
