"""Five bounded workers for the terminal agent's final-alert-review mode."""
import hashlib
import json
import queue
import threading
import time

from .pipeline import Pipeline
from ..facts import texts
from ..guardrails import guardrail_check, fact_downgrade, final_guardrail_check
from ..l2_final_review import eligible, project_final


class ReviewPipeline(Pipeline):
    stages = ('gateway', 'l1', 'l2_prefilter', 'l2', 'final_guardrail')

    def __init__(self, buffer, engine, audit, workflow):
        super().__init__(buffer, engine, audit)
        self.workflow = workflow
        self.workflow.brain.routing_only = True
        # Keep priority selection close to L1; longer L2 waits stay bounded too.
        self.queues = {name: queue.Queue(1 if name == 'l1' else 32) for name in self.stages[1:]}
        self.threads = {}
        self.state_lock = threading.Lock()
        self.state = {name: dict(busy=False, completed=0, errors=0, occupied_ms=0., queue_wait_ms=0.) for name in self.stages}
        self._last_deadlines = 0.
        with buffer.lock, buffer.conn:
            buffer.conn.execute("CREATE INDEX IF NOT EXISTS idx_l2_deadline ON l2_cases(json_extract(body,'$.deadline'))")

    def start(self):
        if self.threads: raise RuntimeError('review pipeline already started')
        for stage in self.stages:
            self.threads[stage] = threading.Thread(target=self._run, args=(stage,),
                name='arbiter-'+stage, daemon=True)
        self.thread = self.threads['gateway']
        for thread in self.threads.values(): thread.start()

    def process_one(self):
        raise RuntimeError('five-stage processing requires start(), not synchronous process_one()')

    def status(self):
        with self.buffer.lock:
            pending = self.buffer.conn.execute("SELECT COUNT(*) FROM telemetry WHERE state='pending'").fetchone()[0]
        with self.state_lock:
            return {name: {**state, 'alive': bool(self.threads.get(name) and self.threads[name].is_alive()),
                'queued': self.queues[name].qsize() if name in self.queues else pending,
                'queue_capacity': self.queues[name].maxsize if name in self.queues else self.buffer.capacity}
                for name, state in self.state.items()}

    def _put(self, stage, job, caller):
        job['_queued_at'] = time.monotonic()
        while not self.stop_event.is_set():
            try:
                self.queues[stage].put(job, timeout=.1)
                return
            except queue.Full:
                if caller == 'gateway': self._housekeeping()
        # Unfinished rows remain processing and are recovered as pending on restart.

    def _housekeeping(self):
        self.last_activity = time.monotonic()
        if self.last_activity-self._last_prune > 3600:
            self.buffer.prune(); self._last_prune = self.last_activity
        if self.last_activity-self._last_deadlines < 1: return
        self._last_deadlines = self.last_activity
        w = self.workflow
        with w.lock:
            with self.buffer.lock:
                expired = [json.loads(r[0]) for r in self.buffer.conn.execute(
                    "SELECT body FROM l2_cases WHERE json_extract(body,'$.deadline')<=? "
                    "AND json_extract(body,'$.state')='waiting' AND COALESCE(json_extract(body,'$.deadline_alerted'),0)=0 LIMIT 100", (w.clock(),))]
            for case in expired:
                case['deadline_alerted'] = True
                w.save(case, 'Review deadline reached; alert remains visible and requires human review')

    def _run(self, stage):
        while not self.stop_event.is_set():
            job = None
            try:
                if stage == 'gateway':
                    self._housekeeping()
                    row = self.buffer.claim()
                    if not row:
                        self.stop_event.wait(.1); continue
                    job = {'row': row}
                else:
                    try: job = self.queues[stage].get(timeout=.1)
                    except queue.Empty: continue
                started = time.monotonic()
                with self.state_lock:
                    self.state[stage]['busy'] = True
                    if stage != 'gateway': self.state[stage]['queue_wait_ms'] += (started-job['_queued_at'])*1000
                try:
                    self._step(stage, job)
                    with self.state_lock: self.state[stage]['completed'] += 1
                except Exception as exc:
                    with self.state_lock: self.state[stage]['errors'] += 1
                    if stage in {'l2_prefilter', 'l2'}:
                        job['l2_error'] = type(exc).__name__
                        self._put('final_guardrail', job, stage)
                    else:
                        self.buffer.fail(job['row']['id'])
                finally:
                    with self.state_lock:
                        self.state[stage]['busy'] = False
                        self.state[stage]['occupied_ms'] += (time.monotonic()-started)*1000
                    if stage != 'gateway': self.queues[stage].task_done()
            except Exception as exc:
                # A broken store must stop the pipeline instead of silently losing a worker.
                with self.state_lock:
                    self.state[stage]['errors'] += 1
                    self.state[stage]['failure'] = type(exc).__name__
                self.stop_event.set()

    def _case(self, job):
        key = hashlib.sha256(job['event'].event_id.encode()).hexdigest()[:24]
        with self.buffer.lock:
            saved = self.buffer.conn.execute('SELECT body FROM l2_cases WHERE id=?', (key,)).fetchone()
        if saved:
            case = json.loads(saved[0])
            if case['event_id'] != job['event'].event_id: raise ValueError('case belongs to a different event')
            return case
        row = {'event': job['event'].__dict__, 'analysis': job['analysis']}
        level = self.workflow.policy.severity(row)
        window = self.workflow.policy.windows[level]
        case = dict(id=key, event_id=job['event'].event_id, severity=level,
            created=self.workflow.clock(), deadline=self.workflow.clock()+window if window is not None else None,
            state='waiting', brief=None, action_id=None)
        self.workflow.save(case, 'L1 escalated this event for L2 and human review')
        return case

    def _step(self, stage, job):
        if stage == 'gateway':
            job.update(self.prepare(job['row']))
            self._put('l1', job, stage)
        elif stage == 'l1':
            job['analysis'] = self.analyze(job)
            # L1 has already passed its own shared gate; pending alerts stay visible.
            with self.buffer.lock, self.buffer.conn:
                self.buffer.conn.execute("UPDATE telemetry SET analysis=? WHERE id=? AND state='processing'",
                    (json.dumps(job['analysis']), job['row']['id']))
            if eligible(job['analysis']):
                with self.workflow.lock: job['case'] = self._case(job)
                self._put('l2_prefilter', job, stage)
            else: self._put('final_guardrail', job, stage)
        elif stage == 'l2_prefilter':
            case = job['case']
            if case.get('review_failed') or case['state'] == 'rejected':
                job['reused_case'] = True
                self._put('final_guardrail', job, stage)
                return
            row = dict(event=job['event'].__dict__, analysis=job['analysis'],
                event_id=job['event'].event_id, connector=job['row']['connector'], state='processing')
            row = self.workflow.evidence_row(row)
            event = job['event'].to_event()
            context = job['analysis'].get('context_signature')
            if context: event.fields['_context_signature'] = context
            job['prepared'] = self.workflow.brain.prepare_review(event, job['analysis'],
                replay=job['row']['connector'] in {'file','replay','demo'}, related=row['_l2_related'])
            if case.get('brief'):
                project_final(job['analysis'], case['brief'], event_id=job['event'].event_id)
                job['candidate'] = dict(case['brief'])
                self._put('final_guardrail', job, stage)
            elif job['prepared']['assessment']['route'] == 'model': self._put('l2', job, stage)
            else:
                job['candidate'] = self.workflow.brain.review_prepared(job['prepared'])
                self._put('final_guardrail', job, stage)
        elif stage == 'l2':
            job['candidate'] = self.workflow.brain.review_prepared(job['prepared'])
            self._put('final_guardrail', job, stage)
        else:
            self._finish_review(job)

    def _finish_review(self, job):
        first = job['analysis']
        if 'case' in job:
            with self.workflow.lock:
                case = self._case(job)
                rejected = case['state'] == 'rejected'
                if not job.get('reused_case'):
                    brief = None
                    if not job.get('l2_error'):
                        try:
                            brief = self.workflow.brain.finish_review(job['prepared'], job['candidate'])
                            project_final(first, brief, event_id=job['event'].event_id)
                        except Exception as exc:
                            job['l2_error'] = type(exc).__name__
                    if job.get('l2_error'):
                        case.update(review_failed=True, review_error=job['l2_error'], state='needs_review', brief=None)
                        notice = 'L2 unavailable or invalid output; alert retained for human review'
                    else:
                        case['brief'] = brief
                        notice = 'Final guardrail checked the L2 decision; inspect l2-cases'
                    # Rejection wins even if it arrived during model inference.
                    if rejected: case['state'] = 'rejected'
                    self.workflow.save(case, notice)
                elif case.get('brief'):
                    project_final(first, case['brief'], event_id=job['event'].event_id)
        else:
            event = job['event'].to_event()
            rail = guardrail_check(event)
            allow = None
            if rail and first['tier'] == 'llm':
                facts = self.engine.memory.facts_for(event.host, event.source)
                if fact_downgrade(rail, event, texts(facts)): allow = rail.name
            hit = final_guardrail_check(event, first['decision'], allow)
            if hit:
                first.update(decision='escalate', kind='alert', tier='guardrail', backend='deterministic', model='',
                    rationale=f'Shared final guardrail [{hit.code}]: {hit.reason}')
            first['pipeline_final_guardrail'] = dict(decision=first['decision'], veto=hit.code if hit else None)
        self.finish(job, first)

    def stop(self):
        self.stop_event.set()
        deadline = time.monotonic()+max(130, self.workflow.brain.review_seconds+5)
        for thread in self.threads.values(): thread.join(timeout=max(0, deadline-time.monotonic()))
        if any(t.is_alive() for t in self.threads.values()):
            raise RuntimeError('review workers are still stopping; keep their stores open')
