"""One durable CPU report worker, independent of the decision queues."""
import json
import threading

from ..reports import digest, render, snapshot


class ReportWorker:
    def __init__(self, buffer, project):
        self.buffer,self.project=buffer,project
        self.stop_event=threading.Event()
        self.thread=None
        self.last_error=''

    def start(self):
        if self.thread and self.thread.is_alive():return
        self.stop_event.clear()
        self.thread=threading.Thread(target=self.run,name='arbiter-reports',daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop_event.is_set():
            try:
                if not self.process_one():self.stop_event.wait(.2)
            except Exception as exc:
                self.last_error=type(exc).__name__
                self.stop_event.wait(1)

    def process_one(self):
        b=self.buffer
        with b.lock:
            job=b.conn.execute("SELECT event_id,revision FROM decision_reports WHERE state='pending' ORDER BY rowid LIMIT 1").fetchone()
        if not job:return False
        try:
            row=self.project(b.detail(job['event_id']))
            if not row:return False
            value=snapshot(row);body=render(value)
            with b.lock,b.conn:
                b.conn.execute("UPDATE decision_reports SET state='ready',snapshot=?,digest=?,body=?,error='' WHERE event_id=? AND revision=?",
                    (json.dumps(value),digest(value),json.dumps(body),job['event_id'],job['revision']))
            self.last_error=''
        except Exception as exc:
            with b.lock,b.conn:
                b.conn.execute("UPDATE decision_reports SET state='failed',error=? WHERE event_id=? AND revision=?",
                    (type(exc).__name__,job['event_id'],job['revision']))
        return True

    def attach(self,row):
        if not row:return row
        if row['state'] in {'pending','processing'}:
            return {**row,'report':dict(state='partial',body=render(snapshot(row)),error='')}
        with self.buffer.lock:
            report=self.buffer.conn.execute('SELECT state,digest,body,error FROM decision_reports WHERE event_id=?',(row['event_id'],)).fetchone()
        if not report:return {**row,'report':{'state':'not_requested'}}
        state=report['state']
        body=None
        if state=='ready':
            try:
                if report['digest']!=digest(snapshot(row)):state='stale'
                else:
                    body=json.loads(report['body'])
                    if (not isinstance(body,dict) or body.get('event_id')!=row['event_id']
                            or body.get('decision')!=(row.get('analysis') or {}).get('decision')
                            or body.get('action_authority') is not False or not isinstance(body.get('brief'),dict)
                            or not isinstance(body.get('title'),str) or not isinstance(body.get('checks'),list)):
                        raise ValueError('invalid saved report')
            except (ValueError,TypeError,KeyError):state='failed';body=None
        return {**row,'report':dict(state=state,body=body,error=report['error'])}

    def status(self):
        with self.buffer.lock:
            counts=dict(self.buffer.conn.execute('SELECT state,COUNT(*) FROM decision_reports GROUP BY state'))
        return dict(alive=bool(self.thread and self.thread.is_alive()),queued=counts.get('pending',0),
            completed=counts.get('ready',0),errors=counts.get('failed',0),error=self.last_error,uses_inference=False)

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=10)
            if self.thread.is_alive():raise RuntimeError('report worker is still stopping')
