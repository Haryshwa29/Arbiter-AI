"""Local terminal agent over the shared ingestion and containment pipeline."""
import getpass
import json
import os
from pathlib import Path
import platform
import socket
import sys

from .ingestion.containment import ContainmentScope, local_firewall
from .ingestion.protection import Protection
from .ingestion.service import IngestionService
from .memory import Memory
from .store import AuditStore


class StateLock:
    """Exclusive process-lifetime ownership; EventBuffer has one worker owner."""
    def __init__(self, path):
        self.stream = Path(path).open("a+b")
        if os.fstat(self.stream.fileno()).st_size == 0:
            self.stream.write(b"0")
            self.stream.flush()
        self.stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(self.stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            self.stream.close()
            raise ValueError("another agent owns this state directory") from None

    def close(self):
        self.stream.close()


class Agent:
    def __init__(self, state_dir, backend="rules-only", model="qwen3.5:4b",
                 scope=None, firewall=None):
        directory = Path(state_dir).resolve()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.owner = StateLock(directory / "agent.lock")
        self.memory = self.audit = self.service = None
        self.l2 = None
        self.l2_model = None
        self.scope = scope
        self.actor = getpass.getuser()
        try:
            self.memory = Memory(directory / "agent-memory.db")
            self.audit = AuditStore(directory / "agent-audit.db")
            self.service = IngestionService(directory / "agent-events.db", self.memory,
                                            self.audit, backend, model)
            self.protection = Protection(self.service.buffer, self.audit,
                firewall or local_firewall(), scope=scope, verify=True)
            self.protection.reconcile()
            self.audit.record_iam(self.actor, "agent_started", json.dumps({
                "host": socket.gethostname(), "backend": backend,
                "containment_enabled": scope is not None,
                "allowed": [str(n) for n in scope.allowed] if scope else [],
                "protected": [str(n) for n in scope.protected] if scope else []}))
        except Exception:
            self.close()
            raise

    def start(self, auth_log=None):
        system = platform.system()
        # Preserve an operator's explicit disable across terminal-agent restarts.
        if not any(row["name"] == "attachments" for row in self.service.buffer.configs()):
            self.service.configure("attachments", True, {"interval": 15})
        else:
            row = next(r for r in self.service.buffer.configs() if r["name"] == "attachments")
            if row["enabled"]:
                from .ingestion.schema import safe_json
                self.service._start("attachments", safe_json(row["config"]), safe_json(row["checkpoint"]))
        self.service.configure("local_process", True, {})
        if system == "Windows":
            self.service.configure("windows", True, {"channels": ["Security"], "read_existing": False})
            from .ingestion.collectors.windows import channel_installed, SYSMON_CHANNEL
            if channel_installed(SYSMON_CHANNEL):
                self.service.configure("sysmon", True, {"read_existing": False})
            # Existing Defender correlator can corroborate Sysmon connections.
            self.service.configure("defender", True, {"read_existing": False})
        elif system == "Linux":
            paths = [Path(auth_log)] if auth_log else [Path("/var/log/auth.log"), Path("/var/log/secure")]
            path = next((p for p in paths if p.is_file()), None)
            if path:
                self.service.configure("linux_auth", True, {"path": str(path.resolve()), "read_existing": False})
            elif auth_log:
                raise ValueError("specified OpenSSH auth log does not exist")
        else:
            raise ValueError("agent supports Windows and Linux")
        self.service.pipeline.start()

    def enable_l2(self, model, policy=None, notify=None, review_seconds=90):
        from .l2 import L2Brain
        from .l2_workflow import L2Workflow, ResponsePolicy
        if policy and policy.get("automatic") and not self.scope:
            raise ValueError("automatic L2 response requires explicit containment scope")
        if self.service.backend == "ollama" and model == self.service.model:
            raise ValueError("L2 must use a distinct model from L1")
        self.l2 = L2Workflow(self, L2Brain(model, review_seconds), ResponsePolicy(policy), notify=notify)
        self.l2_model = model
        self.l2.start()

    def events(self):
        rows = self.service.buffer.query({"scope": "live"}, limit=100)
        results = []
        for row in rows:
            detail = self.service.buffer.detail(row["event_id"])
            results.append({**detail, "proposal": self.protection.proposal(detail) if self.scope else None,
                            "actions": self.protection.actions(row["event_id"])})
        return results

    def command(self, line):
        parts = line.strip().split()
        if not parts: return {"ok": True}
        command, *values = parts
        self.protection.reconcile()
        if command.startswith("l2-"):
            if not self.l2: raise ValueError("L2 is disabled")
            if command == "l2-cases" and not values: return {"cases": self.l2.cases()}
            if command == "l2-notices" and len(values) <= 1: return {"notices": self.l2.notices(int(values[0]) if values else 0)}
            operation = command[3:]
            if operation in {"stop", "resume"} and not values: return self.l2.control(operation)
            if operation in {"ack", "revert"} and len(values) == 1: return self.l2.control(operation, values[0])
            if operation in {"defer", "reject"} and len(values) >= 2: return self.l2.control(operation, values[0], " ".join(values[1:]))
            raise ValueError("invalid L2 command")
        if command == "status" and not values:
            status = self.service.status()
            if platform.system() == "Linux":
                status["elevated"] = os.geteuid() == 0
            if status["backend"] == "rules-only":
                status["model"] = ""
            return {**status, "containment_enabled": self.scope is not None,
                    "protection_enabled": self.scope is not None,
                    "l2_enabled": self.l2 is not None,
                    "l2_model": self.l2_model,
                    "l2_automatic_stopped": self.l2.halted() if self.l2 else True,
                    "live_containment_verified": False,
                    "verification_note": "Native rule presence does not establish that an attacker flow stopped."}
        if command == "events" and not values:
            return {"events": self.events()}
        if command == "actions" and not values:
            with self.service.buffer.lock:
                return {"actions": [dict(r) for r in self.service.buffer.conn.execute(
                    "SELECT * FROM protection_actions ORDER BY rowid DESC LIMIT 100")]}
        if command == "approve" and len(values) == 2:
            if not self.scope: raise ValueError("containment is disabled; restart with explicit scope")
            return {"actions": self.protection.approve(values[0], self.actor, expected_target=values[1]),
                    "native_rule_verified": True, "connectivity_verified": False}
        if command == "undo" and len(values) == 1:
            return {"actions": self.protection.undo(values[0], self.actor), "native_removal_verified": True}
        if command == "quit" and not values:
            return {"stopping": True}
        raise ValueError("commands: status, events, actions, approve EVENT_ID EXACT_IP, undo ACTION_ID, quit")

    def close(self):
        # No rollback claim on exit: OS-owned expiry remains responsible for TTL.
        try:
            if self.l2: self.l2.close()
            if self.service: self.service.stop()
        finally:
            try:
                if self.audit: self.audit.close()
                if self.memory: self.memory.close()
            finally:
                self.owner.close()


def cmd_agent(args):
    scope = None
    if args.enable_containment:
        protected = list(args.protect_network)
        # SSH peer is protected even if accidentally omitted by the operator.
        peer = os.environ.get("SSH_CONNECTION", "").split()
        if not protected and not peer:
            raise SystemExit("--protect-network must identify management and essential service addresses")
        if peer:
            protected.append(peer[0])
        # Never block this host's own resolved interface addresses.
        try:
            protected.extend({item[4][0].split("%", 1)[0] for item in
                              socket.getaddrinfo(socket.gethostname(), None)})
        except OSError:
            raise SystemExit("cannot identify local addresses; resolve the hostname before enabling containment") from None
        try:
            scope = ContainmentScope(args.allow_network, protected)
        except ValueError as exc:
            raise SystemExit(str(exc)) from None
    elif args.allow_network or args.protect_network:
        raise SystemExit("scope options require --enable-containment")
    agent = None
    try:
        agent = Agent(args.state_dir, args.backend, args.model, scope)
        agent.start(args.auth_log)
        if args.l2_model:
            policy = json.loads(Path(args.l2_policy).read_text()) if args.l2_policy else None
            agent.enable_l2(args.l2_model, policy, notify=lambda notice: print(json.dumps(notice), flush=True), review_seconds=args.l2_review_seconds)
        elif args.l2_policy:
            raise ValueError("--l2-policy requires --l2-model")
        print(json.dumps({"started": True, "host": socket.gethostname(),
                          "backend": args.backend, "containment_enabled": scope is not None,
                          "commands": "status | events | actions | approve EVENT_ID EXACT_IP | undo ACTION_ID | quit",
                          "l2_commands": "l2-cases | l2-notices [AFTER_ID] | l2-ack CASE | l2-defer CASE REASON | l2-reject CASE REASON | l2-revert CASE | l2-stop | l2-resume" if agent.l2 else None}), flush=True)
        for line in sys.stdin:
            try:
                result = agent.command(line)
            except (ValueError, OSError) as exc:
                result = {"error": str(exc)}
            print(json.dumps(result), flush=True)
            if result.get("stopping"): break
    except KeyboardInterrupt:
        pass
    except (ValueError, OSError) as exc:
        raise SystemExit(str(exc)) from None
    finally:
        if agent: agent.close()
