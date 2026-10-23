"""Synthetic telemetry + real filtering in a disposable Linux network namespace.

Run as root through `unshare --net`; refuses the initial network namespace.
No SSH attack is performed. This is not evidence of a live breach detection.
Use --expiry to verify the production five-minute TTL with the agent stopped.
"""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import hashlib
import threading
import time

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nft", required=True, help="absolute nft executable")
    parser.add_argument("--l2", action="store_true", help="exercise L2 deadline with a fixture recommendation and native firewall")
    parser.add_argument("--expiry", action="store_true", help="also wait for real five-minute kernel expiry")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, help="test imports from a built agent zipapp")
    args = parser.parse_args()
    if (sys.platform != "linux" or os.geteuid() != 0 or
            os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net")):
        raise SystemExit("run only as root inside a disposable unshare --net namespace")
    sys.path.insert(0, str(args.artifact.resolve()) if args.artifact else str(Path(__file__).resolve().parents[1]))
    from arbiter.agent import Agent
    from arbiter.ingestion.containment import ContainmentScope, LinuxFirewall
    for command in (["ip", "link", "set", "lo", "up"],
                    *(["ip", "addr", "add", ip + "/32", "dev", "lo"] for ip in
                      ("10.203.0.10", "10.203.0.20", "10.203.0.30"))):
        subprocess.run(command, check=True, capture_output=True)
    firewall = LinuxFirewall(str(Path(args.nft).resolve()))
    listener = socket.socket()
    listener.bind(("10.203.0.10", 0))
    listener.listen(10)
    listener.settimeout(.2)
    endpoint = listener.getsockname()
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                client, _ = listener.accept()
            except socket.timeout:
                continue
            with client:
                client.settimeout(.5)
                try:
                    client.sendall(client.recv(16))
                except OSError:
                    pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()

    def reaches(peer):
        try:
            with socket.socket() as client:
                client.settimeout(.6)
                client.bind((peer, 0))
                client.connect(endpoint)
                client.sendall(b"probe")
                return client.recv(16) == b"probe"
        except OSError:
            return False

    report = {"test_type": "synthetic_telemetry_real_namespace_firewall",
              "thm_tested": False, "live_attack_tested": False,
              "started_at": datetime.now(timezone.utc).isoformat()}
    if args.artifact:
        report["artifact_sha256"] = hashlib.sha256(args.artifact.read_bytes()).hexdigest()
    agent = None
    try:
        with tempfile.TemporaryDirectory(prefix="arbiter-agent-smoke-") as directory:
            log = Path(directory) / "auth.log"
            log.touch()
            scope = ContainmentScope(["10.203.0.0/24"], ["10.203.0.10", "10.203.0.30"])
            agent = Agent(Path(directory) / "state", scope=scope, firewall=firewall)
            agent.start(log)
            # Establish the initial end-of-file checkpoint before adding records.
            deadline = time.monotonic() + 5
            while "generation" not in agent.service.collectors["linux_auth"].checkpoint:
                if time.monotonic() >= deadline: raise RuntimeError("collector did not initialize")
                time.sleep(.05)
            with log.open("a") as output:
                for index in range(5):
                    stamp = datetime.now(timezone.utc).isoformat()
                    output.write(f"{stamp} host sshd[{100 + index}]: Failed password for labuser from 10.203.0.20 port {4000 + index} ssh2\n")
            deadline = time.monotonic() + 15
            proposal = None
            while time.monotonic() < deadline:
                proposal = next((row for row in agent.events() if row["proposal"]), None)
                if proposal: break
                time.sleep(.1)
            if not proposal: raise RuntimeError("pipeline did not produce a scoped proposal")
            report["collector_pipeline_proposal"] = True
            report["baseline_target_reachable"] = reaches("10.203.0.20")
            report["baseline_management_reachable"] = reaches("10.203.0.30")
            if args.l2:
                from arbiter.l2_workflow import L2Workflow, ResponsePolicy
                from arbiter.l2 import L2Brain
                brain = L2Brain("fixture-14b")
                def fixture_generate(prompt, system, **kwargs):
                    data = json.loads(prompt); facts = data["evidence_packet"]["facts"]
                    if "recommendation" in data:
                        return json.dumps({"accept":True,"objections":[],"citations":[f["id"] for f in facts]})
                    brief = {k:"Synthetic lab evidence; operator review" for k in ("assessment","evidence","gaps","recommendation","alternatives","recovery","urgency")}
                    brief.update(action="block_ip",target="10.203.0.20",confidence=.99,assertions=[{"fact_id":f["id"],"field":"event_type","value":f["event_type"]} for f in facts])
                    brief["hypotheses"] = [{"kind":kind,"summary":"Synthetic competing explanation","supports":[facts[0]["id"]],"against":[]} for kind in ("malicious","benign")]
                    return json.dumps(brief)
                brain.backend.generate = fixture_generate
                workflow = L2Workflow(agent, brain, ResponsePolicy({"automatic":True,
                    "rules":["repeated_login_failures"], "windows":{"critical":0,"high":0,"medium":0}}))
                agent.l2 = workflow
                workflow.tick()
                case = workflow.cases()[0]
                evidence = workflow.evidence_row(agent.service.buffer.detail(case["event_id"]))
                brief = brain.review(evidence, agent.protection.proposal(evidence))
                workflow.results.put((case["id"],case["severity"],brief,None))
                workflow.tick()
                case = workflow.cases()[0]
                if case["state"] != "executed": raise RuntimeError("L2 policy did not execute")
                action_id = case["action_id"]
                result = {"native_rule_verified":firewall.active(action_id,"10.203.0.20")}
                report["l2_fixture_deadline_executed"] = True
                report["l2_action_notice_persisted"] = any("Revert:" in n["body"] for n in workflow.notices())
            else:
                result = agent.command(f"approve {proposal['event_id']} 10.203.0.20")
                action_id = result["actions"][0]["id"]
            report["native_rule_verified"] = result["native_rule_verified"]
            report["selected_peer_blocked"] = not reaches("10.203.0.20")
            report["management_preserved"] = reaches("10.203.0.30")
            if args.l2: agent.command(f"l2-revert {case['id']}")
            else: agent.command(f"undo {action_id}")
            report["undo_restored_connectivity"] = reaches("10.203.0.20")
            report["native_removal_verified"] = firewall.removed(action_id)
            if args.expiry:
                result = agent.command(f"approve {proposal['event_id']} 10.203.0.20")
                expiry_id = result["actions"][0]["id"]
                report["expiry_block_confirmed"] = not reaches("10.203.0.20")
                agent.close()
                agent = None
                print("Native five-minute expiry test running with agent stopped", flush=True)
                deadline = time.monotonic() + 315
                while time.monotonic() < deadline and not reaches("10.203.0.20"):
                    time.sleep(1)
                report["expiry_restored_without_agent"] = reaches("10.203.0.20")
                report["expired_element_absent"] = not firewall.active(expiry_id, "10.203.0.20")
                firewall.undo(expiry_id)
            checks = [v for k, v in report.items() if isinstance(v, bool) and k not in {"thm_tested", "live_attack_tested"}]
            report["passed"] = bool(checks) and all(checks)
    finally:
        if agent: agent.close()
        stop.set()
        thread.join(timeout=2)
        listener.close()
        report["finished_at"] = datetime.now(timezone.utc).isoformat()
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report), flush=True)
    if not report.get("passed"): raise SystemExit(1)


if __name__ == "__main__":
    main()
