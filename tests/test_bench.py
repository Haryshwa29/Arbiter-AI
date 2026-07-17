"""Flood benchmark (bench.py): stream synthesis, queue math, dedup projection."""

import unittest

from arbiter.bench import (BenchReport, BenchRow, run_bench, simulate_queue,
                           synth_flood)
from arbiter.schema import Decision, Tier


class SynthTests(unittest.TestCase):
    def test_deterministic_and_needles_present(self):
        a = synth_flood(50, 10, seed=7)
        b = synth_flood(50, 10, seed=7)
        self.assertEqual([e.message for e in a], [e.message for e in b])
        types = [e.event_type for e in a]
        self.assertIn("user_created", types)   # rail-visible needle
        self.assertIn("file_change", types)    # LLM-tier needle
        self.assertEqual(len(a), 500)


class QueueTests(unittest.TestCase):
    def test_fifo_backlog_and_delay(self):
        # 3 events arriving 1s apart, each taking 2s: classic growing queue.
        # depth counts events still in the system AHEAD of an arrival:
        # at t=1, event0 is still running -> depth 1; at t=2, event0 just
        # finished and event1 runs -> still 1.
        in_system, depth, drain = simulate_queue([0.0, 1.0, 2.0],
                                                 [2.0, 2.0, 2.0])
        self.assertEqual(in_system, [2.0, 3.0, 4.0])
        self.assertEqual(drain, 6.0)
        self.assertEqual(depth, 1)

    def test_idle_server_never_queues(self):
        in_system, depth, _ = simulate_queue([0.0, 10.0], [1.0, 1.0])
        self.assertEqual(in_system, [1.0, 1.0])
        self.assertEqual(depth, 0)


class DedupTests(unittest.TestCase):
    def _rows(self):
        return [BenchRow(arrival=float(i), signature="a:b:c", tier=Tier.LLM,
                         decision=Decision.ESCALATE, pipeline_s=0.001)
                for i in range(10)]

    def test_dedup_collapses_repeated_signature(self):
        r = BenchReport(rate=1, duration=10, llm_latency=4.0, rows=self._rows())
        as_is = r._services(None)
        dedup = r._services(60.0)
        self.assertEqual(sum(1 for s in as_is if s > 0.001), 10)
        self.assertEqual(sum(1 for s in dedup if s > 0.001), 1)

    def test_dedup_window_expiry_recalls_the_model(self):
        r = BenchReport(rate=1, duration=10, llm_latency=4.0, rows=self._rows())
        dedup = r._services(4.5)   # window shorter than the stream
        self.assertEqual(sum(1 for s in dedup if s > 0.001), 2)


class EndToEndTests(unittest.TestCase):
    def test_flood_is_decided_by_code_not_model(self):
        report = run_bench(rate=50, duration=4, backend_name="mock",
                           model="", llm_latency=4.1)
        flood = [r for r in report.rows
                 if r.signature.startswith("netflow:syn_flood")]
        self.assertTrue(flood)
        self.assertTrue(all(r.tier is not Tier.LLM for r in flood))
        self.assertTrue(all(r.decision is Decision.ESCALATE for r in flood))
        # Needles escalate whatever the load.
        needles = {r.needle: r for r in report.rows if r.needle}
        self.assertEqual(set(needles), {"user_created", "file_change"})
        for r in needles.values():
            self.assertIs(r.decision, Decision.ESCALATE)


if __name__ == "__main__":
    unittest.main()
