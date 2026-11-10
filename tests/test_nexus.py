"""End-to-end checks for the Python side. Run with: python3 -m unittest -v"""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from nexus import ai, calls
from nexus.agent import Agent, run_agent
from nexus.audit import AuditLog, verify
from nexus.detect import correlate, detect_anomalies
from nexus.investigate import Toolbox, investigate, validate
from nexus.simulate import NOW, simulate

WORLD = simulate(7)
ANOMALIES = detect_anomalies(WORLD)


NO_CALLS = {"anomalies": [], "cells": [], "overall": {"total": 0}, "parse": {}, "library_version": "test"}


def fresh_incident() -> dict:
    return correlate(WORLD, ANOMALIES)


class SimulatorTest(unittest.TestCase):
    def test_same_seed_same_world(self):
        self.assertEqual(simulate(7).metrics["CELL-101"], WORLD.metrics["CELL-101"])

    def test_rollback_stops_the_leak(self):
        fixed = simulate(7, rollback_minute=NOW)
        self.assertLess(fixed.metrics["CELL-101"]["memory_pct"][NOW + 30],
                        WORLD.metrics["CELL-101"]["memory_pct"][NOW + 30] - 20)


class DetectionTest(unittest.TestCase):
    def test_finds_the_bad_gateway_only(self):
        incident = fresh_incident()
        self.assertEqual(incident["node"], "pgw-1")
        self.assertEqual({a["cell"] for a in ANOMALIES}, {"CELL-101", "CELL-102", "CELL-103", "CELL-104"})
        self.assertEqual(incident["symptoms"][0]["metric"], "memory_pct")

    def test_decoy_deploy_is_ruled_out(self):
        excluded = " ".join(str(x) for x in fresh_incident()["excluded"])
        self.assertIn("pgw-3", excluded)

    def test_healthy_networks_open_no_incident(self):
        for seed in range(1, 11):
            world = simulate(seed, bad_deploy=False)
            self.assertIsNone(correlate(world, detect_anomalies(world)), f"seed {seed}")


class CallLibraryTest(unittest.TestCase):
    def test_c_library_flags_the_affected_cells(self):
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "calls.csv"
                WORLD.write_call_log(path, NOW - 60, NOW)
                result = calls.analyze(path)
        except calls.CallAnalyzerError as e:
            self.skipTest(str(e))
        self.assertEqual(result["parse"]["rejected"], 0)
        self.assertEqual({a["cell_id"] for a in result["anomalies"]},
                         {"CELL-101", "CELL-102", "CELL-103", "CELL-104"})


class InvestigationTest(unittest.TestCase):
    def test_offline_rca_cites_real_evidence(self):
        rca = investigate(WORLD, fresh_incident(), NO_CALLS)
        self.assertEqual(rca["cause_type"], "deployment_regression")
        ids = {e["id"] for e in rca["evidence"]}
        for fact in rca["facts"]:
            self.assertTrue(set(fact["evidence"]) <= ids)

    def test_made_up_citations_are_rejected(self):
        box = Toolbox(WORLD, fresh_incident(), NO_CALLS)
        box.run("list_deployments", {})
        answer = {"confidence": 0.99, "facts": [{"statement": "x", "evidence": ["E9"]}]}
        problems = validate(answer, box)
        self.assertTrue(any("does not exist" in p for p in problems))
        self.assertTrue(any("confidence" in p for p in problems))


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.rca = investigate(WORLD, fresh_incident(), NO_CALLS)

    def test_approved_agent_resolves_and_patches(self):
        incident, audit = fresh_incident(), AuditLog()
        result = run_agent(WORLD, incident, self.rca, audit, lambda tool, args: True)
        self.assertEqual(result["incident_status"], "resolved")
        self.assertTrue(result["recovery"]["recovered"])
        self.assertIn("+netparse==1.4.5", result["diff"])
        self.assertTrue(verify(audit.entries)[0])

    def test_denied_rollback_keeps_incident_open(self):
        incident = fresh_incident()
        result = run_agent(WORLD, incident, self.rca, AuditLog(), lambda tool, args: False)
        self.assertEqual(result["incident_status"], "open")
        self.assertIn("denied", {a.get("status") for a in result["actions"]})

    def test_policy_blocks_unknown_tools_and_early_resolve(self):
        agent = Agent(WORLD, fresh_incident(), self.rca, AuditLog(), lambda tool, args: True)
        text, is_error = agent.execute("run_shell", {"cmd": "rm -rf /"})
        self.assertTrue(is_error)
        self.assertEqual(agent.actions[-1]["status"], "blocked")
        _, is_error = agent.execute("finish", {"summary": "done", "incident_resolved": True})
        self.assertTrue(is_error)

    def test_downgrades_are_refused(self):
        agent = Agent(WORLD, fresh_incident(), self.rca, AuditLog(), lambda tool, args: True)
        _, is_error = agent.execute("upgrade_dependency", {"package": "netparse", "version": "1.0.0", "reason": "x"})
        self.assertTrue(is_error)


class AuditTest(unittest.TestCase):
    def test_tampering_breaks_the_chain(self):
        log = AuditLog()
        for i in range(5):
            log.record("agent", "step", n=i)
        self.assertTrue(verify(log.entries)[0])
        tampered = json.loads(json.dumps(log.entries))
        tampered[2]["details"]["n"] = 99
        self.assertEqual(verify(tampered), (False, "chain broken at entry 3"))


class FakeClient:
    """Stands in for anthropic.Anthropic(): replays scripted tool calls."""
    def __init__(self, turns):
        self.turns, self.requests = list(turns), []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    def create(self, **request):
        self.requests.append({**request, "messages": list(request["messages"])})
        blocks = [SimpleNamespace(type="tool_use", id=f"t{len(self.requests)}{i}", name=n, input=a)
                  for i, (n, a) in enumerate(self.turns.pop(0))]
        return SimpleNamespace(stop_reason="tool_use", content=blocks)


class ToolLoopTest(unittest.TestCase):
    def test_loop_feeds_errors_back_and_returns_finish_input(self):
        client = FakeClient([
            [("lookup", {"q": "a"})],
            [("finish", {"answer": "bad"})],
            [("finish", {"answer": "42"})],
        ])

        def execute(name, args):
            if name == "finish":
                return ("rejected", True) if args["answer"] == "bad" else ("accepted", False)
            return "result", False

        out = ai.run_tools("sys", "task", [ai.schema("lookup", "d", q={"type": "string"})], execute,
                           "finish", client=client)
        self.assertEqual(out, {"answer": "42"})
        self.assertEqual(len(client.requests), 3)
        last = client.requests[-1]["messages"][-1]["content"][0]
        self.assertTrue(last["is_error"])
        self.assertTrue(client.requests[0]["tools"][0]["strict"])


if __name__ == "__main__":
    unittest.main()
