"""Unit tests for the TroubleshootingReport v2 structured-report contract (report_v2.py)
plus the thin handler-side wiring. Stdlib unittest; no cluster, no network.

Run from the repo root:  python3 -m unittest discover -s tests -v
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import report_v2
from report_v2 import parse_structured_report

PROSE = "## Root cause\nThe deployment is crash-looping.\n\n## Remediation\nFix the image tag."

VALID_BLOCK = {
    "analyzedResources": [
        {"gvr": "apps/v1/deployments", "name": "payment-api", "namespace": "prod",
         "whatWasRead": "status + last 10 events"},
    ],
    "sources": [
        {"type": "logs", "ref": "hyperdx: body:CrashLoopBackOff", "excerpt": "Back-off restarting failed container"},
        {"type": "events", "ref": "prod/payment-api", "excerpt": "Failed to pull image \"payment:v9\""},
    ],
    "missingContext": ["No metrics retention beyond 1h"],
    "assumptions": ["The registry outage seen at 09:00 is over"],
    "reasoningTrace": [
        {"step": 1, "statement": "Pods crash-loop on image pull", "evidenceRefs": [0, 1]},
        {"step": 2, "statement": "Tag v9 does not exist in the registry", "evidenceRefs": [1]},
    ],
    "rootCause": {"statement": "Bad image tag v9", "confidence": 0.85, "category": "image"},
    "remediationPlan": [
        {"description": "Point the deployment back to v8", "verb": "patch",
         "gvr": "apps/v1/deployments", "target": {"name": "payment-api", "namespace": "prod"},
         "payload": {"spec": {"template": {"spec": {"containers": [{"name": "api", "image": "payment:v8"}]}}}},
         "successCriterion": "deployment Available=True, restarts stop"},
    ],
}


def answer(block, prose=PROSE, fence="json"):
    return f"{prose}\n\n```{fence}\n{json.dumps(block, indent=1)}\n```"


class TestValidV2(unittest.TestCase):
    def test_full_valid_block(self):
        prose, v2 = parse_structured_report(answer(VALID_BLOCK))
        self.assertEqual(prose, PROSE)                      # block stripped from the prose
        self.assertNotIn("```", prose)
        self.assertEqual(v2["analyzedResources"][0]["gvr"], "apps/v1/deployments")
        self.assertEqual([s["type"] for s in v2["sources"]], ["logs", "events"])
        self.assertEqual(v2["missingContext"], ["No metrics retention beyond 1h"])
        self.assertEqual(v2["assumptions"], ["The registry outage seen at 09:00 is over"])
        self.assertEqual(v2["reasoningTrace"][0]["evidenceRefs"], [0, 1])
        self.assertEqual(v2["rootCause"],
                         {"statement": "Bad image tag v9", "category": "image", "confidence": "0.85"})
        plan = v2["remediationPlan"][0]
        self.assertEqual(plan["verb"], "patch")
        self.assertEqual(plan["target"], {"name": "payment-api", "namespace": "prod"})
        self.assertIn("payload", plan)
        self.assertEqual(plan["observedOutcome"], "")       # ALWAYS empty pre-apply

    def test_unfenced_json_tag_still_parses(self):
        prose, v2 = parse_structured_report(answer(VALID_BLOCK, fence=""))  # bare ``` fence
        self.assertEqual(prose, PROSE)
        self.assertTrue(v2)

    def test_last_valid_block_wins(self):
        first = answer({"rootCause": {"statement": "early draft", "confidence": 0.2}}, prose="Draft.")
        text = first + "\n\nFinal answer.\n" + answer(VALID_BLOCK, prose="")
        _, v2 = parse_structured_report(text)
        self.assertEqual(v2["rootCause"]["statement"], "Bad image tag v9")

    def test_json_only_answer_keeps_report_readable(self):
        prose, v2 = parse_structured_report(answer(VALID_BLOCK, prose=""))
        self.assertEqual(prose, "Bad image tag v9")         # falls back to the root-cause statement
        self.assertTrue(v2)

    def test_observed_outcome_from_agent_is_discarded(self):
        block = json.loads(json.dumps(VALID_BLOCK))
        block["remediationPlan"][0]["observedOutcome"] = "I already fixed it"  # it must NOT claim this
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual(v2["remediationPlan"][0]["observedOutcome"], "")


class TestFallbacks(unittest.TestCase):
    def test_v1_prose_only(self):
        prose, v2 = parse_structured_report(PROSE)
        self.assertEqual(prose, PROSE)
        self.assertEqual(v2, {})

    def test_malformed_json_falls_back_to_prose(self):
        text = PROSE + '\n```json\n{"rootCause": {"statement": "x", }\n```'  # trailing comma + unclosed
        prose, v2 = parse_structured_report(text)
        self.assertEqual(prose, text)                       # full text kept, nothing lost
        self.assertEqual(v2, {})

    def test_json_block_without_v2_keys_ignored(self):
        text = PROSE + '\n```json\n{"foo": 1}\n```'
        prose, v2 = parse_structured_report(text)
        self.assertEqual((prose, v2), (text, {}))

    def test_empty_and_none_input(self):
        self.assertEqual(parse_structured_report(""), ("", {}))
        self.assertEqual(parse_structured_report(None), ("", {}))

    def test_never_raises_on_garbage_shapes(self):
        garbage = {"sources": "not-a-list", "reasoningTrace": {"step": 1}, "rootCause": ["x"],
                   "remediationPlan": 42, "missingContext": {"a": 1}, "assumptions": [{}],
                   "analyzedResources": [None, 3, "x"]}
        text = answer(garbage)
        prose, v2 = parse_structured_report(text)
        self.assertEqual(v2, {})                            # right keys, no usable content → v1
        self.assertEqual(prose, text)


class TestEvidenceRefs(unittest.TestCase):
    def test_out_of_bounds_refs_dropped_step_kept(self):
        block = {"sources": [{"type": "logs", "ref": "q", "excerpt": "e"}],
                 "reasoningTrace": [{"step": 1, "statement": "ok", "evidenceRefs": [0, 1, -1, 99]}],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual(v2["reasoningTrace"][0]["evidenceRefs"], [0])

    def test_non_int_refs_dropped_float_int_coerced(self):
        block = {"sources": [{"ref": "a", "excerpt": "x"}, {"ref": "b", "excerpt": "y"}],
                 "reasoningTrace": [{"statement": "s", "evidenceRefs": [1.0, "0", True, None, 0.5]}],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual(v2["reasoningTrace"][0]["evidenceRefs"], [1])  # 1.0→1; "0"/True/None/0.5 dropped

    def test_no_sources_means_no_valid_refs(self):
        block = {"reasoningTrace": [{"statement": "s", "evidenceRefs": [0]}],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual(v2["reasoningTrace"][0]["evidenceRefs"], [])

    def test_steps_renumbered_in_order_and_unstated_dropped(self):
        block = {"sources": [{"ref": "a", "excerpt": "x"}],
                 "reasoningTrace": [{"step": 7, "statement": "first"}, {"step": 2},
                                    {"step": "n/a", "statement": "second", "evidenceRefs": [0]}],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual([(t["step"], t["statement"]) for t in v2["reasoningTrace"]],
                         [(1, "first"), (2, "second")])


class TestSanitizers(unittest.TestCase):
    def test_confidence_normalization(self):
        for raw, want in [(0.85, "0.85"), ("0.7", "0.7"), (1, "1"), (1.5, "1"), (-3, "0"),
                          (0, "0"), ("abc", None), (None, None), (True, None)]:
            self.assertEqual(report_v2._confidence(raw), want, f"confidence({raw!r})")

    def test_source_type_outside_enum_becomes_object(self):
        block = {"sources": [{"type": "trace", "ref": "r", "excerpt": "e"}, "junk",
                             {"type": "metrics", "ref": "cpu", "excerpt": "97%"}],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual([s["type"] for s in v2["sources"]], ["object", "metrics"])

    def test_root_cause_requires_statement(self):
        block = {"rootCause": {"confidence": 0.9, "category": "config"},
                 "missingContext": ["kept so the block is non-empty"]}
        _, v2 = parse_structured_report(answer(block))
        self.assertNotIn("rootCause", v2)
        self.assertEqual(v2["missingContext"], ["kept so the block is non-empty"])

    def test_plan_requires_description_and_dict_payload(self):
        block = {"remediationPlan": [
                     {"verb": "delete"},                                   # no description → dropped
                     {"description": "restart", "payload": "not-a-dict"},  # payload dropped, step kept
                 ],
                 "rootCause": {"statement": "x"}}
        _, v2 = parse_structured_report(answer(block))
        self.assertEqual(len(v2["remediationPlan"]), 1)
        self.assertNotIn("payload", v2["remediationPlan"][0])


class TestHandlerWiring(unittest.TestCase):
    """The thin handler-side pieces: prompt carries the contract; the CR gets trigger=alert."""

    def _handler(self):
        import handler  # imports requests; safe — the server only starts under __main__
        return handler

    def test_prompt_requires_structured_block(self):
        h = self._handler()
        p = h.build_prompt("err-logs", "ALERT", where="body:ERROR", message="errors spiking")
        self.assertIn("```json", p)
        self.assertIn("missingContext", p)
        self.assertIn("MUST be honest", p)
        self.assertIn("0-based indices into \"sources\"", p)
        self.assertTrue(p.rstrip().endswith("no trailing commas)."))

    def test_upsert_sets_trigger_alert_on_create_and_patch(self):
        h = self._handler()
        calls = []
        orig = h._k8s
        h._k8s = lambda method, path, body=None, subresource="": calls.append((method, body)) or {}
        try:
            h._upsert_report("ns", "report-x", "x", "ALERT", "id", "prompt", "now", existing=None)
            h._upsert_report("ns", "report-x", "x", "ALERT", "id", "prompt", "now",
                             existing={"metadata": {"annotations": {}}})
        finally:
            h._k8s = orig
        create = next(b for m, b in calls if m == "POST")
        patch = next(b for m, b in calls if m == "PATCH" and b and "spec" in b)
        self.assertEqual(create["spec"]["trigger"], "alert")
        self.assertEqual(patch["spec"]["trigger"], "alert")


if __name__ == "__main__":
    unittest.main()


class TestYamlThenJsonFixture(unittest.TestCase):
    """Regression: a ```yaml example BEFORE the ```json block must not break extraction
    (live 2026-07-14: the yaml closer mis-paired as a json opener; the valid structured
    block was never parsed)."""

    def test_live_reply_with_yaml_block_parses_structured(self):
        import os
        fixture = os.path.join(os.path.dirname(__file__), "fixtures", "reply_yaml_then_json.txt")
        with open(fixture) as f:
            raw = f.read()
        prose, v2 = report_v2.parse_structured_report(raw)
        self.assertTrue(v2, "structured block must parse")
        self.assertTrue((v2.get("rootCause") or {}).get("statement"))
        self.assertTrue(v2.get("remediationPlan"))
        # the yaml example stays in the prose; the json block is stripped
        self.assertIn("```yaml", prose)
        self.assertNotIn('"remediationPlan"', prose)
