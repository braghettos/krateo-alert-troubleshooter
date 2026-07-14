"""TroubleshootingReport v2 — the structured-investigation contract with the Autopilot agent.

Owns BOTH sides of the contract so they can't drift:
  * STRUCTURED_OUTPUT_INSTRUCTIONS — appended to the RCA prompt; requires the agent to end its
    answer with ONE fenced ```json block matching the v2 status fields.
  * parse_structured_report(text) — defensively extracts + sanitizes that block into the CR's
    status fields. NEVER raises: any malformed/missing JSON degrades to a prose-only (v1) report.

Sanitizing rules (defensive, latest-run-wins):
  * unknown keys are dropped; wrong-typed values are coerced when safe, else dropped;
  * sources[].type outside the enum falls back to "object" (evidence is kept, never lost);
  * reasoningTrace[].evidenceRefs are validated against len(sources): out-of-bounds/non-int
    indices are dropped (the step is kept — a step may legitimately lose a bad citation);
  * steps are renumbered 1..N in the order given (the agent's order is authoritative);
  * rootCause.confidence normalizes number-or-string to a "0.00"-style decimal string in [0,1];
  * remediationPlan[].payload must be a JSON object (the CRD preserves unknown fields there);
    observedOutcome is forced empty — it is filled post-apply by the remediation flow, not here.

Stdlib only (json/re) — unit-testable without the cluster or requests.
"""
import json
import re

TRIGGERS = ("alert", "composition-condition", "user-ask")
SOURCE_TYPES = ("logs", "events", "metrics", "object")
LIFECYCLES = ("open", "mitigated", "resolved")

# Every v2 key the handler writes under .status. The Ready patch always carries ALL of them
# (parsed value or None→JSON null, which merge-patch DELETES) so a re-run that fails to produce
# structure also clears the previous run's structure — no stale mixed-run investigation.
V2_STATUS_KEYS = ("analyzedResources", "sources", "missingContext", "assumptions",
                  "reasoningTrace", "rootCause", "remediationPlan")

STRUCTURED_OUTPUT_INSTRUCTIONS = """

After the markdown analysis, END your answer with EXACTLY ONE fenced ```json code block (no text
after it) containing a machine-readable summary of the SAME investigation, with these keys:

{
  "analyzedResources": [{"gvr": "apps/v1/deployments", "name": "...", "namespace": "...", "whatWasRead": "status + last events"}],
  "sources": [{"type": "logs|events|metrics|object", "ref": "where this evidence came from", "excerpt": "short verbatim excerpt"}],
  "missingContext": ["what you could NOT see"],
  "assumptions": ["what you assumed because of that"],
  "reasoningTrace": [{"step": 1, "statement": "...", "evidenceRefs": [0]}],
  "rootCause": {"statement": "...", "confidence": 0.85, "category": "config|capacity|image|network|dependency|other"},
  "remediationPlan": [{"description": "...", "verb": "patch|apply|delete|scale|restart", "gvr": "apps/v1/deployments", "target": {"name": "...", "namespace": "..."}, "payload": {}, "successCriterion": "how to verify it worked"}]
}

Hard rules for this block:
- analyzedResources/sources list ONLY what you actually read this run — never invent entries.
- missingContext and assumptions MUST be honest: if you could not read something you wanted
  (logs, metrics, an object, RBAC-denied, empty results), SAY SO there instead of papering over it.
- EVERY reasoningTrace step MUST cite evidence: evidenceRefs are 0-based indices into "sources",
  and every step needs at least one. A step you cannot back with a listed source belongs in
  "assumptions", not in the trace.
- confidence is 0 to 1. remediationPlan is a PLAN only — it will not be executed automatically;
  order the steps, and make each successCriterion independently checkable. Leave observed
  outcomes out; they are recorded later.
- Output STRICT JSON (double quotes, no comments, no trailing commas)."""

# Fence LINES (```lang or bare ```), walked as sequential open/close PAIRS. A single
# pairing regex mis-pairs when a non-json block precedes (a ```yaml example's CLOSING
# fence looks like a bare opener and swallows the prose up to the real ```json opener —
# seen live 2026-07-14: a full valid structured block was never extracted). The walker
# pairs fences in order and yields only blocks whose OPENER language is json/blank.
_FENCE_LINE_RE = re.compile(r"^```([A-Za-z0-9_-]*)[ \t]*\r?$", re.MULTILINE)


class _BlockSpan:
    """Minimal match-like span (start/end of the WHOLE fenced block, opener to closer)."""

    def __init__(self, start, end, body):
        self._start, self._end, self.body = start, end, body

    def start(self):
        return self._start

    def end(self):
        return self._end


def _fenced_blocks(text):
    """(span, body) for each properly PAIRED fenced block, in document order."""
    fences = list(_FENCE_LINE_RE.finditer(text))
    for i in range(0, len(fences) - 1, 2):
        opener, closer = fences[i], fences[i + 1]
        lang = (opener.group(1) or "").lower()
        body = text[opener.end():closer.start()].strip("\n")
        yield lang, _BlockSpan(opener.start(), closer.end(), body)


def _s(v, limit=4096):
    """A string, or None. Scalars are coerced; containers are rejected (never str(dict))."""
    if isinstance(v, str):
        v = v.strip()
        return v[:limit] if v else None
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return str(v)
    return None


def _str_list(v, limit=64):
    if not isinstance(v, list):
        return []
    return [s for s in (_s(x) for x in v[:limit]) if s]


def _obj(v, fields):
    """Pick the named string fields off a dict; None unless at least one is present."""
    if not isinstance(v, dict):
        return None
    out = {}
    for f in fields:
        s = _s(v.get(f))
        if s:
            out[f] = s
    return out or None


def _obj_list(v, fields, limit=64):
    if not isinstance(v, list):
        return []
    return [o for o in (_obj(x, fields) for x in v[:limit]) if o]


def _confidence(v):
    """Number-or-string 0..1 → clamped decimal string ("0.85"), else None."""
    if isinstance(v, bool):
        return None
    if isinstance(v, str):
        try:
            v = float(v.strip())
        except (ValueError, AttributeError):
            return None
    if not isinstance(v, (int, float)):
        return None
    return f"{min(max(float(v), 0.0), 1.0):.2f}".rstrip("0").rstrip(".") or "0"


def _sources(v):
    out = []
    if not isinstance(v, list):
        return out
    for x in v[:64]:
        o = _obj(x, ("ref", "excerpt"))
        if not o:
            continue
        t = _s(x.get("type")) if isinstance(x, dict) else None
        o["type"] = t if t in SOURCE_TYPES else "object"  # keep the evidence, sane the enum
        out.append(o)
    return out


def _trace(v, n_sources):
    """Ordered steps; drop step entries without a statement; drop out-of-bounds evidenceRefs;
    renumber 1..N in the given order (the order IS the trace)."""
    out = []
    if not isinstance(v, list):
        return out
    for x in v[:64]:
        if not isinstance(x, dict):
            continue
        stmt = _s(x.get("statement"))
        if not stmt:
            continue
        refs = x.get("evidenceRefs")
        good = []
        if isinstance(refs, list):
            for r in refs[:32]:
                if isinstance(r, bool):
                    continue
                if isinstance(r, float) and r.is_integer():
                    r = int(r)
                if isinstance(r, int) and 0 <= r < n_sources:
                    good.append(r)
        out.append({"step": len(out) + 1, "statement": stmt, "evidenceRefs": good})
    return out


def _root_cause(v):
    o = _obj(v, ("statement", "category"))
    if not o or "statement" not in o:
        return None
    conf = _confidence(v.get("confidence")) if isinstance(v, dict) else None
    if conf is not None:
        o["confidence"] = conf
    return o


def _plan(v):
    out = []
    if not isinstance(v, list):
        return out
    for x in v[:32]:
        o = _obj(x, ("description", "verb", "gvr", "successCriterion"))
        if not o or "description" not in o:
            continue
        target = _obj(x.get("target"), ("name", "namespace"))
        if target:
            o["target"] = target
        payload = x.get("payload")
        if isinstance(payload, dict) and payload:
            o["payload"] = payload  # CRD: object + x-kubernetes-preserve-unknown-fields
        o["observedOutcome"] = ""  # filled post-apply by the remediation flow, never here
        out.append(o)
    return out


def _candidate_blocks(text):
    """json/blank-language fenced blocks that parse as a JSON object mentioning ≥1 v2 key,
    best (last) first."""
    blocks = [(lang, span) for lang, span in _fenced_blocks(text) if lang in ("", "json")]
    for lang, span in reversed(blocks):
        try:
            data = json.loads(span.body)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(data, dict) and any(k in data for k in V2_STATUS_KEYS + ("rootCause",)):
            yield span, data


def parse_structured_report(text):
    """(prose, v2_status_fields) from the agent's raw answer. v2 is {} when no valid structured
    block exists (v1 fallback); prose is the answer with the block stripped (or the full answer
    on fallback). Never raises."""
    text = (text or "").strip()
    try:
        for match, data in _candidate_blocks(text):
            sources = _sources(data.get("sources"))
            v2 = {
                "analyzedResources": _obj_list(data.get("analyzedResources"),
                                               ("gvr", "name", "namespace", "whatWasRead")),
                "sources": sources,
                "missingContext": _str_list(data.get("missingContext")),
                "assumptions": _str_list(data.get("assumptions")),
                "reasoningTrace": _trace(data.get("reasoningTrace"), len(sources)),
                "rootCause": _root_cause(data.get("rootCause")),
                "remediationPlan": _plan(data.get("remediationPlan")),
            }
            if not any(v2.values()):
                continue  # a JSON block with the right keys but no usable content → keep looking
            prose = (text[:match.start()] + text[match.end():]).strip()
            if not prose:  # agent answered JSON-only; keep the report human-readable
                prose = (v2.get("rootCause") or {}).get("statement") or text
            return prose, {k: v for k, v in v2.items() if v}
    except Exception:  # noqa: BLE001 — the structured block is best-effort, never fatal
        pass
    return text, {}
