#!/usr/bin/env python3
"""krateo-alert-troubleshooter — bridges a HyperDX alert webhook to an Autopilot root-cause analysis.

On POST /webhook (HyperDX alert-fired payload):
  1. create a TroubleshootingReport CR (phase=Analyzing) via the apiserver,
  2. call the krateo-autopilot A2A agent (JSON-RPC message/stream) with a troubleshooting prompt,
  3. accumulate the streamed analysis and patch the CR status (phase=Ready, report=<markdown>).

Runs anyone's-browser-independent: this is the "background" path. Minimal deps: stdlib + requests.
"""
import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

import report_v2  # the structured-report (v2) contract: prompt instructions + defensive parser

# --- config (env, with in-cluster defaults) ---
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
AUTOPILOT_A2A = os.environ.get("AUTOPILOT_A2A_URL", "http://krateo-autopilot.krateo-system.svc:8080/")
APISERVER = os.environ.get("APISERVER", "https://kubernetes.default.svc")
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
GROUP, VERSION, PLURAL = "observability.krateo.io", "v1alpha1", "troubleshootingreports"
A2A_TIMEOUT = int(os.environ.get("A2A_TIMEOUT", "180"))
# HyperDX notifies every eval while an alert stays breached; dedup so we don't spam a new report
# each interval. Skip if one for the same alert is in-flight, or was created within this window.
REPORT_COOLDOWN = int(os.environ.get("REPORT_COOLDOWN", "1800"))
# The per-alert kagent A2A thread is continued (same contextId) across re-runs for rail/deep-link
# continuity, but each re-run forces a COMPLETE fresh RCA (build_prompt rerun=True) that re-pulls ALL
# telemetry (logs + k8s dumps) into that ONE thread. Over many fires the thread's accumulated
# tool-call history grows without bound and eventually overflows the model's input-token window
# (seen live 2026-07-16: 95 runs on one thread -> 1,097,807 tokens > Gemini's 1,048,576 limit -> the
# provider 400s and the RCA can no longer run at all). So the thread is ROTATED every
# CONTEXT_MAX_RUNS runs: the contextId is keyed on a run-count "epoch", so after this many runs a
# fresh empty thread opens and the accumulated context resets. Continuity is preserved within a
# window; no analysis quality is lost across a rotation because the next run re-derives everything
# from scratch anyway. At a conservative ~15k tokens of telemetry per run, 10 runs ~= 150k tokens --
# an order of magnitude under the limit, with ample headroom for a verbose run.
CONTEXT_MAX_RUNS = max(1, int(os.environ.get("CONTEXT_MAX_RUNS", "10")))

_create_lock = threading.Lock()  # serialize the dedup-check + create so simultaneous fires don't race


def _now():
    return datetime.now(timezone.utc).isoformat()


def _sa_token():
    with open(f"{SA_DIR}/token") as f:
        return f.read().strip()


def _k8s(method, path, body=None, subresource=""):
    """Call the apiserver with the mounted SA token."""
    url = f"{APISERVER}{path}"
    if subresource:
        url += f"/{subresource}"
    headers = {"Authorization": f"Bearer {_sa_token()}", "Content-Type": "application/json"}
    if method == "PATCH":
        headers["Content-Type"] = "application/merge-patch+json"
    r = requests.request(method, url, headers=headers, data=json.dumps(body) if body else None,
                         verify=f"{SA_DIR}/ca.crt", timeout=30)
    r.raise_for_status()
    return r.json()


def _safe_name(s):
    """A valid metadata.generateName prefix: lowercase alnum + '-', from an arbitrary alert title
    (which may carry spaces, colons, em-dashes, …). k8s 422s on anything else."""
    slug = re.sub(r"[^a-z0-9-]+", "-", (s or "alert").lower()).strip("-")[:40].strip("-")
    return slug or "alert"


RUN_COUNT_ANNO = "observability.krateo.io/run-count"
FIRST_RUN_ANNO = "observability.krateo.io/first-run-at"
LAST_RUN_ANNO = "observability.krateo.io/last-run-at"
CONTEXT_ID_ANNO = "observability.krateo.io/context-id"


def _stable_name(alert_name):
    """One DETERMINISTIC report CR per alert (upserted), so a re-firing alert bumps a run-count on
    the SAME report instead of piling up a new near-identical report every cooldown window."""
    return f"report-{_safe_name(alert_name)}"[:63].rstrip("-")


def _context_id(alert_name, run_count=0):
    """A DETERMINISTIC A2A contextId per alert (uuid5 of the stable report name + a run-count epoch),
    so RCA runs of the SAME alert continue ONE kagent conversation thread for rail/deep-link
    continuity — but that thread is ROTATED every CONTEXT_MAX_RUNS runs so its accumulated telemetry
    can never overflow the model's input-token window. Two DIFFERENT alerts get two distinct threads;
    the same alert gets a fresh thread each epoch. Deterministic + stable across restarts (the epoch
    is derived from the report's persisted run-count, not from process state).

    run_count is the count of THIS run (1-based). Epoch = (run_count - 1) // CONTEXT_MAX_RUNS, so
    runs 1..N share epoch 0, runs N+1..2N share epoch 1, etc. — each epoch a clean, empty thread."""
    epoch = max(0, (int(run_count) - 1)) // CONTEXT_MAX_RUNS
    seed = _stable_name(alert_name) if epoch == 0 else f"{_stable_name(alert_name)}#e{epoch}"
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, seed))


def _get_report(ns, name):
    try:
        return _k8s("GET", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}/{name}")
    except requests.HTTPError as e:
        if getattr(getattr(e, "response", None), "status_code", None) == 404:
            return None
        raise


def _next_run_count(existing):
    """The 1-based count of the run about to start: previous run-count + 1, or 1 for a first-ever
    report. Kept consistent with the increment in _upsert_report so the rotated contextId's epoch
    matches the run-count the report is stamped with."""
    if existing is None:
        return 1
    anns = (existing.get("metadata") or {}).get("annotations") or {}
    try:
        return int(anns.get(RUN_COUNT_ANNO, "0")) + 1
    except (ValueError, TypeError):
        return 1


def _upsert_report(ns, name, alert_name, alert_state, alert_id, prompt, now, existing, context_id=""):
    """Create the alert's report (run-count=1) or bump the existing one (run-count++, last-run=now),
    setting phase=Analyzing. Run info + the per-alert kagent context id live in annotations — no
    TroubleshootingReport CRD change."""
    if existing is None:
        body = {
            "apiVersion": f"{GROUP}/{VERSION}", "kind": "TroubleshootingReport",
            "metadata": {"name": name,
                         "annotations": {RUN_COUNT_ANNO: "1", FIRST_RUN_ANNO: now, LAST_RUN_ANNO: now,
                                         CONTEXT_ID_ANNO: context_id}},
            "spec": {"alertName": alert_name or "", "alertNamespace": ns, "alertState": alert_state or "ALERT",
                     "trigger": "alert",  # this flow IS the alert entry point (v2 enum)
                     "hyperdxAlertId": alert_id or "", "prompt": prompt, "triggeredAt": now},
        }
        _k8s("POST", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}", body)
    else:
        anns = (existing.get("metadata") or {}).get("annotations") or {}
        try:
            count = int(anns.get(RUN_COUNT_ANNO, "0")) + 1
        except (ValueError, TypeError):
            count = 1
        _k8s("PATCH", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}/{name}",
             {"metadata": {"annotations": {RUN_COUNT_ANNO: str(count), LAST_RUN_ANNO: now,
                                           CONTEXT_ID_ANNO: context_id}},
              "spec": {"alertState": alert_state or "ALERT", "trigger": "alert", "triggeredAt": now}})
    patch_status(ns, name, {"phase": "Analyzing"})


def patch_status(ns, name, status):
    _k8s("PATCH", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}/{name}", {"status": status}, subresource="status")


def _within_cooldown(report):
    """Dedup: True if this alert's report is mid-analysis, or was last run within REPORT_COOLDOWN —
    so a perpetually-breached alert re-analyzes at most once per window (bumping its run-count then)."""
    if not report:
        return False
    if ((report.get("status") or {}).get("phase")) in ("Pending", "Analyzing"):
        return True
    anns = (report.get("metadata") or {}).get("annotations") or {}
    ts = anns.get(LAST_RUN_ANNO) or (report.get("metadata") or {}).get("creationTimestamp")
    try:
        if ts and (datetime.now(timezone.utc) - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds() < REPORT_COOLDOWN:
            return True
    except (ValueError, AttributeError):
        pass
    return False


def _alert_where(alert_name, ns):
    """Look up the fired Alert CR (observability.krateo.io) matching the webhook alertName, to SCOPE
    the RCA to what actually tripped: its `spec.where` query + `message`. Match on the alphanumeric
    core — the HyperDX alert title may carry an emoji/prefix the CR displayName doesn't."""
    def norm(s):
        return re.sub(r"[^a-z0-9]+", "", (s or "").lower())
    target = norm(alert_name)
    if not target:
        return None, None
    try:
        alerts = _k8s("GET", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/alerts").get("items", [])
    except Exception:  # noqa: BLE001 — best-effort; fall back to an unscoped prompt
        return None, None
    for a in alerts:
        spec = a.get("spec") or {}
        disp = norm(spec.get("displayName") or (a.get("metadata") or {}).get("name", ""))
        if disp and (disp in target or target in disp):
            return spec.get("where"), spec.get("message")
    return None, None


def a2a_analyze(prompt, context_id=None):
    """POST JSON-RPC message/stream to the Autopilot A2A agent; accumulate the agent's text.
    A stable `context_id` continues ONE kagent thread across re-runs of the same alert (omitted =
    a fresh thread)."""
    message = {"kind": "message", "messageId": str(uuid.uuid4()), "role": "user",
               "parts": [{"kind": "text", "text": prompt}]}
    if context_id:
        message["contextId"] = context_id
    body = {"id": 1, "jsonrpc": "2.0", "method": "message/stream", "params": {"message": message}}
    out = ""
    with requests.post(AUTOPILOT_A2A, json=body, stream=True, timeout=A2A_TIMEOUT,
                       headers={"Accept": "text/event-stream", "Content-Type": "application/json"}) as resp:
        resp.raise_for_status()
        for raw in resp.iter_lines(decode_unicode=True):
            if not raw or not raw.startswith("data:"):
                continue
            try:
                payload = json.loads(raw[len("data:"):].strip())
            except json.JSONDecodeError:
                continue
            result = payload.get("result") or {}
            msg = result.get("status", {}).get("message") or result.get("message") or {}
            if msg.get("role") != "agent":
                continue
            text = "".join(p["text"] for p in msg.get("parts", [])
                           if p.get("kind") == "text" and p.get("text"))
            if not text:
                continue
            # kagent's A2A stream re-sends cumulative snapshots of the message (and repeats the
            # final one), so blindly appending every event duplicated the whole report. Replace
            # when the new text extends what we already have (a snapshot), skip an exact-duplicate
            # tail, else append (a genuine delta) — correct for snapshot-, delta-, and repeat streams.
            if text.startswith(out):
                out = text
            elif not out.endswith(text):
                out += text
    return out.strip()


def build_prompt(alert_name, alert_state, where=None, message=None, rerun=False):
    # RE-RUNS: the stable per-alert kagent thread makes the agent 'remember' its previous
    # answer and short-circuit ('I already analyzed this') — which parses to NOTHING and
    # starves re-analysis (seen live 2026-07-14: every post-first run returned 0 chars).
    # Force a complete fresh pass while keeping the thread (rail continuity).
    rerun_preamble = ""
    if rerun:
        rerun_preamble = (
            "RE-ANALYSIS REQUEST: this alert has fired again. Do NOT refer to, summarize, or "
            "defer to your previous answers in this conversation. Re-verify against the CURRENT "
            "cluster and telemetry state from scratch, and output the COMPLETE analysis again — "
            "including the full structured JSON block — as if this were the first request.\n\n"
        )
    scope = ""
    if where:
        scope = (
            f"\n\nThis alert fired because log records matched the query `{where}`"
            + (f" (intent: {message})" if message else "")
            + ". Those SPECIFIC matching logs are what tripped it. ROOT-CAUSE THAT signal:\n"
            "1. Find the matching logs by their BODY as the query specifies — do NOT additionally "
            "require a severity level (this pipeline often leaves SeverityText empty, so a severity "
            "filter will wrongly return nothing) — to see WHICH workload/namespace emits them.\n"
            "2. Then inspect THAT workload's Kubernetes state directly (k8s_get_resources): pod status "
            "and recent events — CrashLoopBackOff, OOMKilled, restart counts, connection errors. The "
            "workload's k8s state is AUTHORITATIVE even when the logs are hard to query.\n"
            "Diagnose the workload this alert points at. Do NOT substitute a different, louder problem "
            "elsewhere on the cluster. Only if you can determine NEITHER the matching logs NOR the "
            "workload's k8s state should you say you cannot find the cause."
        )
    return rerun_preamble + (
        f"A HyperDX observability alert \"{alert_name}\" has fired (state {alert_state}) on this "
        "Krateo PlatformOps cluster." + scope +
        "\n\nPerform a focused root-cause analysis of what triggered THIS alert: identify the single "
        "most likely root cause, name the affected composition(s)/component(s), and give concrete, "
        "ordered remediation steps. Be concise and actionable; use short markdown sections."
        + report_v2.STRUCTURED_OUTPUT_INSTRUCTIONS
    )


def process(payload):
    # HyperDX webhook payload shape varies; extract best-effort.
    alert_name = (payload.get("alertName") or payload.get("title") or payload.get("name")
                  or (payload.get("alert") or {}).get("name") or "hyperdx-alert")
    alert_id = payload.get("id") or payload.get("alertId") or (payload.get("alert") or {}).get("id") or ""
    alert_state = payload.get("state") or payload.get("status") or "ALERT"
    alert_ns = payload.get("alertNamespace") or NAMESPACE
    where, message = _alert_where(alert_name, alert_ns)  # scope the RCA to what actually tripped
    prompt = None  # built after the dedup gate, when we know if this is a re-run
    name = _stable_name(alert_name)
    now = _now()
    # One report CR per alert, upserted under a lock: re-fires within the cooldown are skipped;
    # otherwise the same CR is re-analyzed and its run-count bumped — no pile-up of duplicate reports.
    with _create_lock:
        existing = _get_report(alert_ns, name)
        if _within_cooldown(existing):
            print(f"[dedup] {alert_name!r} analyzed recently / in-flight; skipping", flush=True)
            return
        # THIS run's 1-based count = previous run-count + 1 (1 for a first-ever report). The kagent
        # thread is keyed on it so the thread rotates every CONTEXT_MAX_RUNS runs — bounding the
        # accumulated telemetry well under the model's input-token limit.
        run_count = _next_run_count(existing)
        ctx = _context_id(alert_name, run_count)  # per-alert thread, rotated every CONTEXT_MAX_RUNS
        prompt = build_prompt(alert_name, alert_state, where, message, rerun=bool(existing))
        _upsert_report(alert_ns, name, alert_name, alert_state, alert_id, prompt, now, existing, ctx)
    try:
        raw = a2a_analyze(prompt, ctx)
        # v2: split the answer into prose + the structured investigation. Parsing is defensive —
        # a missing/malformed JSON block degrades to a prose-only (v1) report, never a crash.
        print(f"[a2a] raw reply: {len(raw)} chars", flush=True)
        prose, v2 = report_v2.parse_structured_report(raw)
        # KEEP-LAST-GOOD: an EMPTY analysis (no prose AND no structure) is a FAILED run, not a
        # result — never let it overwrite a previous good investigation (seen live 2026-07-14:
        # an empty A2A reply wiped a full structured RCA to "Autopilot returned no analysis").
        # Record the failed re-run on the CR without touching report/v2 fields.
        if not prose.strip() and not v2:
            existing_now = _get_report(alert_ns, name) or {}
            had_analysis = bool(((existing_now.get("status") or {}).get("report") or "").strip()) \
                or bool((existing_now.get("status") or {}).get("rootCause"))
            if had_analysis:
                patch_status(alert_ns, name, {"phase": "Ready",
                                              "error": f"re-analysis at {_now()} returned no output; kept previous analysis"})
                print(f"[warn] report {alert_ns}/{name}: empty analysis — kept previous (keep-last-good)", flush=True)
                return
        status = {"phase": "Ready", "report": prose or "_Autopilot returned no analysis._",
                  "completedAt": _now(), "lifecycle": "open", "auditRecordRefs": []}
        # Latest-run-wins: ALWAYS send every v2 key — parsed value, or None (JSON null, which
        # merge-patch DELETES) so a re-run that lost structure also clears the stale previous one.
        for k in report_v2.V2_STATUS_KEYS:
            status[k] = v2.get(k)
        patch_status(alert_ns, name, status)
        print(f"[ok] report {alert_ns}/{name} ready ({len(prose)} chars prose, "
              f"structured={'yes' if v2 else 'no'})", flush=True)
    except Exception as e:  # noqa: BLE001 — record the failure on the CR
        patch_status(alert_ns, name, {"phase": "Failed", "error": str(e)[:500], "completedAt": _now()})
        print(f"[err] report {alert_ns}/{name} failed: {e}", flush=True)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # health
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()
        self.wfile.write(b"ok" if self.path == "/healthz" else b"")

    def do_POST(self):
        # Accept any POST path as a webhook: HyperDX redacts the webhook URL path to `/****` in
        # its API and may deliver to a redacted/normalised path, so we don't gate on "/webhook".
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        print(f"[webhook] POST {self.path} ({length}B)", flush=True)  # observe the delivered path
        try:
            payload = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            payload = {"raw": raw.decode("utf-8", "replace")}
        # Ack fast; analyse in the background so HyperDX's webhook doesn't time out.
        threading.Thread(target=process, args=(payload,), daemon=True).start()
        self.send_response(202); self.end_headers(); self.wfile.write(b"accepted")

    def log_message(self, *args):  # quieter logs
        pass


if __name__ == "__main__":
    # Background: reconcile Alert CRs -> HyperDX (config + status) via the session API.
    if os.environ.get("RECONCILER_ENABLED", "true").lower() == "true":
        import reconciler  # imported here so the webhook path has no hard dep on it
        threading.Thread(target=reconciler.run_forever, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"krateo-alert-troubleshooter listening on :{port} → A2A {AUTOPILOT_A2A}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
