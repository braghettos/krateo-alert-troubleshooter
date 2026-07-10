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


def create_report(alert_name, alert_ns, alert_state, alert_id, prompt):
    ns = alert_ns or NAMESPACE
    body = {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "TroubleshootingReport",
        "metadata": {"generateName": f"{_safe_name(alert_name)}-"},
        "spec": {"alertName": alert_name or "", "alertNamespace": ns, "alertState": alert_state or "ALERT",
                 "hyperdxAlertId": alert_id or "", "prompt": prompt, "triggeredAt": _now()},
    }
    obj = _k8s("POST", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}", body)
    name = obj["metadata"]["name"]
    patch_status(ns, name, {"phase": "Analyzing"})
    return ns, name


def patch_status(ns, name, status):
    _k8s("PATCH", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}/{name}", {"status": status}, subresource="status")


def _recent_report(alert_name, ns):
    """Dedup: True if a report for this alert is still Pending/Analyzing, or was created within
    REPORT_COOLDOWN seconds. Keeps a perpetually-breached alert from spawning a report every eval."""
    try:
        items = _k8s("GET", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}").get("items", [])
    except Exception:  # noqa: BLE001 — on a list error, don't block the report
        return False
    now = datetime.now(timezone.utc)
    for r in items:
        if (r.get("spec") or {}).get("alertName") != alert_name:
            continue
        if (r.get("status") or {}).get("phase") in ("Pending", "Analyzing"):
            return True
        ts = r.get("metadata", {}).get("creationTimestamp")
        try:
            if ts and (now - datetime.fromisoformat(ts.replace("Z", "+00:00"))).total_seconds() < REPORT_COOLDOWN:
                return True
        except ValueError:
            pass
    return False


def a2a_analyze(prompt):
    """POST JSON-RPC message/stream to the Autopilot A2A agent; accumulate the agent's text."""
    body = {"id": 1, "jsonrpc": "2.0", "method": "message/stream", "params": {"message": {
        "kind": "message", "messageId": str(uuid.uuid4()), "role": "user",
        "parts": [{"kind": "text", "text": prompt}]}}}
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


def build_prompt(alert_name, alert_state):
    return (
        f"A HyperDX observability alert \"{alert_name}\" has fired (state {alert_state}) on this "
        "Krateo PlatformOps cluster. Perform an END-TO-END troubleshooting root-cause analysis: "
        "inspect the platform's reconcile-failure rate, per-composition reconcile latency, the grouped "
        "error-log digest, recent error/warning logs, and pod resource pressure. Identify the single "
        "most likely root cause, name the affected composition(s) or component(s), and give concrete, "
        "ordered remediation steps. Be concise and actionable; use short markdown sections."
    )


def process(payload):
    # HyperDX webhook payload shape varies; extract best-effort.
    alert_name = (payload.get("alertName") or payload.get("title") or payload.get("name")
                  or (payload.get("alert") or {}).get("name") or "hyperdx-alert")
    alert_id = payload.get("id") or payload.get("alertId") or (payload.get("alert") or {}).get("id") or ""
    alert_state = payload.get("state") or payload.get("status") or "ALERT"
    alert_ns = payload.get("alertNamespace") or NAMESPACE
    prompt = build_prompt(alert_name, alert_state)
    # Dedup under a lock: skip if a report for this alert is in-flight or within the cooldown.
    with _create_lock:
        if _recent_report(alert_name, alert_ns):
            print(f"[dedup] recent/in-flight report for {alert_name!r}; skipping", flush=True)
            return
        ns, name = create_report(alert_name, alert_ns, alert_state, alert_id, prompt)
    try:
        report = a2a_analyze(prompt) or "_Autopilot returned no analysis._"
        patch_status(ns, name, {"phase": "Ready", "report": report, "completedAt": _now()})
        print(f"[ok] report {ns}/{name} ready ({len(report)} chars)", flush=True)
    except Exception as e:  # noqa: BLE001 — record the failure on the CR
        patch_status(ns, name, {"phase": "Failed", "error": str(e)[:500], "completedAt": _now()})
        print(f"[err] report {ns}/{name} failed: {e}", flush=True)


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
