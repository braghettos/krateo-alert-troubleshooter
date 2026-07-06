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


def create_report(alert_name, alert_ns, alert_state, alert_id, prompt):
    ns = alert_ns or NAMESPACE
    body = {
        "apiVersion": f"{GROUP}/{VERSION}", "kind": "TroubleshootingReport",
        "metadata": {"generateName": f"{(alert_name or 'alert')[:40]}-".lower().replace('_', '-')},
        "spec": {"alertName": alert_name or "", "alertNamespace": ns, "alertState": alert_state or "ALERT",
                 "hyperdxAlertId": alert_id or "", "prompt": prompt, "triggeredAt": _now()},
    }
    obj = _k8s("POST", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}", body)
    name = obj["metadata"]["name"]
    patch_status(ns, name, {"phase": "Analyzing"})
    return ns, name


def patch_status(ns, name, status):
    _k8s("PATCH", f"/apis/{GROUP}/{VERSION}/namespaces/{ns}/{PLURAL}/{name}", {"status": status}, subresource="status")


def a2a_analyze(prompt):
    """POST JSON-RPC message/stream to the Autopilot A2A agent; accumulate the agent's text."""
    body = {"id": 1, "jsonrpc": "2.0", "method": "message/stream", "params": {"message": {
        "kind": "message", "messageId": str(uuid.uuid4()), "role": "user",
        "parts": [{"kind": "text", "text": prompt}]}}}
    out = []
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
            if msg.get("role") == "agent":
                for part in msg.get("parts", []):
                    if part.get("kind") == "text" and part.get("text"):
                        out.append(part["text"])
    return "".join(out).strip()


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
        if self.path != "/webhook":
            self.send_response(404); self.end_headers(); return
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
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
    port = int(os.environ.get("PORT", "8080"))
    print(f"krateo-alert-troubleshooter listening on :{port} → A2A {AUTOPILOT_A2A}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
