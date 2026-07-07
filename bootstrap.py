#!/usr/bin/env python3
"""hyperdx key bootstrap — headlessly provision the HyperDX team API key into a Secret.

The installer runs this as a Job. HyperDX has no no-UI key endpoint, so we drive the UI's own
endpoints with a session cookie jar:
  GET  /api/installation                 -> is a team already set up? (idempotency)
    false -> POST /api/register/password (create the first admin + team)
    true  -> POST /api/login/password    (log in)
  GET  /api/team                         -> team.apiKey  (the /api/v2 access key)
  -> write it into the `hyperdx-api-token` Secret (apiserver, via the mounted SA token).

Auth notes (verified against ClickStack v2.27):
  * register enforces a Zod policy: password >= 12 chars incl. upper+lower+digit+special, AND a
    matching `confirmPassword` field. The admin-creds Secret must satisfy this.
  * HyperDX is configured with FRONTEND_URL=http://localhost:3000, so passport failures 302 to
    http://localhost:3000/login?err=authFail — unreachable from inside the pod. We DON'T follow
    redirects; we read the status + Location to decide success, so a bad login never crashes us.

Idempotent + retry-friendly (Job backoffLimit covers HyperDX still booting). No human, no UI.
"""
import json
import os
import time

import requests

HDX = os.environ["HYPERDX_URL"].rstrip("/")
EMAIL = os.environ["HYPERDX_ADMIN_EMAIL"]
PASSWORD = os.environ["HYPERDX_ADMIN_PASSWORD"]
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
SECRET_NAME = os.environ.get("SECRET_NAME", "hyperdx-api-token")
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
APISERVER = os.environ.get("APISERVER", "https://kubernetes.default.svc")


def _auth_ok(r):
    """passport/register success = a 2xx, or a 3xx whose Location is NOT an error redirect
    (failures 302 to .../login?err=authFail). We never follow the redirect (it points at
    the unreachable FRONTEND_URL localhost:3000)."""
    loc = r.headers.get("Location", "")
    if 300 <= r.status_code < 400:
        return "err" not in loc and "authFail" not in loc
    return r.ok


def wait_for_hyperdx(session, tries=30):
    """HyperDX may still be booting when the Job starts — poll /api/installation."""
    for i in range(tries):
        try:
            r = session.get(f"{HDX}/api/installation", timeout=5)
            if r.ok:
                return r.json().get("isTeamExisting", False)
        except requests.RequestException:
            pass
        print(f"[wait] HyperDX not ready yet ({i + 1}/{tries})", flush=True)
        time.sleep(5)
    raise SystemExit("HyperDX /api/installation never became ready")


def register(session):
    """Create the first admin + team. Zod requires email + password + matching confirmPassword."""
    body = {"email": EMAIL, "password": PASSWORD, "confirmPassword": PASSWORD}
    r = session.post(f"{HDX}/api/register/password", json=body, timeout=30, allow_redirects=False)
    if not _auth_ok(r):
        print(f"[register] {r.status_code} loc={r.headers.get('Location', '')!r} "
              f"body={r.text[:300]!r}", flush=True)
        return False
    return True


def login(session):
    """passport local — try the email field, fall back to username. No redirect-follow."""
    for body in ({"email": EMAIL, "password": PASSWORD}, {"username": EMAIL, "password": PASSWORD}):
        r = session.post(f"{HDX}/api/login/password", json=body, timeout=30, allow_redirects=False)
        if _auth_ok(r):
            return True
        print(f"[login] {r.status_code} loc={r.headers.get('Location', '')!r} "
              f"body={r.text[:150]!r}", flush=True)
    return False


def get_api_key(session):
    r = session.get(f"{HDX}/api/team", timeout=30, allow_redirects=False)
    if 300 <= r.status_code < 400:
        raise SystemExit(f"/api/team redirected to {r.headers.get('Location', '')!r} — not authenticated")
    r.raise_for_status()
    team = r.json()
    if isinstance(team, list):
        team = team[0] if team else {}
    key = team.get("apiKey")
    if not key:
        raise SystemExit(f"no apiKey in /api/team response: {json.dumps(team)[:200]}")
    return key


def k8s(method, path, body=None):
    tok = open(f"{SA}/token").read().strip()
    headers = {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}
    if method == "PATCH":
        headers["Content-Type"] = "application/merge-patch+json"
    return requests.request(method, f"{APISERVER}{path}", headers=headers,
                            data=json.dumps(body) if body else None, verify=f"{SA}/ca.crt", timeout=30)


def write_secret(token):
    body = {"apiVersion": "v1", "kind": "Secret",
            "metadata": {"name": SECRET_NAME, "namespace": NAMESPACE},
            "stringData": {"token": token}}
    r = k8s("POST", f"/api/v1/namespaces/{NAMESPACE}/secrets", body)
    if r.status_code == 409:  # already exists -> merge-patch the token
        k8s("PATCH", f"/api/v1/namespaces/{NAMESPACE}/secrets/{SECRET_NAME}",
            {"stringData": {"token": token}}).raise_for_status()
    else:
        r.raise_for_status()


def main():
    s = requests.Session()  # cookie jar carries the passport session across calls
    if wait_for_hyperdx(s):
        print("team exists -> logging in", flush=True)
        if not login(s):
            raise SystemExit(f"login failed for {EMAIL}")
    else:
        print(f"no team -> registering first admin {EMAIL}", flush=True)
        if not register(s):
            # someone registered between our check and now -> fall back to login
            print("register failed; trying login", flush=True)
            if not login(s):
                raise SystemExit(f"register and login both failed for {EMAIL}")
    key = get_api_key(s)
    write_secret(key)
    print(f"[ok] wrote Secret {NAMESPACE}/{SECRET_NAME} ({len(key)} chars)", flush=True)


if __name__ == "__main__":
    main()
