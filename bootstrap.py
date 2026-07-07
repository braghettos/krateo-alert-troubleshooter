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
  * On success login/register return 303 + `set-cookie: connect.sid=...; Domain=localhost` (from
    FRONTEND_URL). No HTTP client will send a Domain=localhost cookie back to the in-cluster
    service host, so the cookie jar stays empty and /api/team 401s. We therefore extract the
    connect.sid value from the raw Set-Cookie header and send it EXPLICITLY on /api/team.

Idempotent + retry-friendly (Job backoffLimit covers HyperDX still booting). No human, no UI.
"""
import json
import os
import re
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


def _sid_from(resp):
    """Pull connect.sid out of the raw Set-Cookie header. The cookie is scoped Domain=localhost
    (FRONTEND_URL), so requests' jar won't replay it to the service host — we send it by hand."""
    if resp is None:
        return None
    m = re.search(r"connect\.sid=([^;]+)", resp.headers.get("set-cookie", ""))
    return m.group(1) if m else None


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
    """Create the first admin + team. Zod requires email + password + matching confirmPassword.
    Returns the (successful) response so main can lift the session cookie, else None."""
    body = {"email": EMAIL, "password": PASSWORD, "confirmPassword": PASSWORD}
    r = session.post(f"{HDX}/api/register/password", json=body, timeout=30, allow_redirects=False)
    if not _auth_ok(r):
        print(f"[register] {r.status_code} loc={r.headers.get('Location', '')!r} "
              f"body={r.text[:300]!r}", flush=True)
        return None
    return r


def login(session):
    """passport local — try the email field, fall back to username. No redirect-follow.
    Returns the (successful) response so main can lift the session cookie, else None."""
    for body in ({"email": EMAIL, "password": PASSWORD}, {"username": EMAIL, "password": PASSWORD}):
        r = session.post(f"{HDX}/api/login/password", json=body, timeout=30, allow_redirects=False)
        if _auth_ok(r):
            return r
        print(f"[login] {r.status_code} loc={r.headers.get('Location', '')!r} "
              f"body={r.text[:150]!r}", flush=True)
    return None


def get_api_key(session, sid):
    # Send connect.sid explicitly (Domain=localhost keeps it out of the jar — see module docstring).
    headers = {"Cookie": f"connect.sid={sid}"} if sid else {}
    r = session.get(f"{HDX}/api/team", headers=headers, timeout=30, allow_redirects=False)
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
    s = requests.Session()
    if wait_for_hyperdx(s):
        print("team exists -> logging in", flush=True)
        resp = login(s)
        if not resp:
            raise SystemExit(f"login failed for {EMAIL}")
    else:
        print(f"no team -> registering first admin {EMAIL}", flush=True)
        resp = register(s)
        if not resp:
            # someone registered between our check and now -> fall back to login
            print("register failed; trying login", flush=True)
            resp = login(s)
            if not resp:
                raise SystemExit(f"register and login both failed for {EMAIL}")
    sid = _sid_from(resp)
    if not sid:
        # auth response carried no cookie -> do an explicit login to obtain a fresh session
        print("no connect.sid on auth response; performing explicit login", flush=True)
        resp = login(s)
        sid = _sid_from(resp)
    key = get_api_key(s, sid)
    write_secret(key)
    print(f"[ok] wrote Secret {NAMESPACE}/{SECRET_NAME} ({len(key)} chars)", flush=True)


if __name__ == "__main__":
    main()
