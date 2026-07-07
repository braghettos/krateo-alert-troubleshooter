#!/usr/bin/env python3
"""hyperdx key bootstrap — headlessly provision the HyperDX team API key into a Secret.

The installer runs this as a Job. HyperDX has no no-UI key endpoint, so we drive the UI's own
endpoints with a session cookie jar:
  GET  /api/installation                 -> is a team already set up? (idempotency)
    false -> POST /api/register/password (create the first admin + team)
    true  -> POST /api/login/password    (log in)
  GET  /api/team                         -> team.apiKey  (the /api/v2 access key)
  -> write it into the `hyperdx-api-token` Secret (apiserver, via the mounted SA token).

Idempotent + retry-friendly (Job backoffLimit covers HyperDX still booting). No human, no UI.
"""
import json
import os
import sys
import time

import requests

HDX = os.environ["HYPERDX_URL"].rstrip("/")
EMAIL = os.environ["HYPERDX_ADMIN_EMAIL"]
PASSWORD = os.environ["HYPERDX_ADMIN_PASSWORD"]
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
SECRET_NAME = os.environ.get("SECRET_NAME", "hyperdx-api-token")
SA = "/var/run/secrets/kubernetes.io/serviceaccount"
APISERVER = os.environ.get("APISERVER", "https://kubernetes.default.svc")


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


def login(session):
    """passport local — try the email field, fall back to username."""
    for body in ({"email": EMAIL, "password": PASSWORD}, {"username": EMAIL, "password": PASSWORD}):
        r = session.post(f"{HDX}/api/login/password", json=body, timeout=30)
        if r.ok:
            return
    raise SystemExit(f"login failed for {EMAIL}: {r.status_code} {r.text[:200]}")


def get_api_key(session):
    r = session.get(f"{HDX}/api/team", timeout=30)
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
        login(s)
    else:
        print(f"no team -> registering first admin {EMAIL}", flush=True)
        r = s.post(f"{HDX}/api/register/password", json={"email": EMAIL, "password": PASSWORD}, timeout=30)
        if not r.ok:
            # someone registered between our check and now -> fall back to login
            print(f"register returned {r.status_code}; trying login", flush=True)
            login(s)
    key = get_api_key(s)
    write_secret(key)
    print(f"[ok] wrote Secret {NAMESPACE}/{SECRET_NAME} ({len(key)} chars)", flush=True)


if __name__ == "__main__":
    main()
