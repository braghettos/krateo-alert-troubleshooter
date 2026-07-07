#!/usr/bin/env python3
"""Minimal HyperDX/ClickStack v2.27 session-API client.

Alerts + webhooks on this version are managed ONLY via the passport session-authenticated internal
API (no bearer/apikey REST API exists — verified live). This client logs in, carries the session
cookie explicitly (it's scoped Domain=localhost from FRONTEND_URL, so no jar replays it to the
service host), and exposes the ensure-by-name primitives the reconciler needs:

    login -> first_source -> ensure_webhook -> ensure_dashboard_tile -> ensure_alert / list_alerts

Response envelopes are inconsistent across endpoints: /api/webhooks + /api/alerts wrap in {"data":…}
while /api/sources + /api/dashboards return bare values — _unwrap() normalises both.
"""
import json
import re

import requests


def _unwrap(x):
    return x["data"] if isinstance(x, dict) and "data" in x else x


# HyperDX compiles a generic webhook's `body` as a Handlebars template to build the POST payload;
# a webhook with NO body makes handleSendGenericWebhook throw ("Handlebars.compile(undefined)") and
# every notification silently fails. {{title}} is the alert title (single-line -> JSON-safe once
# Handlebars HTML-escapes quotes); the handler reads alertName from it.
DEFAULT_WEBHOOK_BODY = '{"alertName":"{{title}}","state":"ALERT","source":"hyperdx-alert"}'


class HyperDXError(RuntimeError):
    pass


class HyperDX:
    def __init__(self, url, email, password, timeout=30):
        self.url = url.rstrip("/")
        self.email = email
        self.password = password
        self.timeout = timeout
        self.sid = None
        self.s = requests.Session()

    # ---- auth ----
    def _sid_from(self, r):
        m = re.search(r"connect\.sid=([^;]+)", r.headers.get("set-cookie", ""))
        return m.group(1) if m else None

    @staticmethod
    def _redirect_ok(r):
        loc = r.headers.get("Location", "")
        return (300 <= r.status_code < 400 and "err" not in loc and "authFail" not in loc) or r.ok

    def login(self):
        """passport local login -> capture connect.sid. Returns True on success.
        A 303 to `/` (no err) is success; failures 303 to /login?err=authFail. Never follow the
        redirect (it points at the unreachable FRONTEND_URL localhost:3000)."""
        r = self.s.post(f"{self.url}/api/login/password",
                        json={"email": self.email, "password": self.password},
                        timeout=self.timeout, allow_redirects=False)
        if not self._redirect_ok(r):
            return False
        self.sid = self._sid_from(r)
        return self.sid is not None

    def register(self):
        """Create the first admin + team (fresh install). Zod requires a matching confirmPassword
        and a strong password (>=12 chars, upper+lower+digit+special)."""
        r = self.s.post(f"{self.url}/api/register/password",
                        json={"email": self.email, "password": self.password,
                              "confirmPassword": self.password},
                        timeout=self.timeout, allow_redirects=False)
        if not self._redirect_ok(r):
            return False
        self.sid = self._sid_from(r)
        return self.sid is not None

    def ensure_session(self):
        """Self-bootstrapping auth: register the admin on a fresh HyperDX (no team yet), else log
        in. Returns True once a usable session cookie is held. Idempotent + race-safe."""
        exists = True
        try:
            r = self.s.get(f"{self.url}/api/installation", timeout=self.timeout)
            if r.ok:
                exists = r.json().get("isTeamExisting", False)
        except requests.RequestException:
            pass
        if not exists and self.register() and self.sid:
            return True
        return self.login()

    def _headers(self):
        return {"Cookie": f"connect.sid={self.sid}", "Content-Type": "application/json"}

    def _req(self, method, path, body=None):
        r = self.s.request(method, f"{self.url}{path}", headers=self._headers(),
                           data=json.dumps(body) if body is not None else None,
                           timeout=self.timeout, allow_redirects=False)
        if 300 <= r.status_code < 400:  # redirect to login => session lost
            raise requests.HTTPError("session expired (redirect)", response=_Resp401())
        r.raise_for_status()
        return _unwrap(r.json()) if r.content else None

    # ---- domain primitives (all ensure-by-name = idempotent) ----
    def first_source(self):
        srcs = self._req("GET", "/api/sources") or []
        if not srcs:
            raise HyperDXError("no HyperDX sources configured")
        return srcs[0]

    def ensure_webhook(self, name, target_url, service="generic", description="", body=None):
        """Ensure a generic webhook named `name` exists WITH a body template. Returns
        (webhookId, recreated). A pre-existing body-less webhook is deleted and recreated (its send
        would otherwise 500), so callers must re-point alerts when recreated is True."""
        body = body or DEFAULT_WEBHOOK_BODY
        for w in (self._req("GET", f"/api/webhooks?service={service}") or []):
            if w.get("name") == name:
                if w.get("body"):
                    return w["_id"], False
                self._req("DELETE", f"/api/webhooks/{w['_id']}")  # body-less -> recreate with body
                break
        created = self._req("POST", "/api/webhooks",
                            {"name": name, "service": service, "url": target_url,
                             "description": description or name, "body": body})
        return created["_id"], True

    def delete_alert(self, alert_id):
        self._req("DELETE", f"/api/alerts/{alert_id}")

    def ensure_dashboard_tile(self, name, source, where=""):
        """Ensure a single-tile dashboard `name` counting rows of `source` matching `where`.
        Returns (dashboardId, tileId). The tile config mirrors the verified working shape."""
        frm = source.get("from", {"databaseName": "default", "tableName": "otel_logs"})
        ts = source.get("displayedTimestampValueExpression") or source.get("timestampValueExpression") or "Timestamp"
        for d in (self._req("GET", "/api/dashboards") or []):
            if d.get("name") == name and d.get("tiles"):
                return d["_id"], d["tiles"][0]["id"]
        tile = {
            "id": "count", "x": 0, "y": 0, "w": 6, "h": 3,
            "config": {"name": name, "source": source["_id"], "displayType": "line",
                       "select": "count()", "where": where, "whereLanguage": "lucene",
                       "granularity": "auto", "from": frm, "timestampValueExpression": ts},
        }
        d = self._req("POST", "/api/dashboards", {"name": name, "tags": [], "tiles": [tile]})
        return d["_id"], d["tiles"][0]["id"]

    def list_alerts(self):
        return self._req("GET", "/api/alerts") or []

    def ensure_alert(self, name, dashboard_id, tile_id, webhook_id,
                     interval="5m", threshold=1, threshold_type="above", message=""):
        """Create the tile-based alert if one with this name doesn't already exist.
        Returns {id, state}."""
        for a in self.list_alerts():
            if a.get("name") == name:
                return {"id": a["_id"], "state": a.get("state", "OK")}
        body = {"name": name, "source": "tile", "dashboardId": dashboard_id, "tileId": tile_id,
                "interval": interval, "threshold": threshold, "thresholdType": threshold_type,
                "channel": {"type": "webhook", "webhookId": webhook_id},
                "message": message or f"{name} threshold crossed — Krateo Autopilot will auto-triage."}
        a = self._req("POST", "/api/alerts", body)
        return {"id": a["_id"], "state": a.get("state", "OK")}


class _Resp401:
    """Marker so callers can treat a login-redirect as a 401 and re-authenticate."""
    status_code = 401
    def json(self):
        return {}
