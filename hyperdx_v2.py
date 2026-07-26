#!/usr/bin/env python3
"""HyperDX ≥2.28 external API v2 client (Bearer auth, port 8000).

Replaces the session-cookie hyperdx.py. All calls go directly to the Express
backend at port 8000 (krateo-clickstack-api.krateo-system.svc:8000) using the
user.accessKey from the hyperdx-api-token Secret (written by the bootstrap Job).

API shape notes:
  * All collection endpoints return {"data": [...], "meta": {...}}; _unwrap normalises.
  * Resources use "id" (not "_id") — consistent across alerts, webhooks, sources, dashboards.
  * Dashboard tile config v2 shape: {sourceId, select: [{aggFn, where}], displayType, ...}
    (NOT the legacy {source, select: "count()", whereLanguage, from, granularity, ...}).
"""
import requests

DEFAULT_WEBHOOK_BODY = '{"alertName":"{{title}}","state":"ALERT","source":"hyperdx-alert"}'


class HyperDXError(RuntimeError):
    pass


def _unwrap(x):
    if isinstance(x, dict) and "data" in x:
        return x["data"]
    return x


class HyperDXV2:
    def __init__(self, api_url, access_key, timeout=30):
        self.url = api_url.rstrip("/")  # http://krateo-clickstack-api.krateo-system.svc:8000
        self._headers = {
            "Authorization": f"Bearer {access_key}",
            "Content-Type": "application/json",
        }
        self.timeout = timeout

    def _req(self, method, path, body=None):
        r = requests.request(
            method,
            f"{self.url}{path}",
            headers=self._headers,
            json=body,
            timeout=self.timeout,
        )
        r.raise_for_status()
        return _unwrap(r.json()) if r.content else None

    # ---- domain primitives ----

    def first_source(self):
        srcs = self._req("GET", "/api/v2/sources") or []
        if not srcs:
            raise HyperDXError("no HyperDX sources configured")
        return srcs[0]

    def ensure_webhook(self, name, target_url, service="generic", description="", body=None):
        """Ensure a generic webhook named `name` exists with a body template.

        Returns (webhookId, recreated). A pre-existing body-less webhook is deleted and
        recreated so callers must re-point alerts when recreated is True.
        """
        body = body or DEFAULT_WEBHOOK_BODY
        for w in (self._req("GET", "/api/v2/webhooks") or []):
            if w.get("name") == name:
                if w.get("body"):
                    return w["id"], False
                self._req("DELETE", f"/api/v2/webhooks/{w['id']}")
                break
        created = self._req("POST", "/api/v2/webhooks",
                            {"name": name, "service": service, "url": target_url,
                             "description": description or name, "body": body})
        return created["id"], True

    def ensure_dashboard_tile(self, name, source, where=""):
        """Ensure a single-tile dashboard `name` with a count-over-time line chart.

        `source` is the first_source() dict. Returns (dashboardId, tileId).
        The v2 tile config uses sourceId + select:[{aggFn, where}] (not the legacy
        {source, select:"count()", whereLanguage, from, granularity}).
        """
        source_id = source["id"]
        for d in (self._req("GET", "/api/v2/dashboards") or []):
            if d.get("name") == name and d.get("tiles"):
                return d["id"], d["tiles"][0]["id"]
        tile = {
            "id": "count", "x": 0, "y": 0, "w": 6, "h": 3,
            "name": name,
            "config": {
                "displayType": "line",
                "sourceId": source_id,
                "asRatio": False,
                "fillNulls": True,
                "select": [{"aggFn": "count", "where": where or ""}],
            },
        }
        d = self._req("POST", "/api/v2/dashboards", {"name": name, "tags": [], "tiles": [tile]})
        return d["id"], d["tiles"][0]["id"]

    def list_alerts(self):
        return self._req("GET", "/api/v2/alerts") or []

    def ensure_alert(self, name, dashboard_id, tile_id, webhook_id,
                     interval="5m", threshold=1, threshold_type="above", message=""):
        """Create a tile-based alert if one with this name doesn't already exist.

        Returns {id, state}.
        """
        for a in self.list_alerts():
            if a.get("name") == name:
                return {"id": a["id"], "state": a.get("state", "OK")}
        body = {
            "name": name,
            "source": "tile",
            "dashboardId": dashboard_id,
            "tileId": tile_id,
            "interval": interval,
            "threshold": threshold,
            "thresholdType": threshold_type,
            "channel": {"type": "webhook", "webhookId": webhook_id},
            "message": message or f"{name} threshold crossed — Krateo Autopilot will auto-triage.",
        }
        a = self._req("POST", "/api/v2/alerts", body)
        return {"id": a["id"], "state": a.get("state", "OK")}

    def delete_alert(self, alert_id):
        self._req("DELETE", f"/api/v2/alerts/{alert_id}")

    def delete_dashboard(self, dashboard_id):
        self._req("DELETE", f"/api/v2/dashboards/{dashboard_id}")
