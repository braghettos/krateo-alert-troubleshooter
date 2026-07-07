#!/usr/bin/env python3
"""Session-driven reconciler for Alert CRs (alerts.observability.krateo.io).

Replaces KOG for HyperDX alert/webhook management (KOG can't drive the passport session this
ClickStack version requires — see the module docstring in hyperdx.py). Runs as a background thread
in the krateo-alert-troubleshooter process:

  every RECONCILE_INTERVAL seconds:
    login (once; re-login on session expiry) ->
    ensure the shared webhook (-> this troubleshooter's /webhook) ->
    for each Alert CR:
        no status.hyperdxAlertId -> create dashboard-tile + alert in HyperDX, record ids in status
        else                      -> mirror the live alert state (OK/ALERT/PENDING) into status

Alerts flow: HyperDX evaluates the alert; when it fires it POSTs the webhook -> this service's
/webhook -> Autopilot RCA -> TroubleshootingReport. The reconciler only manages config + status.
"""
import os
import time

import requests

import hyperdx
from handler import _k8s, _now  # reuse the apiserver helper + timestamp

GROUP, VERSION, PLURAL = "observability.krateo.io", "v1alpha1", "alerts"
NAMESPACE = os.environ.get("NAMESPACE", "krateo-system")
INTERVAL = int(os.environ.get("RECONCILE_INTERVAL", "60"))
WEBHOOK_NAME = os.environ.get("WEBHOOK_NAME", "krateo-autopilot")
WEBHOOK_TARGET = os.environ.get(
    "WEBHOOK_TARGET_URL", "http://krateo-alert-troubleshooter.krateo-system.svc:8080/webhook")


def _list_alert_crs():
    return _k8s("GET", f"/apis/{GROUP}/{VERSION}/namespaces/{NAMESPACE}/{PLURAL}").get("items", [])


def _patch_status(name, status):
    _k8s("PATCH", f"/apis/{GROUP}/{VERSION}/namespaces/{NAMESPACE}/{PLURAL}/{name}",
         {"status": status}, subresource="status")


def _reconcile_cr(hdx, cr, source, webhook_id):
    meta, spec, status = cr["metadata"], cr.get("spec", {}), cr.get("status", {})
    name = meta["name"]
    display = spec.get("displayName") or name
    hdx_id = status.get("hyperdxAlertId")

    live = {a["_id"]: a for a in hdx.list_alerts()}
    if hdx_id and hdx_id in live:
        _patch_status(name, {"state": live[hdx_id].get("state", "OK"),
                             "phase": "Synced", "lastSyncedAt": _now()})
        return

    # (re)create: dashboard-tile then alert on it, both ensure-by-name (idempotent)
    dash_id, tile_id = hdx.ensure_dashboard_tile(f"krateo-alert-{name}", source, spec.get("where", ""))
    alert = hdx.ensure_alert(display, dash_id, tile_id, webhook_id,
                             interval=spec.get("interval", "5m"),
                             threshold=spec.get("threshold", 1),
                             threshold_type=spec.get("thresholdType", "above"),
                             message=spec.get("message", ""))
    _patch_status(name, {"hyperdxAlertId": alert["id"], "hyperdxDashboardId": dash_id,
                         "state": alert.get("state", "OK"), "phase": "Synced", "lastSyncedAt": _now()})
    print(f"[reconciler] synced Alert {name} -> hyperdx {alert['id']} ({alert.get('state')})", flush=True)


def reconcile_once(hdx):
    source = hdx.first_source()
    webhook_id, recreated = hdx.ensure_webhook(WEBHOOK_NAME, WEBHOOK_TARGET,
                                               description="Krateo Autopilot auto-troubleshooter")
    if recreated:
        # the webhook id changed -> alerts referencing the old id would notify a dead channel.
        # Drop the HyperDX alerts we manage + reset their CR status so they rebuild on this webhook.
        crs = _list_alert_crs()
        managed = {cr.get("status", {}).get("hyperdxAlertId") for cr in crs} - {None, ""}
        for a in hdx.list_alerts():
            if a["_id"] in managed:
                try:
                    hdx.delete_alert(a["_id"])
                except Exception:  # noqa: BLE001
                    pass
        for cr in crs:
            _patch_status(cr["metadata"]["name"], {"hyperdxAlertId": None, "phase": "Pending"})
    for cr in _list_alert_crs():
        try:
            _reconcile_cr(hdx, cr, source, webhook_id)
        except requests.HTTPError:
            raise  # bubble 401/session issues to the loop for re-login
        except Exception as e:  # noqa: BLE001 — one bad CR shouldn't stall the rest
            name = cr.get("metadata", {}).get("name", "?")
            try:
                _patch_status(name, {"phase": "Error", "error": str(e)[:300], "lastSyncedAt": _now()})
            except Exception:  # noqa: BLE001
                pass
            print(f"[reconciler] Alert {name} error: {e}", flush=True)


def run_forever():
    url = os.environ.get("HYPERDX_URL", "http://krateo-clickstack.krateo-system.svc:3000")
    email = os.environ.get("HYPERDX_ADMIN_EMAIL")
    password = os.environ.get("HYPERDX_ADMIN_PASSWORD")
    if not (email and password):
        print("[reconciler] HYPERDX_ADMIN_EMAIL/PASSWORD unset — reconciler disabled", flush=True)
        return
    hdx = hyperdx.HyperDX(url, email, password)
    print(f"[reconciler] started (interval={INTERVAL}s, hyperdx={url})", flush=True)
    while True:
        try:
            if not hdx.sid and not hdx.ensure_session():
                print("[reconciler] auth (register/login) failed; retrying next cycle", flush=True)
            elif hdx.sid:
                reconcile_once(hdx)
        except requests.HTTPError as e:
            code = getattr(getattr(e, "response", None), "status_code", None)
            if code in (401, 403):
                hdx.sid = None  # session expired -> re-login next cycle
            print(f"[reconciler] http error ({code}); will retry: {e}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"[reconciler] cycle error: {e}", flush=True)
        time.sleep(INTERVAL)
