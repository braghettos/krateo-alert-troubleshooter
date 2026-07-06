# alert-troubleshooter

Bridges a **HyperDX alert** to an **Autopilot root-cause analysis**, in the background — no
browser required. The "auto-troubleshoot on fire" path for the Krateo observability Alerts.

```
HyperDX alert fires → webhook → alert-troubleshooter → A2A call to krateo-autopilot
                                                      → TroubleshootingReport CR (status.report = analysis)
                                                      → portal Alerts section renders it
```

## What it does
On `POST /webhook` (a HyperDX alert-fired payload) the handler:
1. creates a `TroubleshootingReport` CR (`observability.krateo.io/v1alpha1`, phase `Analyzing`),
2. calls the Autopilot A2A agent (`krateo-autopilot`, JSON-RPC `message/stream`) with an
   end-to-end troubleshooting prompt,
3. patches the CR status with the streamed analysis (`phase: Ready`, `report: <markdown>`).

Acks the webhook immediately (202) and analyses in a background thread so HyperDX doesn't time out.

## Build
Image is built + pushed by CI (`.github/workflows/release.yaml`) to
`ghcr.io/braghettos/alert-troubleshooter` on push to `main` / tags. No local docker push.

## Deploy
```sh
kubectl apply -f crd.troubleshootingreport.yaml   # the report CRD
kubectl apply -f deploy.yaml                       # SA + RBAC + Deployment + Service
```
Then point a HyperDX webhook at `http://alert-troubleshooter.krateo-system.svc:8080/webhook`
and reference it as the `channel.webhookId` on your `Alert` CRs.

## Config (env)
- `NAMESPACE` (default `krateo-system`) — where reports are created.
- `AUTOPILOT_A2A_URL` (default `http://krateo-autopilot.krateo-system.svc:8080/`).
- `A2A_TIMEOUT` (default `180`s).
