# Mist Access Assurance — Deny Log Intelligence

A browser-based dashboard that transforms raw RADIUS deny logs from [Mist Access Assurance](https://www.juniper.net/us/en/products/cloud-services/mist-ai.html) into actionable, client-centric intelligence. Instead of scanning hundreds of identical event rows, you get **one record per device** — showing exactly why it is failing, how long it has been failing, and whether the issue is isolated or systemic.

---

## The Problem

Mist Access Assurance generates one RADIUS deny event per authentication attempt. At enterprise scale, a single broken client generates hundreds of identical rows. Native tooling provides a 24-hour lookback window, which means clients that failed Friday afternoon and went silent over the weekend are completely invisible by Monday morning.

| Pain Point | Impact |
|---|---|
| One row per deny event | A single broken device creates hundreds of duplicate log entries |
| 24-hour lookback window | Clients that fail Friday and go silent disappear before Monday triage |
| No grouping by failure type | Cert failures, credential errors, and MAC auth failures look identical in raw logs |
| No blast radius view | No way to tell if 20 devices are failing for the same systemic reason |
| No automated notification path | Building tech teams only find out when users file tickets |

---

## The Solution

A client-centric deny log intelligence layer on top of the Mist API that:

- Aggregates a rolling **7-day window** of RADIUS deny events into **one record per client** (not one row per event)
- Automatically **categorizes failures**: Cert/TLS issue · Wrong credentials · MAC auth / policy failure
- Detects **silent failures** — clients that failed and stopped retrying — using business-hour-aware logic so Friday failures are not missed over the weekend
- Scores each client by **blast radius** — how many devices share the same deny reason — to surface systemic issues immediately
- Generates **pre-written notification emails** to building tech teams (per site) and a NOC digest (all sites), with category-specific remediation steps

---

## Quick Start

### Requirements

- A modern web browser (Chrome, Edge, Firefox, or Safari)
- A Mist API token with **org-level read access**
- Python 3 (used only to serve the file locally — no other dependencies)

### Mac

1. Download or clone this repository
2. Double-click **`start_report.command`**
   - If macOS shows a security warning, right-click the file → **Open** → **Open**
3. Your browser opens automatically
4. Paste your Mist API token and click **Connect & Generate Report**

### Windows

1. Download or clone this repository
2. Double-click **`start_report.bat`**
3. Paste your Mist API token and click **Connect & Generate Report**

> The launcher scripts start a lightweight local Python web server so the browser can reach the Mist API. Keep the terminal or command window open while using the tool. Close it when you are done.

---

## Getting Your API Token

1. Log in to **[manage.mist.com](https://manage.mist.com)**
2. Click your name (top-right) → **My Profile**
3. Scroll to **API Token** → **Create Token**
4. Give it a name (e.g. `Deny Log Report`) and click **Generate**
5. **Copy the token immediately** — it is only shown once
6. Paste it into the dashboard when prompted

**Required access:** Org-level read access to NAC client events and sites. An org admin token works. Site-level tokens will only show data for a single site and will miss cross-site patterns.

---

## Dashboard

### Metric Cards

| Card | Definition |
|---|---|
| Total Deny Events | Raw count of individual RADIUS deny events in the selected time window |
| Unique Clients | Distinct devices (by MAC address) with at least one deny — the number that matters for triage |
| Sites Affected | How many Mist sites have at least one failing client |
| Cert Failures | Clients whose primary failure is a certificate or TLS trust issue |
| Silent Failures | Clients that failed and stopped retrying (business-hour-aware — see below) |

### Failure Categories

| Category | Meaning | Typical Fix |
|---|---|---|
| 🔐 Cert / TLS Issue | Device does not trust the RADIUS server cert, or its client cert is missing, expired, or from an untrusted CA | Deploy the Mist org certificate via MDM — **Organization → Access → Certificates** |
| 🔑 Wrong Credentials | Username or password rejected by the identity provider | Verify credentials, check account is not locked, confirm IdP group grants network access |
| 📱 MAC Auth / Policy Failure | No NAC policy rule matched the device — implicit deny | Confirm MAC is enrolled; verify a NAC rule exists for this device type or SSID |

### Client Status

| Status | Definition |
|---|---|
| 🔴 **failing** | Deny event within the last 8 business hours — actively retrying and being rejected right now |
| 🟣 **silent** | Last deny event was 8+ business hours ago (Mon–Fri, 7am–7pm) with no successful auth since. The client stopped retrying. Weekend hours are excluded — a Friday failure will not flip to silent until it has missed a full business day. |
| 🟢 **resolved** | A successful RADIUS permit event was seen in the lookback window after the deny events |

### Blast Radius

Blast radius is calculated **across clients**, not per-client. It measures how many devices share the exact same primary deny reason. A high blast radius is the signal that a single root cause — a misconfigured cert rollout, an MDM deployment that missed a fleet, or a policy change — is affecting many users at once.

| Score | Threshold | Interpretation |
|---|---|---|
| 🔴 HIGH | 5+ clients share the same deny reason | Systemic — likely a policy change, cert rollout, or MDM deployment affecting a device fleet |
| 🟡 MED | 3–4 clients share the same deny reason | Small group pattern — shared policy, same device model, or same SSID configuration issue |
| 🟢 LOW | 1–2 clients share this deny reason | Isolated — specific to that device or user account |

---

## Tabs

### Dashboard
Sortable, filterable client table. Filter by site, status, deny reason, or free-text search across MAC, username, site, and error text. Click a category card to filter to that failure type.

### Deny Reasons
Every unique RADIUS error message, ranked by how many clients are hitting it. Click any row to jump to the Dashboard filtered to exactly those clients. This is the fastest path from "something is wrong" to "here is who to fix first."

### 7-Day Timeline
One row per client, colored by failure category, one block per day. Makes it easy to spot sudden onset (all clients start the same day — likely a policy change), persistent failures (full 7-day bar), and silent failures (activity only on early days).

### Notification Center
Pre-written emails for every site with affected clients:
- **Per-site email** — affected MACs, deny reasons, and step-by-step remediation, ready to send to the building tech team. Editable before sending.
- **NOC Digest** — single cross-site summary for the network operations team.

### Help
In-app reference: definitions for every field, status, and score, plus a FAQ covering the most common questions.

---

## Configuration Options

| Setting | Options | Notes |
|---|---|---|
| Cloud Region | Global / Europe / APAC | Must match your Mist dashboard URL. Most customers use Global. |
| Lookback Window | 3 / 7 / 14 days | 7 days recommended. Catches the Friday problem while keeping the dataset manageable. Event retention varies by Mist org tier. |

---

## Technical Details

### API Endpoints Used

| Endpoint | Purpose |
|---|---|
| `GET /api/v1/self` | Authenticate token and discover org ID and org name |
| `GET /api/v1/orgs/{org_id}/sites` | Build site ID → site name lookup map |
| `GET /api/v1/orgs/{org_id}/nac_clients/events/search` | Paginated retrieval of all NAC client events for the lookback window |

All API calls use `Authorization: Token <token>`. All operations are **read-only**. No data is written to Mist.

### Event Classification Logic

| Event Type | Classified As |
|---|---|
| `NAC_SERVER_CERT_VALIDATION_FAILURE` | cert |
| `NAC_CLIENT_DENY` + text contains "certificate", "cert", "tls", or "ca" | cert |
| `NAC_CLIENT_DENY` + `auth_type = device-auth` | mac |
| `NAC_CLIENT_DENY` + text contains "policy rules", "implicit deny", or "no policy" | mac |
| All other `NAC_CLIENT_DENY` events | cred |
| `NAC_CLIENT_PERMIT` | Used to set client status to `resolved` |

### Silent Failure Detection

The silent threshold is not a fixed wall-clock duration. Instead, the tool counts only business hours (Monday–Friday, 7am–7pm) elapsed since the client's last deny event. Weekend hours and overnight hours do not count.

A client that fails Friday at 5pm will not be marked silent until **Monday at 3pm** (8 business hours later) — giving a full business day for the user to return and attempt reconnection before it is considered silently broken.

---

## Security

- **Read-only:** This tool makes no write calls to the Mist API
- **No storage:** API tokens are held only in browser session memory and are never written to disk, logged, or transmitted to any third party
- **No server:** All aggregation and analysis runs locally in the browser — no backend, no cloud service
- **Session-scoped:** Closing the browser tab clears the token

---

## Files

| File | Description |
|---|---|
| `deny_dashboard.html` | Main tool — the complete dashboard as a single self-contained HTML file |
| `start_report.command` | Mac launcher — double-click to start the local server and open the browser |
| `start_report.bat` | Windows launcher — double-click to start the local server and open the browser |
| `LICENSE` | MIT License |
| `README.md` | This file |

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

Built by Derek Juergens — contributions and feedback welcome.
