# Mist Access Assurance — Deny Log Intelligence

A Python report generator that transforms raw RADIUS deny logs from [Mist Access Assurance](https://www.juniper.net/us/en/products/cloud-services/mist-ai.html) into actionable, client-centric intelligence. Run one command, enter your API token, and receive a self-contained **interactive HTML dashboard** and a **multi-sheet Excel workbook** — both opened automatically when the script finishes.

Instead of scanning hundreds of identical event rows, you get **one record per device** — showing exactly why it is failing, how long it has been failing, and whether the issue is isolated or systemic.

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

A Python script that pulls from the Mist API and produces two output files:

- **HTML report** — fully interactive dashboard (filters, tabs, email composer, help) that opens directly in any browser. No web server required. Can be emailed to a colleague.
- **Excel workbook** — four-sheet workbook for IT teams who prefer spreadsheets.

Both files are self-contained and work completely offline after generation.

---

## Quick Start

### Requirements

- Python 3.8 or later — verify with `python3 --version`
- A Mist API token with **org-level read access** (instructions below)
- Terminal / Command Prompt

---

### Step 1 — Get the files

**Option A: Git clone (recommended — makes future updates easy)**

```bash
git clone https://github.com/djuergens/mist-access-assurance-deny-intelligence.git
cd mist-access-assurance-deny-intelligence
```

**Option B: Download ZIP**

Click the green **Code** button on this page → **Download ZIP** → unzip it → open Terminal and `cd` into the folder.

---

### Step 2 — Install dependencies (one time only)

**Mac / Linux:**
```bash
pip3 install -r requirements.txt
```

**Windows:**
```bash
pip install -r requirements.txt
```

> If `pip3` is not found, try: `python3 -m pip install -r requirements.txt`

Dependencies: `requests`, `openpyxl`. Nothing else required.

---

### Step 3 — Run the script

**Mac / Linux:**
```bash
python3 deny_report.py
```

**Windows:**
```bash
python deny_report.py
```

---

### Step 4 — Answer the prompts

```
Mist API Token (input hidden): ••••••••••••••••••••

Cloud Region:
  1. Global          (api.mist.com)
  2. Europe          (api.eu.mist.com)
  3. APAC            (api.gc1.mist.com)
  ...
Select region [1]: 1

Organizations available with this token:
  1. Acme Corp   (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
  2. Lab Org     (yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy)
Select org [1–2]: 1

Lookback window in days [7]: 7
```

The script authenticates, fetches events, aggregates data, writes both output files, and opens them automatically.

To tag clients as managed or unmanaged, use the **📋 Import Asset List** button in the top-right corner of the HTML report — no re-run needed. See [Managed Device CSV](#managed-device-csv-optional) below.

---

### Updating to the latest version

If you cloned with git:
```bash
cd mist-access-assurance-deny-intelligence
git pull
```

If you downloaded manually, re-download `deny_report.py`:
```bash
curl -O https://raw.githubusercontent.com/djuergens/mist-access-assurance-deny-intelligence/main/deny_report.py
```

---

## Managed Device CSV (Optional)

Import a CSV of known company-owned devices to tag every failing client as **Managed**, **Unmanaged**, or **Unknown**. This lets IT admins immediately focus on company assets and deprioritize BYOD and guest devices.

### What it unlocks

- **Managed Assets Failing** metric card in the HTML dashboard (only shown when a CSV is loaded)
- **Asset** column in the client table — green badge for managed devices, gray for unmanaged
- **Device Type filter** dropdown — filter the table to show only managed or only unmanaged clients
- **Managed Asset Failures** sheet in the Excel workbook — managed clients sorted to the top, with device name, owner, and department
- Free-text search across device name, owner, and department

### CSV format

The script auto-detects the MAC address column by scanning header names for common keywords (`mac`, `address`, `hardware`, `ethernet`, etc.). No specific column name is required.

| Column | Required | Auto-detected keywords | Example values |
|---|---|---|---|
| MAC address | **Yes** | mac, address, hardware, ethernet, wifi, bssid | `a4:c3:f0:12:34:56`, `A4C3F0123456`, `a4-c3-f0-12-34-56` |
| Device name | No | name, hostname, computer, device, asset | `LAPTOP-JSMITH` |
| Assigned user | No | user, owner, assigned, person, email | `John Smith` |
| Department | No | dept, department, group, division, team, ou | `Finance` |

MAC addresses can be in any common format — colons, dashes, dots, no separator, uppercase or lowercase. All formats are normalized automatically.

### Example CSV

See [`assets_example.csv`](assets_example.csv) for a ready-to-use template:

```csv
MAC Address,Device Name,Assigned User,Department
a4:c3:f0:12:34:56,LAPTOP-JSMITH,John Smith,Finance
B8:27:EB:AB:CD:EF,DESKTOP-KLEE,Karen Lee,IT
d4:6d:6d:aa:bb:cc,IPAD-CONF-ROOM-1,,Facilities
```

### Exporting from your MDM

**Jamf Pro**
1. Computers → Search Inventory → export all
2. Include columns: MAC Address, Computer Name, Username, Department

**Microsoft Intune**
1. Devices → All devices → Export (CSV)
2. Relevant columns: MAC address (Wi-Fi), Device name, Primary user UPN, Department (from Azure AD)

**Google Admin / Chrome OS**
1. Devices → Chrome devices → Download device list
2. Include: MAC address, Asset ID, User, Organizational unit

**Manual / Spreadsheet**
Any CSV with a column containing MAC addresses works. Extra columns are ignored. If the MAC column cannot be auto-detected, the script will show the available column names and ask you to type the correct one.

---

## Getting Your API Token

1. Log in to **[manage.mist.com](https://manage.mist.com)**
2. Click your name (top-right) → **My Profile**
3. Scroll to **API Token** → **Create Token**
4. Give it a name (e.g. `Deny Log Report`) and click **Generate**
5. **Copy the token immediately** — it is only shown once
6. Paste it at the prompt when running the script

**Required access:** Org-level read access to NAC client events and sites. An org admin token works. Site-level tokens will only show data for a single site and will miss cross-site patterns.

> **Security note:** The token is entered via a hidden prompt (`getpass`) and is never written to disk. It exists in memory only for the duration of the script run.

---

## Output Files

Both files are timestamped (e.g. `deny_report_20260410_1020.html`) and saved in the directory where you run the script.

### HTML Report

An interactive single-file dashboard with five tabs:

**Dashboard** — Sortable, filterable client table. Filter by site, status, category, deny reason, or device type (managed/unmanaged). Free-text search across MAC, username, site, error text, device name, owner, and department. Click a category card to filter to that failure type. Use the **📋 Import Asset List** button (top-right) to load a managed device CSV — no re-run needed. The report updates live: a **Managed Assets Failing** metric card appears, an **Asset** column shows managed/unmanaged status with device name, owner, and department inline, and a **Device Type** filter dropdown is enabled. Drag-and-drop a CSV onto the page also works. A **✕ Remove** link clears the import.

**Deny Reasons** — Every unique RADIUS error message, ranked by how many clients are hitting it. Click any row to jump to the Dashboard filtered to exactly those clients. Fastest path from "something is wrong" to "here is who to fix first."

**7-Day Timeline** — One row per client, colored by failure category, one block per day. Spot sudden onset (all clients start the same day), persistent failures (full 7-day bar), and silent failures (activity only on early days).

**Notification Center** — Pre-written emails for every site:
- **Per-site email** — affected MACs, deny reasons, and remediation steps, ready to send to the building tech team. Editable before sending.
- **NOC Digest** — single cross-site summary for the network operations team.

**Help** — In-app reference for every field, status, and score, plus FAQ.

### Excel Workbook

| Sheet | Contents |
|---|---|
| Client Summary | One row per MAC — status, category, blast radius, attempts, dates, primary deny reason. Color-coded cells. |
| Deny Reasons | Each unique deny reason text with client count, total events, category, and affected MACs |
| Daily Timeline | Events per client per day — colored cells matching the category (cert / cred / mac) |
| Remediation Guide | Step-by-step fix instructions for each failure category |

---

## Dashboard Reference

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

Blast radius is calculated **across clients**, not per-client. It measures how many devices share the exact same primary deny reason. A high blast radius signals that a single root cause — a misconfigured cert rollout, an MDM deployment that missed a fleet, or a policy change — is affecting many users at once.

| Score | Threshold | Interpretation |
|---|---|---|
| 🔴 HIGH | 5+ clients share the same deny reason | Systemic — likely a policy change, cert rollout, or MDM deployment affecting a device fleet |
| 🟡 MED | 3–4 clients share the same deny reason | Small group pattern — shared policy, same device model, or SSID configuration issue |
| 🟢 LOW | 1–2 clients share this deny reason | Isolated — specific to that device or user account |

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

The silent threshold is not a fixed wall-clock duration. The tool counts only business hours (Monday–Friday, 7am–7pm) elapsed since the client's last deny event. Weekend hours and overnight hours do not count.

A client that fails Friday at 5pm will not be marked silent until **Monday at 3pm** (8 business hours later) — giving a full business day for the user to return and attempt reconnection before it is considered silently broken.

---

## Security

- **Read-only:** This tool makes no write calls to the Mist API
- **Token never stored:** The API token is entered via a hidden prompt and lives in memory only for the duration of the script. It is never written to disk, logged, or transmitted anywhere except the Mist API.
- **No backend:** All data is fetched directly from Mist to your local machine. Nothing passes through any intermediate server.
- **Local processing:** All aggregation and analysis runs on your machine. The generated HTML and Excel files contain no live connections — they are static snapshots.
- **Shareable output:** The HTML report can be emailed freely — it contains no credentials, no tokens, and no live API connections.

---

## Files

| File | Description |
|---|---|
| `deny_report.py` | Main script — run with `python3 deny_report.py` |
| `requirements.txt` | Python dependencies (`requests`, `openpyxl`) |
| `assets_example.csv` | Example managed device CSV — use as a template for your MDM export |
| `deny_dashboard.html` | Alternative: live browser tool that calls the Mist API directly (requires a local web server for CORS) |
| `LICENSE` | MIT License |
| `README.md` | This file |

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

## Author

Built by Derek Juergens — contributions and feedback welcome.
