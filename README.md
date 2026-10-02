# AI-IDPS — AI Intrusion Detection & Prevention System (Windows)

Real-time network + web attack detection using Npcap/Scapy capture,
XGBoost ML classification, a Flask + WebSocket SOC dashboard, and
optional OPNsense auto-blocking.

---

## 1. Architecture

```
Kali Attacker --> Windows Host (Npcap capture + Test Website)
                     |
                     v
            Feature Engineering Layer
            (packet_rate, byte_rate, unique_ports,
             syn_rate, request_rate, error_rate,
             suspicious_pattern_score)
                     |
                     v
              XGBoost Classifier
                     |
                     v
                IDS Engine -----> PostgreSQL (alerts, logs)
                     |
                     v
          IPS Engine (OPNsense API, optional)
                     |
                     v
   Flask + Flask-SocketIO Backend (REST API + WebSocket)
                     |
                     v
        Nginx Reverse Proxy (TLS termination)
                     |
                     v
          SOC Dashboard (3-page cyber UI)
```

---

## 2. Prerequisites

- **Windows 10/11** with Administrator access
- **Python 3.12**
- **Npcap** installed (https://npcap.com) — required by Scapy for raw
  packet capture. During install, enable "Support raw 802.11 traffic"
  and "Install Npcap in WinPcap API-compatible mode" if prompted.
- **PostgreSQL 14+** running locally or reachable over the network
- (Optional) **OPNsense** firewall with API access, for auto-blocking
- (Optional) **Nginx** for TLS termination / reverse proxy
- An isolated lab network with a **Kali Linux** VM for generating
  attack traffic against your own test site

> ⚠️ Only run attack tools (sqlmap, hydra, nmap, etc.) against systems
> you own, on an isolated lab network. Do not point this at production
> or third-party systems.

---

## 3. Setup

### 3.1 Clone / copy the project

```
ai-idps/
├── backend/        Flask app, config, auth, REST API, test website
├── capture/        Npcap/Scapy packet sniffer
├── feature_engine/ Sliding-window feature aggregation + web pattern scoring
├── ml_model/       XGBoost training + inference
├── ids/            IDS detection engine
├── ips/            IPS engine (OPNsense integration)
├── db/             SQLAlchemy models + init.sql
├── dashboard/      HTML/CSS/JS frontend (templates + static)
├── nginx/          Example reverse proxy config
└── requirements.txt
```

### 3.2 Python environment

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

### 3.3 PostgreSQL

```powershell
psql -U postgres -f db\init.sql
```

This creates the `idps_db` database and `idps_user` role. Adjust
`db\init.sql` and `backend\config.py` (`DATABASE_URL`) if you use
different credentials.

### 3.4 Environment variables (optional overrides)

Set these in your shell or a `.env` loader of your choice:

```powershell
$env:SECRET_KEY = "your-flask-secret"
$env:JWT_SECRET_KEY = "your-jwt-secret"
$env:DATABASE_URL = "postgresql://idps_user:idps_pass@localhost:5432/idps_db"
$env:CAPTURE_IFACE = ""            # leave empty for default interface
$env:IPS_DRY_RUN = "true"          # set to "false" once OPNsense is configured

# Only needed if IPS_DRY_RUN=false
$env:OPNSENSE_HOST = "https://192.168.1.1"
$env:OPNSENSE_API_KEY = "..."
$env:OPNSENSE_API_SECRET = "..."
$env:OPNSENSE_ALIAS = "IDPS_BLOCKLIST"
```

### 3.5 Train the ML model

```powershell
python -m ml_model.train_model
```

This generates `ml_model/idps_xgb_model.json` using a synthetic
dataset that mirrors the feature schema. For better accuracy, replace
`generate_synthetic_dataset()` with real labeled traffic captured from
your lab (normal browsing vs. Kali attack traffic against the test
site).

### 3.6 Run the application

Open PowerShell **as Administrator** (required for Npcap raw capture):

```powershell
venv\Scripts\activate
python -m backend.app
```

On first run this will:
- Create all database tables
- Create a default admin account: **username `admin` / password `ChangeMe123!`**
  → **change this immediately** via `/api/auth/register` or directly in the DB.
- Start the packet sniffer, feature aggregator, and IDS detection loop
- Serve the dashboard at `http://localhost:5000`

---

## 4. Using the system

1. Navigate to `http://localhost:5000/login` and sign in.
2. **Page 1 (Live Monitoring)**: CPU/RAM, live packet/byte rate charts,
   active connections table, real-time attack feed via WebSocket.
3. **Page 2 (Attack Analytics)**: attack-type distribution, hourly
   trend chart, recent alerts table.
4. **Page 3 (Incident Forensics)**: look up any source IP to see its
   alert history, feature trend chart, and raw web request log. Admins
   and analysts can manually block/unblock IPs from here.

### Generating test traffic

From your **Kali VM** (same isolated lab network):

```bash
# Port scan
nmap -sS <windows-host-ip>

# Web attack traffic against the built-in test site
curl "http://<windows-host-ip>:5000/testsite/search?q=' OR 1=1 --"
curl "http://<windows-host-ip>:5000/testsite/comment" -d "comment=<script>alert(1)</script>"

# Brute-force simulation
hydra -l admin -P wordlist.txt <windows-host-ip> http-post-form \
  "/testsite/login:username=^USER^&password=^PASS^:invalid"
```

The IDS engine sweeps every 2 seconds; alerts and (if `IPS_DRY_RUN=false`)
auto-blocks will appear on the dashboard in real time.

---

## 5. OPNsense auto-blocking setup

1. In OPNsense: **Firewall → Aliases**, create a Host alias named
   `IDPS_BLOCKLIST` (empty content is fine initially).
2. **Firewall → Rules**: add a rule on the relevant interface that
   **blocks** source = `IDPS_BLOCKLIST`, placed above any allow rules.
3. **System → Access → Users**: create an API key/secret for a user
   with firewall API permissions.
4. Set `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`,
   `OPNSENSE_ALIAS`, and `IPS_DRY_RUN=false` as shown above.
5. Restart `backend.app`. High/critical alerts will now add the
   offending IP to `IDPS_BLOCKLIST` and apply the firewall rule set.

---

## 6. Security notes

- The default admin password **must** be changed on first login.
- JWT tokens are stored in `localStorage` by the dashboard; serve over
  HTTPS (via the provided Nginx config) in any non-local deployment.
- RBAC: `admin` and `analyst` roles can block/unblock IPs and create
  users; `viewer` is read-only.
- The built-in `/testsite/*` routes are intentionally simple
  attack-pattern targets for **lab use only** — do not expose them to
  the internet or connect them to a real database/user store.

---

## 7. Production deployment with Nginx

1. Generate/obtain a TLS certificate for your IDPS host.
2. Edit `nginx/idps.conf` with your cert paths and hostname.
3. Point Nginx at the Flask-SocketIO app running on `127.0.0.1:5000`
   (the config proxies both HTTP and the `/socket.io/` WebSocket path).
4. Run `backend.app` as a Windows service (e.g. via NSSM) so it starts
   on boot, with Administrator privileges for Npcap.
