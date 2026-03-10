# TV1 Reporter — Trend Vision One Reporting Portal

A self-hosted web portal for generating professional PDF security reports from **Trend Vision One (TV1)** data. Reports are produced on demand via the web UI or by uploading CSV exports from TV1, and are enriched with authoritative CVE data from the NIST National Vulnerability Database (NVD).

---

## Features

- **Multi-customer management** — store multiple TV1 customer environments, each with its own encrypted API key
- **7 report types** generated from the TV1 API or CSV uploads:
  - Executive Summary
  - Patch Remediation (CVEs grouped by fixing patch/KB article)
  - MITRE ATT&CK Heatmap
  - Most Targeted Assets
  - Threat Behaviour
  - Alert Response Timeline
  - Blocked Threats & IoCs
- **CSV upload** for Patch Remediation — paste or upload a TV1 vulnerability export and generate a report without a live API connection
- **NVD CVE enrichment** — every CVE is enriched with CVSS score, severity, CWE, vector string, and patch/advisory URLs from the NIST NVD API v2
- **Local NVD cache** — a local MariaDB cache of ~260k CVEs eliminates live API calls during report generation; cache is kept current via full and incremental syncs
- **Admin portal** with user management, application settings, and NVD cache controls
- **Secure by default** — API keys encrypted at rest (Fernet), bcrypt password hashing, JWT HttpOnly cookies, CSRF protection, rate-limited login

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Browser  ──►  Caddy (TLS, reverse proxy :443 → :8100)      │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│  FastAPI / Uvicorn  (web/)                                   │
│  ┌──────────┐  ┌─────────────┐  ┌──────────────────────┐   │
│  │  Routes  │  │  Jinja2 UI  │  │  PDF Generation      │   │
│  │  /auth   │  │  Bootstrap5 │  │  (ReportLab)         │   │
│  │  /cust.  │  └─────────────┘  └──────────────────────┘   │
│  │  /rep.   │                                               │
│  │  /admin  │  ┌─────────────┐  ┌──────────────────────┐   │
│  └──────────┘  │  SQLAlchemy │  │  collectors/         │   │
│                │  MariaDB    │  │  TV1 API, NVD API     │   │
│                └─────────────┘  └──────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Tech stack:**

| Layer | Technology |
|---|---|
| Web framework | FastAPI + Uvicorn |
| Templates | Jinja2 + Bootstrap 5 |
| Database | MariaDB via SQLAlchemy 2 + PyMySQL |
| PDF | ReportLab |
| Auth | JWT (HttpOnly cookie) + bcrypt |
| Secrets | Fernet symmetric encryption |
| CSRF | itsdangerous double-submit cookie |
| Rate limiting | slowapi |
| HTTP client | httpx |
| Reverse proxy | Caddy v2 |
| Process manager | systemd user service |

---

## Directory Structure

```
V1/
├── collectors/            # Data collection and enrichment
│   ├── nvd.py             # NVD API client + cache-aware lookup
│   ├── nvd_sync.py        # Full / incremental NVD cache sync
│   ├── csv_patch.py       # TV1 CSV → PatchGroup objects
│   ├── patch_remediation.py
│   ├── executive_summary.py
│   ├── mitre_heatmap.py
│   ├── targeted_assets.py
│   ├── threat_behaviour.py
│   ├── alert_response.py
│   └── blocked_threats.py
├── reports/               # PDF report builders (ReportLab)
│   ├── patch_report.py
│   ├── executive_summary_report.py
│   ├── mitre_report.py
│   └── ...
├── web/                   # FastAPI web application
│   ├── app.py             # Application factory, startup hooks
│   ├── models.py          # SQLAlchemy ORM models
│   ├── database.py        # DB engine and session factory
│   ├── security.py        # JWT, bcrypt, Fernet helpers
│   ├── settings_store.py  # Admin-configurable app settings (encrypted)
│   ├── routes/
│   │   ├── auth.py        # Login / logout
│   │   ├── customers.py   # Customer CRUD + API key management
│   │   ├── reports.py     # Report generation + CSV upload
│   │   ├── dashboard.py
│   │   └── admin.py       # User management, settings, NVD sync
│   └── templates/         # Jinja2 HTML templates
├── .env.example           # Environment variable reference
├── requirements.txt       # CLI/collector dependencies
└── web/requirements.txt   # Web application dependencies
```

---

## Prerequisites

- Python 3.11+
- MariaDB 10.6+ (or MySQL 8+)
- Caddy v2 (for production TLS reverse proxy)
- A **Trend Vision One** API token (per customer)
- A **NIST NVD API key** (free — https://nvd.nist.gov/developers/request-an-api-key)

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/x2-Consulting/V1_reports.git
cd V1_reports
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
pip install -r web/requirements.txt
```

### 4. Set up the database

```sql
-- Run as MariaDB root
CREATE DATABASE tv1reporter CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'tv1'@'localhost' IDENTIFIED BY 'strongpassword';
GRANT ALL PRIVILEGES ON tv1reporter.* TO 'tv1'@'localhost';
FLUSH PRIVILEGES;
```

### 5. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` and fill in all values:

```ini
TVOne_API_KEY=your_default_tv1_api_key   # optional; per-customer keys override this
TVOne_BASE_URL=https://api.xdr.trendmicro.com

DATABASE_URL=mysql+pymysql://tv1:strongpassword@localhost:3306/tv1reporter

# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=<32-char-random-hex>

# Generate: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY=<fernet-key>

ADMIN_USERNAME=admin
ADMIN_PASSWORD=changeme123
ADMIN_EMAIL=admin@example.com
```

> **Important:** Never commit `.env` to version control. It is listed in `.gitignore`.

### 6. Start the web application

```bash
cd web
uvicorn app:app --host 127.0.0.1 --port 8100
```

On first startup the application will:
- Create all database tables automatically
- Create the bootstrap admin user from the `ADMIN_*` env vars (if no users exist)

---

## Production Deployment

### systemd user service

Create `~/.config/systemd/user/tv1reporter.service`:

```ini
[Unit]
Description=TV1 Reporter Web Application
After=network.target

[Service]
WorkingDirectory=/home/youruser/V1/web
ExecStart=/home/youruser/V1/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 8100
EnvironmentFile=/home/youruser/V1/.env
Restart=on-failure

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now tv1reporter
```

### Caddy reverse proxy

`/etc/caddy/Caddyfile`:

```caddyfile
v1.yourdomain.com {
    reverse_proxy 127.0.0.1:8100 {
        transport http {
            response_header_timeout 120s
            read_timeout 300s
            write_timeout 300s
        }
    }
    request_body {
        max_size 100MB
    }
}
```

```bash
sudo systemctl reload caddy
```

---

## Usage

### First login

Navigate to `https://v1.yourdomain.com` and log in with the admin credentials from your `.env`.

### Adding customers

1. Go to **Customers → Add Customer**
2. Enter the customer name and their TV1 API key
3. Select the TV1 regional base URL for their environment
4. The API key is encrypted at rest using the `FERNET_KEY`

### Generating reports

1. Select a customer from the **Customers** list
2. Click **Generate Report** and choose a report type
3. Configure the date range and options
4. The PDF is generated server-side and downloaded automatically

### CSV upload (Patch Remediation)

1. In TV1, export the vulnerability list as CSV
2. Go to **Reports → CSV Upload**
3. Select the customer, upload the CSV, and click **Generate**

The expected CSV columns (TV1 export format):

| Column | Description |
|---|---|
| `Device name` | Hostname of the affected endpoint |
| `Vulnerability ID` | CVE identifier (e.g. `CVE-2024-21412`) |
| `Global exploit potential` | Severity label from TV1 |
| `OS/Application` | Affected software |
| `Mitigation options` | KB article numbers (e.g. `KB5034441`) |
| `Status` | `Active` / `Fixed` / `Resolved` — Fixed/Resolved rows are skipped |
| `Device ID` | TV1 endpoint GUID |

### NVD CVE cache

The local NVD cache drastically speeds up report generation by eliminating live API calls.

1. Go to **Admin → NVD Cache**
2. Add your NVD API key under **Admin → Settings**
3. Run **Full Sync** once (~3–5 minutes, downloads ~260k CVEs)
4. Schedule **Sync Recent (7 days)** daily or weekly to keep the cache current

After a full sync, report generation for cached CVEs runs entirely offline (~1ms per CVE vs ~20ms for a live lookup).

---

## Security Notes

- **API keys** for TV1 customers are encrypted with Fernet (AES-128-CBC) before storage. The encryption key (`FERNET_KEY`) must be kept secret and backed up.
- **Passwords** are hashed with bcrypt (work factor 12).
- **Sessions** use JWT tokens stored in HttpOnly, Secure, SameSite=Lax cookies.
- **CSRF** is protected via an itsdangerous-signed double-submit cookie on all mutating forms.
- **Login** is rate-limited to 20 attempts per minute per IP via slowapi.
- The `.env` file must never be committed — it is excluded in `.gitignore`.

---

## Report Types

| Report | Data Source | Description |
|---|---|---|
| **Executive Summary** | TV1 API | High-level risk posture: open alerts, endpoint health, top threats |
| **Patch Remediation** | TV1 API or CSV | CVEs grouped by the patch/KB article that fixes them, enriched with NVD CVSS data |
| **MITRE ATT&CK Heatmap** | TV1 API | Visualises which ATT&CK techniques were observed in the environment |
| **Most Targeted Assets** | TV1 API | Endpoints ranked by alert volume and severity |
| **Threat Behaviour** | TV1 API | Breakdown of threat categories and detection methods |
| **Alert Response** | TV1 API | Timeline and response metrics for security alerts |
| **Blocked Threats & IoCs** | TV1 API | Summary of blocked malicious connections, files, and indicators |

---

## Development

Run with auto-reload:

```bash
cd web
uvicorn app:app --reload --host 127.0.0.1 --port 8100
```

Run the CLI report tool directly:

```bash
python main.py --customer "Acme Corp" --report patch_remediation --days 30
```

---

## License

Proprietary — © 2025 x2 Consulting. All rights reserved.
