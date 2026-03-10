#!/usr/bin/env bash
# =============================================================================
#  TV1 Reporter — Installer / Setup Script
#  Supports Ubuntu 22.04 / 24.04 LTS
#  Run as the user who will own the application (not root).
#  sudo access is required for system package installation.
# =============================================================================
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[OK]${RESET}    $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
error()   { echo -e "${RED}[ERROR]${RESET} $*" >&2; }
die()     { error "$*"; exit 1; }
hr()      { echo -e "${BOLD}──────────────────────────────────────────────────────────${RESET}"; }

# ── Guard: must not run as root ───────────────────────────────────────────────
if [[ $EUID -eq 0 ]]; then
    die "Do not run this script as root. Run as the application user (e.g. 'ubuntu' or 'xspader')."
fi

INSTALL_USER="$(whoami)"
HOME_DIR="$(eval echo ~"$INSTALL_USER")"

clear
hr
echo -e "${BOLD}  TV1 Reporter — Installation & Setup${RESET}"
echo    "  Trend Vision One Security Reporting Portal"
hr
echo ""
info "Running as user: ${BOLD}${INSTALL_USER}${RESET}"
info "Home directory : ${BOLD}${HOME_DIR}${RESET}"
echo ""

# ── Helper: prompt with default ───────────────────────────────────────────────
prompt() {
    # prompt <var_name> <label> <default> [secret]
    local var="$1" label="$2" default="$3" secret="${4:-}"
    local val
    if [[ -n "$secret" ]]; then
        read -rsp "  ${label} [hidden]: " val; echo ""
        [[ -z "$val" ]] && val="$default"
    else
        read -rp "  ${label} [${default}]: " val
        [[ -z "$val" ]] && val="$default"
    fi
    printf -v "$var" '%s' "$val"
}

prompt_required() {
    # prompt_required <var_name> <label> [secret]
    local var="$1" label="$2" secret="${3:-}" val
    while true; do
        if [[ -n "$secret" ]]; then
            read -rsp "  ${label} (required): " val; echo ""
        else
            read -rp "  ${label} (required): " val
        fi
        [[ -n "$val" ]] && break
        warn "This field is required."
    done
    printf -v "$var" '%s' "$val"
}

# =============================================================================
#  SECTION 1 — Gather configuration
# =============================================================================
hr
echo -e "${BOLD}  Step 1/7 — Configuration${RESET}"
hr
echo ""

# Install directory
prompt INSTALL_DIR "Install directory" "${HOME_DIR}/V1"
echo ""

# Domain / hostname
echo "  Enter the domain name this site will be served on."
echo "  Use 'localhost' for local-only access (no TLS)."
echo "  For a real domain, Caddy will obtain a Let's Encrypt certificate."
prompt DOMAIN "Domain name" "localhost"
echo ""

# Port
prompt APP_PORT "Internal application port" "8100"
echo ""

# ── Admin user ────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Admin account credentials${RESET}"
hr
prompt  ADMIN_USERNAME "Admin username"  "admin"
prompt  ADMIN_EMAIL    "Admin email"     "admin@${DOMAIN}"
while true; do
    prompt_required ADMIN_PASSWORD "Admin password" secret
    local_pw_confirm=""
    read -rsp "  Confirm admin password: " local_pw_confirm; echo ""
    [[ "$ADMIN_PASSWORD" == "$local_pw_confirm" ]] && break
    warn "Passwords do not match — please try again."
done
echo ""

# ── Database ─────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Database configuration (MariaDB / MySQL)${RESET}"
hr
prompt DB_HOST "Database host" "localhost"
prompt DB_PORT "Database port" "3306"
prompt DB_NAME "Database name" "tv1reporter"
prompt DB_USER "Database user" "tv1reporter"
while true; do
    prompt_required DB_PASS "Database password" secret
    local_db_confirm=""
    read -rsp "  Confirm database password: " local_db_confirm; echo ""
    [[ "$DB_PASS" == "$local_db_confirm" ]] && break
    warn "Passwords do not match — please try again."
done
echo ""
info "You will be prompted for the MariaDB root password later to create the database."
echo ""

# ── Optional API keys ─────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Optional: API keys${RESET}"
echo    "  These can be left blank and configured later in the admin panel."
hr
prompt TV1_API_KEY  "Trend Vision One API key  (leave blank to skip)" ""
prompt TV1_BASE_URL "Trend Vision One base URL" "https://api.xdr.trendmicro.com"
prompt NVD_API_KEY  "NIST NVD API key           (leave blank to skip)" ""
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Configuration summary${RESET}"
hr
echo "  Install directory : ${INSTALL_DIR}"
echo "  Domain            : ${DOMAIN}"
echo "  App port          : ${APP_PORT}"
echo "  Admin username    : ${ADMIN_USERNAME}"
echo "  Admin email       : ${ADMIN_EMAIL}"
echo "  Database          : ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "  TV1 API key       : ${TV1_API_KEY:+(provided)}${TV1_API_KEY:-not set — configure later}"
echo "  NVD API key       : ${NVD_API_KEY:+(provided)}${NVD_API_KEY:-not set — configure later}"
echo ""
read -rp "  Proceed with installation? [Y/n]: " CONFIRM
[[ "${CONFIRM,,}" == "n" ]] && { info "Aborted."; exit 0; }
echo ""

# =============================================================================
#  SECTION 2 — System packages
# =============================================================================
hr
echo -e "${BOLD}  Step 2/7 — Installing system packages${RESET}"
hr

info "Updating apt package lists..."
sudo apt-get update -qq

info "Installing required packages..."
sudo apt-get install -y -qq \
    python3 python3-venv python3-pip \
    mariadb-server mariadb-client \
    curl git debian-keyring debian-archive-keyring apt-transport-https \
    >/dev/null

success "System packages installed."

# ── Caddy ─────────────────────────────────────────────────────────────────────
if ! command -v caddy &>/dev/null; then
    info "Installing Caddy..."
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq caddy >/dev/null
    success "Caddy installed."
else
    success "Caddy already installed: $(caddy version 2>&1 | head -1)"
fi

# =============================================================================
#  SECTION 3 — MariaDB database setup
# =============================================================================
hr
echo -e "${BOLD}  Step 3/7 — Database setup${RESET}"
hr

info "Ensuring MariaDB is running..."
sudo systemctl enable --now mariadb >/dev/null 2>&1 || true

# Check if DB already exists
DB_EXISTS=$(sudo mysql -u root -e "SHOW DATABASES LIKE '${DB_NAME}';" 2>/dev/null | grep -c "${DB_NAME}" || true)

if [[ "$DB_EXISTS" -gt 0 ]]; then
    warn "Database '${DB_NAME}' already exists — skipping creation."
else
    info "Creating database and user..."
    sudo mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
SQL
    success "Database '${DB_NAME}' and user '${DB_USER}' created."
fi

# Verify connection
if mysql -u "${DB_USER}" -p"${DB_PASS}" -h "${DB_HOST}" -P "${DB_PORT}" "${DB_NAME}" -e "SELECT 1;" >/dev/null 2>&1; then
    success "Database connection verified."
else
    die "Cannot connect to database as '${DB_USER}'. Check credentials and try again."
fi

# =============================================================================
#  SECTION 4 — Application files
# =============================================================================
hr
echo -e "${BOLD}  Step 4/7 — Application setup${RESET}"
hr

# If INSTALL_DIR doesn't exist or is empty, clone from GitHub
if [[ ! -f "${INSTALL_DIR}/web/app.py" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "Pulling latest code..."
        git -C "${INSTALL_DIR}" pull --ff-only
    else
        info "Cloning repository into ${INSTALL_DIR}..."
        git clone https://github.com/x2-Consulting/V1_reports.git "${INSTALL_DIR}"
    fi
    success "Application files ready."
else
    success "Application files already present at ${INSTALL_DIR}."
fi

# ── Virtual environment ───────────────────────────────────────────────────────
VENV_DIR="${INSTALL_DIR}/.venv"
if [[ ! -d "${VENV_DIR}" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "${VENV_DIR}"
fi

info "Installing Python dependencies..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/web/requirements.txt"
success "Python dependencies installed."

# ── Generate secrets ──────────────────────────────────────────────────────────
info "Generating SECRET_KEY and FERNET_KEY..."
SECRET_KEY=$("${VENV_DIR}/bin/python3" -c "import secrets; print(secrets.token_hex(32))")
FERNET_KEY=$("${VENV_DIR}/bin/python3" -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
success "Secrets generated."

# ── Write .env ────────────────────────────────────────────────────────────────
ENV_FILE="${INSTALL_DIR}/.env"
info "Writing ${ENV_FILE}..."
cat > "${ENV_FILE}" <<ENV
# =============================================================
#  TV1 Reporter — Environment Configuration
#  Generated by install.sh on $(date -u +"%Y-%m-%d %H:%M UTC")
#  DO NOT COMMIT THIS FILE TO VERSION CONTROL
# =============================================================

# Trend Vision One API
TVOne_API_KEY=${TV1_API_KEY}
TVOne_BASE_URL=${TV1_BASE_URL}

# Report output directory
REPORT_OUTPUT_DIR=${INSTALL_DIR}/output

# Database
DATABASE_URL=mysql+pymysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}

# Security
SECRET_KEY=${SECRET_KEY}
FERNET_KEY=${FERNET_KEY}

# Bootstrap admin user (used only on first startup if no users exist)
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_EMAIL=${ADMIN_EMAIL}

# Session duration (minutes)
ACCESS_TOKEN_EXPIRE_MINUTES=480
ENV
chmod 600 "${ENV_FILE}"
success ".env file written (permissions: 600)."

# ── Output directory ──────────────────────────────────────────────────────────
mkdir -p "${INSTALL_DIR}/output"

# =============================================================================
#  SECTION 5 — Caddy configuration
# =============================================================================
hr
echo -e "${BOLD}  Step 5/7 — Caddy configuration${RESET}"
hr

# Detect where Caddy is managed (system vs user)
# On this server Caddy is a system service with /etc/caddy/Caddyfile
CADDYFILE=""
CADDY_MANAGED_BY=""

if [[ -f /etc/caddy/Caddyfile ]]; then
    CADDYFILE="/etc/caddy/Caddyfile"
    CADDY_MANAGED_BY="system"
elif [[ -f "${HOME_DIR}/Caddyfile" ]]; then
    CADDYFILE="${HOME_DIR}/Caddyfile"
    CADDY_MANAGED_BY="user"
else
    # Create system Caddyfile
    sudo mkdir -p /etc/caddy
    CADDYFILE="/etc/caddy/Caddyfile"
    CADDY_MANAGED_BY="system"
    sudo touch "${CADDYFILE}"
fi

info "Caddyfile location: ${CADDYFILE} (${CADDY_MANAGED_BY}-managed)"

# Build the server block
if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
    CADDY_HOST=":${APP_PORT}"
    CADDY_BLOCK=":80"
else
    CADDY_BLOCK="${DOMAIN}"
fi

# Check if this domain block already exists
if grep -q "${DOMAIN}" "${CADDYFILE}" 2>/dev/null; then
    warn "A block for '${DOMAIN}' already exists in ${CADDYFILE}."
    warn "Skipping Caddy config update — edit ${CADDYFILE} manually if needed."
else
    TV1_CADDY_BLOCK="
# ── TV1 Reporter ──────────────────────────────────────────
${CADDY_BLOCK} {
    request_body {
        max_size 100MB
    }
    reverse_proxy 127.0.0.1:${APP_PORT} {
        transport http {
            response_header_timeout 120s
            read_timeout 300s
            write_timeout 300s
        }
    }
}
"
    if [[ "$CADDY_MANAGED_BY" == "system" ]]; then
        echo "${TV1_CADDY_BLOCK}" | sudo tee -a "${CADDYFILE}" >/dev/null
    else
        echo "${TV1_CADDY_BLOCK}" >> "${CADDYFILE}"
    fi
    success "Caddy block added for ${DOMAIN}."
fi

# Validate Caddy config
if caddy validate --config "${CADDYFILE}" 2>/dev/null; then
    success "Caddy configuration is valid."
else
    warn "Caddy config validation had warnings — check ${CADDYFILE} manually."
fi

# =============================================================================
#  SECTION 6 — systemd service
# =============================================================================
hr
echo -e "${BOLD}  Step 6/7 — systemd service${RESET}"
hr

SERVICE_DIR="${HOME_DIR}/.config/systemd/user"
mkdir -p "${SERVICE_DIR}"
SERVICE_FILE="${SERVICE_DIR}/tv1reporter.service"

info "Writing systemd user service: ${SERVICE_FILE}"
cat > "${SERVICE_FILE}" <<SVCEOF
[Unit]
Description=Trend Vision One Reporter (FastAPI)
After=network.target mysql.service mariadb.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${VENV_DIR}/bin/uvicorn web.app:app --host 127.0.0.1 --port ${APP_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SVCEOF

# Enable lingering so user service starts at boot without login
sudo loginctl enable-linger "${INSTALL_USER}" 2>/dev/null || true

systemctl --user daemon-reload
systemctl --user enable tv1reporter
systemctl --user restart tv1reporter
sleep 3

if systemctl --user is-active --quiet tv1reporter; then
    success "tv1reporter service is running."
else
    error "Service failed to start. Check logs with:"
    error "  journalctl --user -u tv1reporter -n 50"
    exit 1
fi

# ── Reload Caddy ──────────────────────────────────────────────────────────────
info "Reloading Caddy..."
if [[ "$CADDY_MANAGED_BY" == "system" ]]; then
    sudo systemctl reload caddy 2>/dev/null \
        || sudo systemctl restart caddy 2>/dev/null \
        || warn "Could not reload system Caddy — try: sudo systemctl reload caddy"
else
    # User-level Caddy
    caddy reload --config "${CADDYFILE}" 2>/dev/null \
        || caddy start --config "${CADDYFILE}" 2>/dev/null \
        || warn "Could not reload user Caddy — try: caddy reload --config ${CADDYFILE}"
fi
success "Caddy reloaded."

# =============================================================================
#  SECTION 7 — Seed NVD API key (if provided)
# =============================================================================
hr
echo -e "${BOLD}  Step 7/7 — Seeding initial settings${RESET}"
hr

if [[ -n "$NVD_API_KEY" ]]; then
    info "Seeding NVD API key into the database..."
    # Wait a moment for the app to initialise tables on first start
    sleep 5
    "${VENV_DIR}/bin/python3" - <<PYEOF
import sys, os
sys.path.insert(0, "${INSTALL_DIR}/web")
os.environ.setdefault("DATABASE_URL", "mysql+pymysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}")
os.environ.setdefault("SECRET_KEY", "${SECRET_KEY}")
os.environ.setdefault("FERNET_KEY", "${FERNET_KEY}")
try:
    from database import SessionLocal
    from settings_store import set_setting
    db = SessionLocal()
    set_setting(db, "nvd_api_key", "${NVD_API_KEY}")
    db.close()
    print("  NVD API key stored.")
except Exception as e:
    print(f"  Could not seed NVD API key automatically: {e}")
    print("  Add it manually: Admin → Settings → nvd_api_key")
PYEOF
    success "NVD API key seeded."
else
    info "No NVD API key provided — add it later: Admin → Settings → nvd_api_key"
fi

# =============================================================================
#  Done
# =============================================================================
echo ""
hr
echo -e "${BOLD}${GREEN}  Installation complete!${RESET}"
hr
echo ""

if [[ "$DOMAIN" == "localhost" || "$DOMAIN" == "127.0.0.1" ]]; then
    SITE_URL="http://localhost:${APP_PORT}"
else
    SITE_URL="https://${DOMAIN}"
fi

echo -e "  ${BOLD}Site URL      :${RESET} ${CYAN}${SITE_URL}${RESET}"
echo -e "  ${BOLD}Admin login   :${RESET} ${ADMIN_USERNAME} / (password you set)"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo "  1. Open ${SITE_URL} in your browser and log in."
if [[ -z "$TV1_API_KEY" ]]; then
echo "  2. Go to Customers → Add Customer and enter your TV1 API key."
else
echo "  2. Go to Customers → Add Customer to set up your first customer."
fi
if [[ -z "$NVD_API_KEY" ]]; then
echo "  3. Go to Admin → Settings and add your NVD API key."
echo "  4. Go to Admin → NVD Cache and run a Full Sync to pre-cache CVE data."
else
echo "  3. Go to Admin → NVD Cache and run a Full Sync to pre-cache ~260k CVEs."
fi
echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo "  View logs  : journalctl --user -u tv1reporter -f"
echo "  Restart    : systemctl --user restart tv1reporter"
echo "  Stop       : systemctl --user stop tv1reporter"
echo "  Status     : systemctl --user status tv1reporter"
echo ""
hr
