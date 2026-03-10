#!/usr/bin/env bash
# =============================================================================
#  TV1 Reporter — Installer / Setup Script
#  Supports Ubuntu 22.04 / 24.04 LTS (and compatible Debian derivatives)
#
#  Automatically detects and configures Caddy or Nginx as the reverse proxy.
#  If neither is present you are offered the choice to install one.
#
#  Run as the user who will own the application (NOT as root).
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
    die "Do not run this script as root. Run as the application user (e.g. 'ubuntu')."
fi

INSTALL_USER="$(whoami)"
HOME_DIR="$(eval echo ~"$INSTALL_USER")"

clear
hr
echo -e "${BOLD}  TV1 Reporter — Installation & Setup${RESET}"
echo    "  Trend Vision One Security Reporting Portal"
hr
echo ""
info "Running as : ${BOLD}${INSTALL_USER}${RESET}"
info "Home dir   : ${BOLD}${HOME_DIR}${RESET}"
echo ""

# ── Prompt helpers ────────────────────────────────────────────────────────────
prompt() {
    # prompt <var> <label> <default> [secret]
    local _var="$1" _label="$2" _default="$3" _secret="${4:-}" _val
    if [[ -n "$_secret" ]]; then
        read -rsp "  ${_label} [hidden, Enter=keep]: " _val; echo ""
        [[ -z "$_val" ]] && _val="$_default"
    else
        read -rp "  ${_label} [${_default}]: " _val
        [[ -z "$_val" ]] && _val="$_default"
    fi
    printf -v "$_var" '%s' "$_val"
}

prompt_required() {
    # prompt_required <var> <label> [secret]
    local _var="$1" _label="$2" _secret="${3:-}" _val
    while true; do
        if [[ -n "$_secret" ]]; then
            read -rsp "  ${_label} (required): " _val; echo ""
        else
            read -rp  "  ${_label} (required): " _val
        fi
        [[ -n "$_val" ]] && break
        warn "This field is required."
    done
    printf -v "$_var" '%s' "$_val"
}

prompt_password() {
    # prompt_password <var> <label>   — prompts twice, must match
    local _var="$1" _label="$2" _a _b
    while true; do
        read -rsp "  ${_label}: " _a; echo ""
        [[ -z "$_a" ]] && { warn "Password cannot be empty."; continue; }
        read -rsp "  Confirm ${_label}: " _b; echo ""
        [[ "$_a" == "$_b" ]] && break
        warn "Passwords do not match — try again."
    done
    printf -v "$_var" '%s' "$_a"
}

# ── Web server detection ──────────────────────────────────────────────────────
detect_webserver() {
    HAS_CADDY=false; HAS_NGINX=false
    command -v caddy &>/dev/null && HAS_CADDY=true
    command -v nginx &>/dev/null && HAS_NGINX=true

    # System service active takes priority for detection
    if systemctl is-active --quiet nginx 2>/dev/null; then HAS_NGINX=true; fi
    if systemctl is-active --quiet caddy 2>/dev/null; then HAS_CADDY=true; fi
    # User-level caddy service
    if systemctl --user is-active --quiet caddy 2>/dev/null; then HAS_CADDY=true; fi
}

# =============================================================================
#  SECTION 1 — Gather configuration
# =============================================================================
hr
echo -e "${BOLD}  Step 1/7 — Configuration${RESET}"
hr
echo ""

# ── Install directory ─────────────────────────────────────────────────────────
prompt INSTALL_DIR "Install directory" "${HOME_DIR}/V1"
echo ""

# ── Domain / SSL ──────────────────────────────────────────────────────────────
echo -e "  ${BOLD}Site domain / hostname${RESET}"
echo    "  Enter the public domain name (e.g. tv1.example.com)."
echo    "  Use 'localhost' for a local/development install (no SSL)."
echo ""
prompt_required DOMAIN "Domain name"
echo ""

# Decide if SSL makes sense
USE_SSL=false
IS_LOCAL=false
if [[ "$DOMAIN" == "localhost" || "$DOMAIN" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    IS_LOCAL=true
    info "Local/IP domain detected — SSL will be skipped."
else
    USE_SSL=true
    info "Public domain detected — SSL (Let's Encrypt) will be configured."
fi
echo ""

# ── App port ──────────────────────────────────────────────────────────────────
prompt APP_PORT "Internal application port" "8100"
echo ""

# ── Web server choice ─────────────────────────────────────────────────────────
detect_webserver

hr
echo -e "  ${BOLD}Web server${RESET}"
hr

if $HAS_CADDY && $HAS_NGINX; then
    echo "  Both Caddy and Nginx are present on this system."
    echo "  Which one should TV1 Reporter use?"
    echo "    1) Caddy  (recommended — automatic SSL, zero config)"
    echo "    2) Nginx  (uses certbot for SSL)"
    read -rp "  Choice [1]: " WS_CHOICE
    [[ "${WS_CHOICE}" == "2" ]] && WEBSERVER="nginx" || WEBSERVER="caddy"
elif $HAS_CADDY; then
    WEBSERVER="caddy"
    info "Caddy detected — will configure Caddy."
elif $HAS_NGINX; then
    WEBSERVER="nginx"
    info "Nginx detected — will configure Nginx."
else
    echo "  No web server detected. Which would you like to install?"
    echo "    1) Caddy  (recommended — automatic SSL, zero config)"
    echo "    2) Nginx  (uses certbot for SSL)"
    read -rp "  Choice [1]: " WS_CHOICE
    [[ "${WS_CHOICE}" == "2" ]] && WEBSERVER="nginx" || WEBSERVER="caddy"
    info "Will install ${WEBSERVER^}."
fi
echo ""

# For Nginx + SSL we need an email for Let's Encrypt
CERTBOT_EMAIL=""
if [[ "$WEBSERVER" == "nginx" && "$USE_SSL" == "true" ]]; then
    echo "  Let's Encrypt requires an email address for certificate notifications."
    prompt_required CERTBOT_EMAIL "Certificate email address"
    echo ""
fi

# ── Admin user ────────────────────────────────────────────────────────────────
hr
echo -e "  ${BOLD}Admin account${RESET}"
hr
prompt         ADMIN_USERNAME "Admin username" "admin"
prompt         ADMIN_EMAIL    "Admin email"    "${CERTBOT_EMAIL:-admin@${DOMAIN}}"
prompt_password ADMIN_PASSWORD "Admin password"
echo ""

# ── Database ─────────────────────────────────────────────────────────────────
hr
echo -e "  ${BOLD}Database (MariaDB / MySQL)${RESET}"
hr
prompt DB_HOST "Host"          "localhost"
prompt DB_PORT "Port"          "3306"
prompt DB_NAME "Database name" "tv1reporter"
prompt DB_USER "DB username"   "tv1reporter"
prompt_password DB_PASS "Database password"

# Validate DB_NAME and DB_USER — only alphanumeric + underscore allowed
if ! [[ "$DB_NAME" =~ ^[a-zA-Z0-9_]+$ ]]; then
    die "Database name '${DB_NAME}' contains invalid characters. Use only letters, digits, and underscores."
fi
if ! [[ "$DB_USER" =~ ^[a-zA-Z0-9_]+$ ]]; then
    die "Database username '${DB_USER}' contains invalid characters. Use only letters, digits, and underscores."
fi
echo ""

# ── Optional API keys ─────────────────────────────────────────────────────────
hr
echo -e "  ${BOLD}Optional API keys${RESET}  (leave blank — add later in Admin panel)"
hr
prompt TV1_API_KEY  "Trend Vision One API key " ""
prompt TV1_BASE_URL "Trend Vision One base URL" "https://api.xdr.trendmicro.com"
prompt NVD_API_KEY  "NIST NVD API key          " ""
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
hr
echo -e "${BOLD}  Configuration summary${RESET}"
hr
echo "  Install dir   : ${INSTALL_DIR}"
echo "  Domain        : ${DOMAIN}"
echo "  SSL           : ${USE_SSL}"
echo "  Web server    : ${WEBSERVER}"
echo "  App port      : ${APP_PORT}"
echo "  Admin user    : ${ADMIN_USERNAME} <${ADMIN_EMAIL}>"
echo "  Database      : ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo "  TV1 API key   : ${TV1_API_KEY:+(provided)}${TV1_API_KEY:-not set}"
echo "  NVD API key   : ${NVD_API_KEY:+(provided)}${NVD_API_KEY:-not set}"
echo ""
read -rp "  Proceed with installation? [Y/n]: " CONFIRM
[[ "${CONFIRM,,}" == "n" ]] && { info "Aborted."; exit 0; }
echo ""

# =============================================================================
#  SECTION 2 — System packages
# =============================================================================
hr
echo -e "${BOLD}  Step 2/7 — System packages${RESET}"
hr

info "Updating package lists..."
sudo apt-get update -qq

PKGS=(python3 python3-venv python3-pip mariadb-server mariadb-client
      curl git ca-certificates gnupg lsb-release)

# Add web-server-specific packages to the install list
if [[ "$WEBSERVER" == "nginx" ]]; then
    PKGS+=(nginx)
    if $USE_SSL; then
        PKGS+=(certbot python3-certbot-nginx)
    fi
fi

info "Installing: ${PKGS[*]}"
sudo apt-get install -y -qq "${PKGS[@]}" >/dev/null
success "Base packages installed."

# ── Install Caddy (if chosen and not yet present) ─────────────────────────────
if [[ "$WEBSERVER" == "caddy" ]] && ! command -v caddy &>/dev/null; then
    info "Installing Caddy from official repository..."
    sudo apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https >/dev/null
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' \
        | sudo gpg --batch --yes --dearmor \
            -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' \
        | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -qq
    sudo apt-get install -y -qq caddy >/dev/null
    success "Caddy installed: $(caddy version 2>&1 | head -1)"
else
    command -v caddy &>/dev/null \
        && success "Caddy already installed: $(caddy version 2>&1 | head -1)" || true
    command -v nginx &>/dev/null \
        && success "Nginx already installed: $(nginx -v 2>&1)" || true
fi

# =============================================================================
#  SECTION 3 — Database
# =============================================================================
hr
echo -e "${BOLD}  Step 3/7 — Database${RESET}"
hr

info "Ensuring MariaDB is running..."
sudo systemctl enable --now mariadb 2>/dev/null || sudo systemctl enable --now mysql 2>/dev/null || true

DB_EXISTS=$(sudo mysql -u root -e "SHOW DATABASES LIKE '${DB_NAME}';" 2>/dev/null \
    | grep -c "${DB_NAME}" || true)

if [[ "$DB_EXISTS" -gt 0 ]]; then
    warn "Database '${DB_NAME}' already exists — skipping creation."
else
    info "Creating database '${DB_NAME}' and user '${DB_USER}'..."
    sudo mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\`
    CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'${DB_HOST}' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON \`${DB_NAME}\`.* TO '${DB_USER}'@'${DB_HOST}';
FLUSH PRIVILEGES;
SQL
    success "Database and user created."
fi

# Verify connection — use MYSQL_PWD env var to avoid password in process list
if MYSQL_PWD="${DB_PASS}" mysql -u "${DB_USER}" -h "${DB_HOST}" -P "${DB_PORT}" \
       "${DB_NAME}" -e "SELECT 1;" >/dev/null 2>&1; then
    success "Database connection verified."
else
    die "Cannot connect to database — check credentials above."
fi

# =============================================================================
#  SECTION 4 — Application files, venv, .env
# =============================================================================
hr
echo -e "${BOLD}  Step 4/7 — Application${RESET}"
hr

# Clone or pull
if [[ ! -f "${INSTALL_DIR}/web/app.py" ]]; then
    if [[ -d "${INSTALL_DIR}/.git" ]]; then
        info "Pulling latest code..."
        git -C "${INSTALL_DIR}" pull --ff-only
    else
        info "Cloning repository into ${INSTALL_DIR}..."
        git clone https://github.com/x2-Consulting/V1_reports.git "${INSTALL_DIR}"
    fi
    success "Code ready."
else
    success "Application files already present at ${INSTALL_DIR}."
fi

# Virtual environment
VENV_DIR="${INSTALL_DIR}/.venv"
if [[ ! -d "${VENV_DIR}" ]]; then
    info "Creating Python virtual environment..."
    python3 -m venv "${VENV_DIR}"
fi

info "Installing Python dependencies (this may take a moment)..."
"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/requirements.txt"
"${VENV_DIR}/bin/pip" install --quiet -r "${INSTALL_DIR}/web/requirements.txt"
success "Python dependencies installed."

# Generate cryptographic secrets
info "Generating SECRET_KEY and FERNET_KEY..."
SECRET_KEY=$("${VENV_DIR}/bin/python3" -c \
    "import secrets; print(secrets.token_hex(32))")
FERNET_KEY=$("${VENV_DIR}/bin/python3" -c \
    "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")
success "Secrets generated."

# Write .env
ENV_FILE="${INSTALL_DIR}/.env"
info "Writing ${ENV_FILE}..."
cat > "${ENV_FILE}" <<ENVEOF
# =============================================================
#  TV1 Reporter — Environment configuration
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

# Bootstrap admin (used only on first startup when no users exist)
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_EMAIL=${ADMIN_EMAIL}

# Session lifetime (minutes)
ACCESS_TOKEN_EXPIRE_MINUTES=120

# HTTPS — set to true when behind SSL terminating proxy (Caddy/Nginx with TLS)
# This enables secure cookie flags and HSTS headers
HTTPS_ENABLED=$([ "$IS_LOCAL" == "true" ] && echo "false" || echo "true")
ENVEOF
chmod 600 "${ENV_FILE}"
success ".env written (mode 600)."

mkdir -p "${INSTALL_DIR}/output"

# =============================================================================
#  SECTION 5 — Web server configuration
# =============================================================================
hr
echo -e "${BOLD}  Step 5/7 — Web server (${WEBSERVER^})${RESET}"
hr

# ────────────────────────── CADDY ────────────────────────────────────────────
configure_caddy() {
    # Determine the Caddyfile location and whether it's user or system managed
    CADDY_MODE="system"
    CADDYFILE=""

    if [[ -f /etc/caddy/Caddyfile ]]; then
        CADDYFILE="/etc/caddy/Caddyfile"
        CADDY_MODE="system"
    elif systemctl --user is-active --quiet caddy 2>/dev/null \
         || [[ -f "${HOME_DIR}/Caddyfile" ]]; then
        CADDYFILE="${HOME_DIR}/Caddyfile"
        CADDY_MODE="user"
    else
        # Fresh system Caddy install — use /etc/caddy
        sudo mkdir -p /etc/caddy
        CADDYFILE="/etc/caddy/Caddyfile"
        CADDY_MODE="system"
        # Replace the default placeholder Caddyfile if it only has the example block
        if sudo grep -q "^# The Caddy" "${CADDYFILE}" 2>/dev/null \
           || [[ ! -s "${CADDYFILE}" ]]; then
            sudo tee "${CADDYFILE}" >/dev/null <<'CADDY_DEFAULT'
# Managed by TV1 Reporter installer
CADDY_DEFAULT
        fi
    fi

    info "Caddyfile: ${CADDYFILE} (${CADDY_MODE}-managed)"

    # Build server block — Caddy handles TLS automatically for real domains
    if $IS_LOCAL; then
        CADDY_HOST="http://${DOMAIN}:${APP_PORT}"
        CADDY_SERVER_NAME=":80"
    else
        CADDY_SERVER_NAME="${DOMAIN}"  # Caddy auto-provisions TLS via Let's Encrypt
    fi

    # Skip if this domain is already in the file
    if grep -qF "${DOMAIN}" "${CADDYFILE}" 2>/dev/null; then
        warn "Entry for '${DOMAIN}' already exists in ${CADDYFILE} — skipping."
    else
        TV1_BLOCK="
# ── TV1 Reporter ──────────────────────────────────────────────────────
${CADDY_SERVER_NAME} {
    request_body {
        max_size 500MB
    }
    reverse_proxy 127.0.0.1:${APP_PORT} {
        transport http {
            response_header_timeout 120s
            read_timeout            300s
            write_timeout           300s
        }
    }
}
"
        if [[ "$CADDY_MODE" == "system" ]]; then
            echo "${TV1_BLOCK}" | sudo tee -a "${CADDYFILE}" >/dev/null
        else
            echo "${TV1_BLOCK}" >> "${CADDYFILE}"
        fi
        success "Caddy block written for ${DOMAIN}."
    fi

    # Validate
    if caddy validate --config "${CADDYFILE}" 2>/dev/null; then
        success "Caddy config valid."
    else
        warn "Caddy config has warnings — check ${CADDYFILE}."
    fi

    # Ensure system Caddy service is enabled and reload
    if [[ "$CADDY_MODE" == "system" ]]; then
        sudo systemctl enable --now caddy 2>/dev/null || true
        sudo systemctl reload caddy 2>/dev/null \
            || sudo systemctl restart caddy 2>/dev/null \
            || warn "Could not reload Caddy. Run: sudo systemctl reload caddy"
    else
        # User Caddy
        systemctl --user enable --now caddy 2>/dev/null || true
        caddy reload --config "${CADDYFILE}" 2>/dev/null \
            || caddy start --config "${CADDYFILE}" 2>/dev/null \
            || warn "Could not reload user Caddy. Run: caddy reload --config ${CADDYFILE}"
    fi

    if $USE_SSL; then
        success "Caddy will obtain and auto-renew the TLS certificate for ${DOMAIN}."
        info "  Ensure port 80 and 443 are open and ${DOMAIN} resolves to this server."
    fi
}

# ────────────────────────── NGINX ────────────────────────────────────────────
configure_nginx() {
    NGINX_CONF_DIR="/etc/nginx/sites-available"
    NGINX_ENABLED_DIR="/etc/nginx/sites-enabled"
    NGINX_CONF="${NGINX_CONF_DIR}/tv1reporter"

    sudo mkdir -p "${NGINX_CONF_DIR}" "${NGINX_ENABLED_DIR}"

    # Remove the default site if it's still there (conflicts on port 80)
    if [[ -f "${NGINX_ENABLED_DIR}/default" ]]; then
        warn "Removing Nginx default site to free port 80."
        sudo rm -f "${NGINX_ENABLED_DIR}/default"
    fi

    if [[ -f "${NGINX_CONF}" ]]; then
        warn "Nginx config ${NGINX_CONF} already exists — skipping write."
    else
        info "Writing Nginx config: ${NGINX_CONF}"
        sudo tee "${NGINX_CONF}" >/dev/null <<NGINXEOF
# TV1 Reporter — managed by install.sh
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # Allow large CSV uploads (up to 500 MB)
    client_max_body_size 500M;

    # Let's Encrypt HTTP challenge (kept even after SSL redirect)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    location / {
        proxy_pass          http://127.0.0.1:${APP_PORT};
        proxy_http_version  1.1;
        proxy_set_header    Host              \$host;
        proxy_set_header    X-Real-IP         \$remote_addr;
        proxy_set_header    X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header    X-Forwarded-Proto \$scheme;
        proxy_read_timeout    600s;
        proxy_connect_timeout  60s;
        proxy_send_timeout    600s;
    }
}
NGINXEOF
        success "Nginx HTTP config written."
    fi

    # Enable the site
    if [[ ! -L "${NGINX_ENABLED_DIR}/tv1reporter" ]]; then
        sudo ln -s "${NGINX_CONF}" "${NGINX_ENABLED_DIR}/tv1reporter"
    fi

    # Test and reload
    sudo nginx -t 2>/dev/null || die "Nginx config test failed — check ${NGINX_CONF}"
    sudo systemctl enable --now nginx 2>/dev/null || true
    sudo systemctl reload nginx
    success "Nginx reloaded with HTTP config."

    # ── SSL via certbot ───────────────────────────────────────────────────────
    if $USE_SSL; then
        echo ""
        info "Obtaining Let's Encrypt certificate for ${DOMAIN}..."
        info "  Port 80 must be reachable from the internet and ${DOMAIN} must point here."
        echo ""

        if sudo certbot --nginx \
                --non-interactive \
                --agree-tos \
                --email "${CERTBOT_EMAIL}" \
                --domains "${DOMAIN}" \
                --redirect; then
            success "SSL certificate obtained and Nginx updated for HTTPS."
        else
            warn "certbot failed — the site is running on HTTP only."
            warn "Possible causes:"
            warn "  • ${DOMAIN} does not resolve to this server's public IP"
            warn "  • Port 80 is blocked by a firewall"
            warn "To retry manually: sudo certbot --nginx -d ${DOMAIN}"
            USE_SSL=false
        fi

        # ── Verify / ensure certbot renewal is active ─────────────────────────
        echo ""
        info "Checking certificate auto-renewal..."

        # certbot on Ubuntu installs a systemd timer; fall back to cron if absent
        if systemctl list-timers --all 2>/dev/null | grep -q certbot; then
            sudo systemctl enable --now certbot.timer 2>/dev/null || true
            success "certbot.timer is active — certificates renew automatically."
        elif [[ -f /etc/cron.d/certbot ]]; then
            success "certbot cron job present — certificates renew automatically."
        else
            warn "No certbot renewal job found — installing a cron entry..."
            echo "0 3 * * * root certbot renew --quiet --post-hook 'systemctl reload nginx'" \
                | sudo tee /etc/cron.d/certbot-tv1 >/dev/null
            success "Renewal cron job written to /etc/cron.d/certbot-tv1 (runs 03:00 daily)."
        fi

        # Do a dry-run to confirm renewal works
        info "Running renewal dry-run to confirm setup..."
        if sudo certbot renew --dry-run --quiet 2>/dev/null; then
            success "Renewal dry-run passed."
        else
            warn "Renewal dry-run had issues — check: sudo certbot renew --dry-run"
        fi
    fi
}

# Dispatch
if [[ "$WEBSERVER" == "caddy" ]]; then
    configure_caddy
else
    configure_nginx
fi

# =============================================================================
#  SECTION 6 — systemd user service
# =============================================================================
hr
echo -e "${BOLD}  Step 6/7 — Application service${RESET}"
hr

SERVICE_DIR="${HOME_DIR}/.config/systemd/user"
mkdir -p "${SERVICE_DIR}"

info "Writing systemd user service..."
cat > "${SERVICE_DIR}/tv1reporter.service" <<SVCEOF
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

# Enable lingering so the user service survives logout and starts at boot
sudo loginctl enable-linger "${INSTALL_USER}" 2>/dev/null || true

systemctl --user daemon-reload
systemctl --user enable tv1reporter
systemctl --user restart tv1reporter

info "Waiting for application to start..."
TRIES=0
until systemctl --user is-active --quiet tv1reporter 2>/dev/null; do
    TRIES=$(( TRIES + 1 ))
    [[ $TRIES -ge 15 ]] && {
        error "Application service failed to start after 15s."
        error "Check logs: journalctl --user -u tv1reporter -n 50"
        exit 1
    }
    sleep 1
done
success "tv1reporter service is running."

# =============================================================================
#  SECTION 7 — Seed settings
# =============================================================================
hr
echo -e "${BOLD}  Step 7/7 — Initial settings${RESET}"
hr

# Give the app time to create DB tables on first boot
sleep 4

if [[ -n "$NVD_API_KEY" ]]; then
    info "Seeding NVD API key into the database..."
    "${VENV_DIR}/bin/python3" - <<PYEOF 2>&1 | sed 's/^/  /'
import sys, os
sys.path.insert(0, "${INSTALL_DIR}/web")
os.environ.setdefault("DATABASE_URL",
    "mysql+pymysql://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}")
os.environ.setdefault("SECRET_KEY", "${SECRET_KEY}")
os.environ.setdefault("FERNET_KEY", "${FERNET_KEY}")
try:
    from database import SessionLocal
    from settings_store import set_setting
    db = SessionLocal()
    set_setting(db, "nvd_api_key", "${NVD_API_KEY}")
    db.close()
    print("NVD API key stored (encrypted).")
except Exception as exc:
    print(f"Warning: could not seed NVD API key: {exc}")
    print("Add it manually: Admin → Settings → nvd_api_key")
PYEOF
    success "NVD API key seeded."
else
    info "NVD API key not provided — add later: Admin → Settings → nvd_api_key"
fi

# =============================================================================
#  Done
# =============================================================================
echo ""
hr
echo -e "${BOLD}${GREEN}  Installation complete!${RESET}"
hr
echo ""

if $IS_LOCAL; then
    SITE_URL="http://localhost:${APP_PORT}"
elif $USE_SSL; then
    SITE_URL="https://${DOMAIN}"
else
    SITE_URL="http://${DOMAIN}"
fi

echo -e "  ${BOLD}Site URL    :${RESET} ${CYAN}${SITE_URL}${RESET}"
echo -e "  ${BOLD}Admin login :${RESET} ${ADMIN_USERNAME}  /  (password you set)"
echo ""
echo -e "  ${BOLD}Next steps:${RESET}"
echo "  1. Open ${SITE_URL} and log in."
if [[ -z "$TV1_API_KEY" ]]; then
    echo "  2. Customers → Add Customer → enter your Trend Vision One API key."
else
    echo "  2. Customers → Add Customer to set up your first environment."
fi
if [[ -z "$NVD_API_KEY" ]]; then
    echo "  3. Admin → Settings → add your NVD API key."
    echo "  4. Admin → NVD Cache → run Full Sync to pre-cache ~260k CVEs."
else
    echo "  3. Admin → NVD Cache → run Full Sync to pre-cache ~260k CVEs."
fi
echo ""
echo -e "  ${BOLD}Useful commands:${RESET}"
echo "  Logs    : journalctl --user -u tv1reporter -f"
echo "  Restart : systemctl --user restart tv1reporter"
echo "  Status  : systemctl --user status tv1reporter"
if [[ "$WEBSERVER" == "nginx" ]] && $USE_SSL; then
    echo "  SSL cert: sudo certbot certificates"
    echo "  Renew   : sudo certbot renew --dry-run"
fi
echo ""
hr
