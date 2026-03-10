# TV1 Reporter — Production Deployment Guide

## Prerequisites
- Ubuntu 22.04 or 24.04 LTS
- A domain name (e.g. `tv1.example.com`) with an **A record already pointing to the server's public IP**
- SSH access to the server as a non-root user with `sudo`
- Port 80 and 443 open in the firewall/security group

---

## Step 1 — DNS
Before anything else, create your DNS A record:
```
tv1.example.com  →  <server public IP>
```
Wait for it to propagate (check with `dig tv1.example.com` or `ping tv1.example.com`).
Let's Encrypt will fail if DNS isn't resolving yet.

---

## Step 2 — Provision the server
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl
```

---

## Step 3 — Clone the repo and run the installer
```bash
git clone https://github.com/x2-Consulting/V1_reports.git ~/V1
cd ~/V1
chmod +x install.sh
./install.sh
```

The installer will prompt you for:

| Prompt | What to enter |
|---|---|
| Install directory | `~/V1` (default) |
| Domain name | `tv1.example.com` |
| Internal app port | `8100` (default) |
| Web server | Choose **Caddy** (recommended — handles SSL automatically) |
| Admin username | Your choice |
| Admin email | Your email |
| Admin password | Strong password |
| DB name | `tv1reporter` (default) |
| DB username | `tv1reporter` (default) |
| DB password | Strong password |
| TV1 API key | Leave blank — add via Admin panel later |
| NVD API key | Leave blank — add via Admin panel later |

> If you choose **Nginx** you will also be asked for a Let's Encrypt notification email.

---

## Step 4 — Verify it's running
```bash
# Check the app service
sudo systemctl status tv1reporter

# Check Caddy (or nginx)
sudo systemctl status caddy

# Tail the app logs
sudo journalctl -u tv1reporter -f
```

Visit `https://tv1.example.com` — you should see the login page with a valid SSL cert.

---

## Step 5 — First login
1. Log in with the admin credentials you set during install
2. Go to **Admin → Settings** and add your:
   - Trend Vision One API key + base URL
   - NIST NVD API key
3. Go to **Admin → NVD Cache** and trigger the initial sync

---

## Step 6 — Add customers and generate reports
1. **Customers** → Add a customer with their Vision One API key
2. **Reports** → Generate or upload a CSV for a patch remediation report

---

## Firewall (UFW)
```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow OpenSSH
sudo ufw enable
```

---

## Troubleshooting
```bash
# Re-run the installer safely — it skips steps already done
./install.sh

# Manually restart the app
sudo systemctl restart tv1reporter

# Check for Python errors
sudo journalctl -u tv1reporter -n 50
```

> **Important:** The main thing to get right before running the installer is DNS propagation.
> Caddy's automatic SSL provisioning will fail if the domain doesn't resolve to the server yet.

---

## Updating an existing installation
```bash
cd ~/V1
git pull
sudo systemctl restart tv1reporter
```

If dependencies changed:
```bash
cd ~/V1
source .venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart tv1reporter
```
