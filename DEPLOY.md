# FinanceIQ — Deployment Guide

## Your files

You only need 2 files to deploy:
- `server.py` — the backend
- `app.html` — the frontend

Everything else (Dockerfile, Procfile, etc.) is for specific platforms.

---

## Option 1: Render.com (Recommended — Free tier available)

**Time: ~5 minutes. No credit card for free tier.**

1. Go to [render.com](https://render.com) and sign up
2. Click **New → Web Service**
3. Connect your GitHub repo (push the files first) OR use **Public Git URL**
4. Settings:
   - **Runtime**: Python
   - **Build Command**: `echo "no build"`
   - **Start Command**: `python3 server.py`
5. Add environment variables:
   - `SECRET_KEY` = (click "Generate" for a random value)
   - `ADMIN_PASS` = your chosen admin password
   - `PORT` = `8080`
6. Add a **Disk** (for SQLite persistence):
   - Mount path: `/data`
   - Size: 1 GB
   - Add env var: `DB_PATH` = `/data/financeiq.db`
7. Click **Deploy**

Your app will be live at `https://financeiq-xxxx.onrender.com`

---

## Option 2: Railway.app (Easiest — $5/mo hobby plan)

1. Go to [railway.app](https://railway.app) and sign up
2. Click **New Project → Deploy from GitHub repo**
   - Or click **Empty Project → Add Service → GitHub Repo**
3. Railway auto-detects the Dockerfile
4. Add variables in the service settings:
   - `SECRET_KEY` = random long string
   - `ADMIN_PASS` = your admin password
   - `DB_PATH` = `/data/financeiq.db`
5. Add a **Volume** mounted at `/data`
6. Railway gives you a URL like `financeiq.up.railway.app`

Optional: Add a custom domain in Settings → Networking.

---

## Option 3: Fly.io (Global edge — free tier)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# From the project directory:
fly launch
# Say yes to defaults, choose a region close to you (e.g., fra for EU)

# Create persistent storage
fly volumes create financeiq_data --size 1 --region fra

# Set secrets
fly secrets set SECRET_KEY=$(openssl rand -hex 32)
fly secrets set ADMIN_PASS=YourStrongPassword

# Deploy
fly deploy
```

Your app: `https://financeiq.fly.dev`

---

## Option 4: VPS (DigitalOcean / Linode / AWS EC2)

### 1. Create a server
- DigitalOcean: $4/mo droplet (Ubuntu 24.04)
- Linode: $5/mo Nanode
- AWS: t3.micro free tier

### 2. SSH in and set up

```bash
ssh root@YOUR_SERVER_IP

# Install Python (usually pre-installed on Ubuntu)
apt update && apt install -y python3 caddy

# Create app directory
mkdir -p /opt/financeiq /data
cd /opt/financeiq

# Upload your files (from your local machine):
# scp server.py app.html root@YOUR_SERVER_IP:/opt/financeiq/
```

### 3. Create a systemd service

```bash
cat > /etc/systemd/system/financeiq.service << 'EOF'
[Unit]
Description=FinanceIQ
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/financeiq
Environment=PORT=8080
Environment=SECRET_KEY=CHANGE_THIS_TO_A_RANDOM_64_CHAR_HEX
Environment=ADMIN_PASS=YourStrongAdminPassword
Environment=DB_PATH=/data/financeiq.db
ExecStart=/usr/bin/python3 server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable financeiq
systemctl start financeiq
```

### 4. Set up HTTPS with Caddy (automatic SSL)

Point your domain's DNS A record to your server IP, then:

```bash
cat > /etc/caddy/Caddyfile << 'EOF'
financeiq.yourdomain.com {
    reverse_proxy localhost:8080
}
EOF

systemctl restart caddy
```

Done — your app is live at `https://financeiq.yourdomain.com` with automatic HTTPS.

---

## Option 5: Your own server / NAS

If you have a home server, NAS (Synology, etc.), or Raspberry Pi:

```bash
# Copy files to the server
scp server.py app.html user@server:/path/to/financeiq/

# SSH in and run
cd /path/to/financeiq
SECRET_KEY=$(openssl rand -hex 32) ADMIN_PASS=YourPass python3 server.py

# Access from your network: http://SERVER_IP:8080
```

For external access, set up port forwarding on your router (port 8080)
and use a free dynamic DNS service like [DuckDNS](https://www.duckdns.org/).

---

## After deployment — First steps

1. Open your app URL
2. The admin TOTP secret is printed in the server logs
   - On Render: check the "Logs" tab
   - On Railway: check "Deployments → View Logs"
   - On Fly: `fly logs`
   - On VPS: `journalctl -u financeiq`
3. Add the TOTP secret to your authenticator app (Google Authenticator, Authy)
4. Log in as `admin` with your ADMIN_PASS + 2FA code
5. You're in the admin panel — start approving users!

---

## Custom domain (optional)

All platforms support custom domains:

1. Buy a domain (Namecheap, Cloudflare, Google Domains)
2. Add a CNAME record pointing to your app URL
   - Render: `financeiq-xxxx.onrender.com`
   - Railway: `financeiq.up.railway.app`
   - Fly: `financeiq.fly.dev`
3. Add the custom domain in the platform settings
4. HTTPS is automatic on all platforms

---

## Security checklist for production

- [ ] Set a strong `SECRET_KEY` (64+ random hex chars)
- [ ] Set a strong `ADMIN_PASS` (not the default!)
- [ ] Use HTTPS (automatic on all platforms above)
- [ ] Save your admin TOTP secret securely
- [ ] Back up `/data/financeiq.db` regularly
- [ ] Consider rate limiting (add nginx/Caddy in front)
