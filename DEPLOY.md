# financiQ — Deployment Guide

## Your files

You only need 2 files to deploy:
- `server.py` — the backend (pure Python, zero dependencies)
- `app.html` — the frontend (single file, no build step)

Everything else (Dockerfile, Procfile, render.yaml, fly.toml) is for specific platforms.

---

## Database: Turso (Recommended — Free, persistent)

financiQ supports two database modes:
- **Turso** (cloud SQLite) — data persists forever, free 9GB tier, works across redeploys
- **Local SQLite** — fallback for development, data resets on redeploy for free hosting tiers

**Turso is strongly recommended for production.** Here's how to set it up:

### 1. Create a Turso account

Go to [turso.tech](https://turso.tech) and sign up (GitHub or email).

### 2. Install the Turso CLI

Mac/Linux:
```bash
curl -sSfL https://get.tur.so/install.sh | bash
```

Windows (PowerShell):
```powershell
iwr https://get.tur.so/install.ps1 -useb | iex
```

### 3. Create your database

```bash
turso auth login
turso db create financiq
```

### 4. Get your credentials

```bash
# Get your database URL
turso db show financiq --url
# Output: libsql://financiq-yourname.turso.io

# Create an auth token
turso db tokens create financiq
# Output: a long token string — copy this
```

**Important:** Change `libsql://` to `https://` in the URL.  
So `libsql://financiq-yourname.turso.io` becomes `https://financiq-yourname.turso.io`

### 5. Set environment variables

Add these to your hosting platform (Render, Railway, Fly, etc.):

| Key | Value |
|---|---|
| `TURSO_URL` | `https://financiq-yourname.turso.io` |
| `TURSO_TOKEN` | (the token from step 4) |

The server auto-detects: if both `TURSO_URL` and `TURSO_TOKEN` are set, it uses Turso. Otherwise it falls back to local SQLite.

### Turso free tier limits

- 9 GB storage
- 500 databases
- 1 billion row reads/month
- 25 million row writes/month

This is more than enough for a personal/family finance app.

---

## Option 1: Render.com (Recommended — Free tier)

**Time: ~5 minutes. No credit card needed.**

### Setup

1. Push `server.py` and `app.html` to a GitHub repo
2. Go to [render.com](https://render.com) → sign up → **New +** → **Web Service**
3. Connect your GitHub repo
4. Configure:
   - **Runtime**: Python 3
   - **Build Command**: `echo "no build needed"`
   - **Start Command**: `python3 server.py`
   - **Region**: Frankfurt or Amsterdam (closest to Israel)

### Environment Variables

Add these in the **Environment** tab:

| Key | Value |
|---|---|
| `PORT` | `8080` |
| `SECRET_KEY` | (click "Generate Value") |
| `ADMIN_PASS` | (choose a strong password) |
| `TURSO_URL` | `https://financiq-yourname.turso.io` |
| `TURSO_TOKEN` | (your Turso token) |

**No disk needed** when using Turso — your data lives in the cloud database.

### Deploy

Click **Create Web Service**. Your app will be live at `https://financiq-xxxx.onrender.com`

> **Note:** Render's free tier spins down after 15 minutes of inactivity. The first request after idle takes ~30 seconds. This is normal — your data is safe in Turso regardless.

---

## Option 2: Railway.app ($5/mo hobby plan)

1. Go to [railway.app](https://railway.app) → sign up
2. **New Project** → **Deploy from GitHub repo**
3. Railway auto-detects the Dockerfile
4. Add environment variables:
   - `SECRET_KEY` = random long string
   - `ADMIN_PASS` = your admin password
   - `TURSO_URL` = your Turso URL
   - `TURSO_TOKEN` = your Turso token
5. Railway gives you a URL like `financiq.up.railway.app`

---

## Option 3: Fly.io (Global edge — free tier)

```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# From the project directory:
fly launch
# Choose a region close to you (e.g., fra for Europe)

# Set secrets
fly secrets set SECRET_KEY=$(openssl rand -hex 32)
fly secrets set ADMIN_PASS=YourStrongPassword
fly secrets set TURSO_URL=https://financiq-yourname.turso.io
fly secrets set TURSO_TOKEN=your-turso-token

# Deploy
fly deploy
```

Your app: `https://financiq.fly.dev`

---

## Option 4: VPS (DigitalOcean / Linode / AWS EC2)

### 1. Create a server
- DigitalOcean: $4/mo droplet (Ubuntu 24.04)
- Linode: $5/mo Nanode
- AWS: t3.micro free tier

### 2. SSH in and set up

```bash
ssh root@YOUR_SERVER_IP
apt update && apt install -y python3 caddy
mkdir -p /opt/financiq
cd /opt/financiq

# Upload your files (from your local machine):
# scp server.py app.html root@YOUR_SERVER_IP:/opt/financiq/
```

### 3. Create a systemd service

```bash
cat > /etc/systemd/system/financiq.service << 'EOF'
[Unit]
Description=financiQ
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/financiq
Environment=PORT=8080
Environment=SECRET_KEY=CHANGE_THIS_TO_A_RANDOM_64_CHAR_HEX
Environment=ADMIN_PASS=YourStrongAdminPassword
Environment=TURSO_URL=https://financiq-yourname.turso.io
Environment=TURSO_TOKEN=your-turso-token
ExecStart=/usr/bin/python3 server.py
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable financiq
systemctl start financiq
```

### 4. Set up HTTPS with Caddy (automatic SSL)

Point your domain's DNS A record to your server IP, then:

```bash
cat > /etc/caddy/Caddyfile << 'EOF'
financiq.yourdomain.com {
    reverse_proxy localhost:8080
}
EOF

systemctl restart caddy
```

Done — `https://financiq.yourdomain.com` with automatic HTTPS.

---

## Option 5: Local / Home Server / NAS

For development or home network use (no Turso needed):

```bash
cd /path/to/financiq
SECRET_KEY=$(openssl rand -hex 32) ADMIN_PASS=YourPass python3 server.py
# Access: http://localhost:8080
```

Data is stored locally in `financiq.db` next to `server.py`.

---

## After deployment — First steps

1. Open your app URL
2. Check the **Logs** for the admin credentials:
   - Render: **Logs** tab
   - Railway: **Deployments → View Logs**
   - Fly: `fly logs`
   - VPS: `journalctl -u financiq`
3. You'll see:
   ```
   ============================================================
     ADMIN: admin / YourAdminPassword
   ============================================================
   ```
4. Log in with `admin` and your `ADMIN_PASS`
5. You'll land in the **Admin Panel**:
   - Set the **AI API Key** in Global Settings (Anthropic or OpenAI)
   - Set the **currency symbol** (₪ by default)
6. Switch to the **App** to start using financiQ
7. The **onboarding questionnaire** will guide you through setup
8. Register additional users — they'll need admin approval

---

## Environment variables reference

| Variable | Required | Description |
|---|---|---|
| `PORT` | Yes | Server port (use `8080`) |
| `SECRET_KEY` | Yes | Random string for session signing (64+ chars) |
| `ADMIN_PASS` | Yes | Admin account password |
| `TURSO_URL` | Recommended | Turso database URL (`https://...turso.io`) |
| `TURSO_TOKEN` | Recommended | Turso auth token |
| `DB_PATH` | No | Local SQLite path (only if not using Turso) |

---

## Custom domain (optional)

All platforms support custom domains:

1. Buy a domain (Namecheap, Cloudflare, Porkbun)
2. Add a CNAME record pointing to your app URL:
   - Render: `financiq-xxxx.onrender.com`
   - Railway: `financiq.up.railway.app`
   - Fly: `financiq.fly.dev`
3. Add the custom domain in the platform settings
4. HTTPS is automatic on all platforms

---

## Security checklist

- [ ] Set a strong `SECRET_KEY` (64+ random hex chars)
- [ ] Set a strong `ADMIN_PASS` (not the default!)
- [ ] Use Turso for persistent, reliable data storage
- [ ] Use HTTPS (automatic on all platforms above)
- [ ] Set the AI API key only through the Admin Panel (never in env vars)
- [ ] Review and approve user registrations promptly

---

## Troubleshooting

**App won't start / crashes on deploy:**
- Check the logs for the error message
- Make sure `PORT` is set to `8080`
- If using Turso, verify `TURSO_URL` starts with `https://` (not `libsql://`)

**Data disappears after redeploy:**
- You're not using Turso — set `TURSO_URL` and `TURSO_TOKEN`
- Or add a persistent disk on your platform

**AI features don't work:**
- Set the AI API key in Admin Panel → Global Settings
- Key must be a valid Anthropic (`sk-ant-...`) or OpenAI (`sk-...`) key

**Can't login / "Invalid credentials":**
- Check the logs for the admin password
- Too many failed attempts? Wait 5 minutes (rate limiting)

**Hebrew/RTL not working:**
- Switch language in Settings or the sidebar toggle
- Language is saved per-user across devices
