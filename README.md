```
  ██████╗ ██████╗
  ╚═══██╗╚════██╗
   ████╔╝  █████╔╝
  ██╔═══╝  ╚═══██╗
  ███████╗██████╔╝
  ╚══════╝╚═════╝
```

# FNORD-PROXY

**Honeypot reverse proxy with real-time analytics dashboard.**

Drop-in nginx honeypot that sits in front of your services, catches attackers probing for common vulnerabilities, logs everything, auto-bans via fail2ban, and gives you a live dashboard to watch it all happen.

Themed after **"23 - Nichts ist wie es scheint"** / Anonymous / 1984 in RAL 3000 Feuerrot.

## What it does

1. **Honeypot locations** - Fake `.env`, `wp-login.php`, `/admin`, `phpMyAdmin`, `.git/config`, `backup.sql` etc. that look real enough to fool scanners
2. **Logs everything** - IP, timestamp, path, user agent, referer in a parseable format
3. **Auto-bans** - fail2ban jail that bans IPs after 3 honeypot hits
4. **Live dashboard** - Real-time analytics with:
   - Fail2ban stats (bans, timeline, heatmap, top IPs, countries)
   - SSH attack pattern analysis (brute force detection, username categorization, attack waves)
   - Honeypot access stats (top paths, IPs, user agents, timeline)
5. **Landing page** - Themed decoy page for the domain
6. **Transparent proxy** - Real traffic passes through to your actual service

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/fnord-proxy-honeypot-ai.git
cd fnord-proxy-honeypot-ai
sudo ./install.sh -d example.com -b http://127.0.0.1:8080
```

### Options

```
-d, --domain DOMAIN      Your domain name
-b, --backend URL        Backend service to proxy (leave empty for landing page only)
-h, --bind-host HOST     Dashboard bind address (default: 127.0.0.1)
-p, --bind-port PORT     Dashboard port (default: 8888)
--skip-nginx             Don't install nginx config
--skip-fail2ban          Don't install fail2ban config
--skip-landing           Don't install landing page
```

### Landing page only (no backend)

```bash
sudo ./install.sh -d honeypot.example.com
```

### With backend service

```bash
sudo ./install.sh -d vault.example.com -b http://10.0.0.5:80
```

### Bind dashboard to Tailscale

```bash
sudo ./install.sh -d example.com -b http://127.0.0.1:8080 -h 100.64.0.1 -p 8888
```

## Requirements

- Linux (Debian/Ubuntu tested)
- nginx
- fail2ban
- Python 3 + Flask
- SSL certs (Let's Encrypt recommended)

## Project Structure

```
fnord-proxy-honeypot-ai/
├── app.py                          # Dashboard (Flask + embedded HTML)
├── install.sh                      # Installer
├── fnord.conf.example              # Config template
├── fnord-proxy.service             # systemd unit
├── nginx/
│   ├── honeypot-log-format.conf    # nginx log format
│   └── fnord-proxy.conf.template   # Site config with honeypot locations
├── fail2ban/
│   ├── fnord-honeypot.conf         # fail2ban filter
│   └── jail-fnord.conf             # fail2ban jail
└── landing/
    └── index.html                  # 23-themed landing page
```

## Configuration

After install, edit `/opt/fnord-proxy/fnord.conf`:

```ini
BIND_HOST=127.0.0.1
BIND_PORT=8888
HONEYPOT_LOG=/var/log/nginx/honeypot.log
F2B_DB=/var/lib/fail2ban/fail2ban.sqlite3
F2B_LOG=/var/log/fail2ban.log
```

## Adding custom honeypot paths

Edit your nginx site config and add locations:

```nginx
location = /your-custom-trap {
    access_log /var/log/nginx/honeypot.log honeypot_log;
    return 200 "your fake response";
}
```

## Dashboard

The dashboard runs as a systemd service and is only accessible from the bind address (default: localhost). Access it via:

- **Tailscale**: Bind to your Tailscale IP
- **SSH tunnel**: `ssh -L 8888:127.0.0.1:8888 yourserver`

### Sections

| # | Section | Description |
|---|---------|-------------|
| 01 | Fail2Ban | Ban stats, timeline, heatmap, top IPs, countries, repeat offenders |
| 23 | Angriffsmuster | SSH brute force analysis, username categories, attack waves |
| 05 | Honeypot | Access stats, top paths, IPs, user agents, live feed |

## How it works in front of a service

```
Internet → nginx (443)
              ├── /.env           → HONEYPOT (log + fake response)
              ├── /wp-login.php   → HONEYPOT (log + fake response)
              ├── /admin          → HONEYPOT (log + fake response)
              ├── /.git/config    → HONEYPOT (log + fake response)
              └── /               → proxy_pass → Your Real Service
                                                  (Vaultwarden, Nextcloud, etc.)
```

fail2ban watches the honeypot log and bans IPs after 3 hits. The dashboard reads the logs, fail2ban DB, and SSH journal for real-time analytics.

## Built with AI

This project was built interactively with Claude Code (Anthropic) as part of a homelab security setup. The entire codebase - nginx configs, Flask dashboard, fail2ban integration, install script, and the 23-themed UI - was developed in a single conversation session.

## License

MIT

---

*FNORD // 2+2=5 // ILLUMINATUS!*

*"Alles ist mit allem verbunden. Nichts ist, was es zu sein scheint. Alles ist moeglich."*
