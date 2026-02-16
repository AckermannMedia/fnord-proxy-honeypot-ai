```
  ██████╗ ██████╗
  ╚═══██╗╚════██╗
   ████╔╝  █████╔╝
  ██╔═══╝  ╚═══██╗
  ███████╗██████╔╝
  ╚══════╝╚═════╝
  FNORD-PROXY
```

# FNORD-PROXY — Honeypot Reverse Proxy with Real-Time Dashboard

A drop-in **nginx honeypot reverse proxy** that sits in front of your web services, catches attackers probing for common vulnerabilities, auto-bans them via fail2ban, and gives you a **live analytics dashboard** to monitor everything in real time.

Themed after the movie **"23 - Nichts ist wie es scheint"** (Karl Koch / Chaos Computer Club), **Anonymous**, and George Orwell's **1984** — styled in **RAL 3000 Feuerrot** with CRT scanlines, glitch effects, and retro terminal aesthetics.

---

## Why This Exists

Every server connected to the internet is under constant, automated attack. Within minutes of going online, bots start probing for `.env` files, WordPress logins, exposed Git repositories, phpMyAdmin instances, and dozens of other common misconfigurations. This isn't targeted — it's industrial-scale scanning by botnets that don't care what your server actually runs. They just spray requests at every IP and see what sticks.

The numbers are staggering. A single VPS with nothing but SSH and nginx will see **hundreds to thousands of brute force attempts per day**. Credential stuffing bots cycle through leaked username/password lists. Vulnerability scanners probe for every CVE published in the last decade. Most of this traffic comes from compromised machines in massive botnets — your server is just one of millions being hit simultaneously.

**The traditional response is passive:** fail2ban watches logs, bans IPs after failed attempts, and that's it. You know you're being attacked, but you don't see the patterns. You don't know which traps are being triggered, which countries the attacks come from, whether it's a coordinated wave or background noise, or what usernames the bots are currently trying.

**FNORD-PROXY takes an active approach:**

1. **Turn their scanning against them.** Instead of just blocking probes, serve fake but realistic responses. An attacker hitting `/.env` gets back what looks like real AWS credentials. This wastes their time — they'll try to use the fake keys, maybe probe deeper, and every additional request gets logged and accelerates their ban.

2. **See everything in real time.** The dashboard doesn't just count attacks — it categorizes them. You can see that the current bot wave is trying crypto-related usernames (solana, validator, miner), that attacks peak at 3 AM UTC, that one IP from Vietnam is hitting you at 45 attempts per minute, and that the `.env` honeypot catches more scanners than all WordPress traps combined.

3. **Protect real services transparently.** The honeypot sits as an nginx layer in front of your actual application. Legitimate API calls, web requests, and client connections pass through untouched. Attackers get trapped before they ever reach your service.

### Why AI?

This entire project — the nginx honeypot configs with realistic fake responses, the Flask dashboard with three analytics engines, the fail2ban integration, the install script, the themed UI — was built in a single interactive session with **Claude Code**. Not as a gimmick, but because this is exactly the kind of project where AI-assisted development shines:

- **Cross-domain integration** — nginx config syntax, Python Flask, JavaScript frontend, fail2ban filter regex, systemd units, shell scripting — all in one project. An AI assistant can context-switch between these seamlessly.
- **Realistic fake data** — the honeypot responses need to look convincing. AI can generate plausible `.env` files, database dumps, API responses, and login forms that waste attacker time.
- **Pattern recognition** — the SSH attack analysis (username categorization, brute force velocity calculation, attack wave detection) was designed iteratively by discussing what patterns are actually interesting to see.
- **Rapid iteration** — from "can we add fail2ban stats?" to a working dashboard section with six metrics, timeline charts, heatmaps, and GeoIP lookups in minutes, not hours.

The bots are automated. The defense should be too — or at least, building it should be fast enough to keep up.

---

## Features

### Honeypot Reverse Proxy
- **30+ trap locations** that mimic real vulnerabilities — `.env` files, WordPress login, admin panels, phpMyAdmin, `.git/config`, `backup.sql`, GraphQL endpoints, debug pages, and more
- **Realistic fake responses** that keep scanners engaged (fake database credentials, fake WordPress forms, fake API responses)
- **Transparent proxy** — legitimate traffic passes through untouched to your real backend service
- **Works with any service** — Vaultwarden, Nextcloud, Gitea, any web application behind nginx

### Automatic Banning
- **fail2ban integration** with custom filter and jail
- Auto-bans IPs after 3 honeypot hits (configurable)
- 24-hour ban duration (configurable)
- Blocks on all HTTP/HTTPS ports via iptables

### Live Analytics Dashboard
Three sections with real-time data, auto-refreshing every 30 seconds:

| Section | # | Tag | What it shows |
|---------|---|-----|---------------|
| **Fail2Ban** | 01 | INGSOC DEFENCE GRID | Total bans, currently banned, bans/day timeline, hourly heatmap, top banned IPs with GeoIP, country breakdown, repeat offenders, live ban/unban feed |
| **Attack Patterns** | 23 | WE ARE LEGION | SSH brute force analysis (24h window), top attempted usernames, username categorization (system/database/devops/crypto/services), per-IP attack velocity, attack wave visualization in 10-minute buckets |
| **Honeypot** | 05 | EXPECT US | Total honeypot hits, top triggered paths, top attacker IPs with GeoIP, user agent analysis, 14-day timeline, hourly heatmap, live access feed |

### Dashboard Features
- **GeoIP lookup** for all IPs (country, city, ISP) via ip-api.com with caching
- **SSH journal analysis** — parses `journalctl -u ssh` for brute force detection
- **Brute force velocity** — calculates attempts/minute per attacker IP
- **Username categorization** — groups attempted usernames into system, database, devops, crypto, services, custom
- **Attack wave detection** — buckets attempts into 10-minute windows to visualize coordinated attacks

### 23 Theme
- **RAL 3000 Feuerrot** (#AF2B1E) color scheme throughout
- **VT323 + Share Tech Mono** retro terminal fonts
- **CRT scanline overlay** with subtle flicker animation
- **Glitch effects** on the "23" logo
- **Clock** that shows 23:23:23 every 23rd second
- Footer: *FNORD // 2+2=5 // ILLUMINATUS!*

---

## Quick Start

```bash
git clone https://github.com/AckermannMedia/fnord-proxy-honeypot-ai.git
cd fnord-proxy-honeypot-ai
sudo ./install.sh -d example.com -b http://127.0.0.1:8080
```

The installer will:
1. Check and install dependencies (Python 3, Flask)
2. Deploy the dashboard to `/opt/fnord-proxy/`
3. Generate the nginx site config with all honeypot locations
4. Install the fail2ban filter and jail
5. Create and enable a systemd service
6. Start the dashboard

---

## Installation Options

```
Usage: sudo ./install.sh [OPTIONS]

Options:
  -d, --domain DOMAIN      Domain name (required)
  -b, --backend URL        Backend service URL to proxy to
  -h, --bind-host HOST     Dashboard bind address (default: 127.0.0.1)
  -p, --bind-port PORT     Dashboard port (default: 8888)
  --skip-nginx             Skip nginx configuration
  --skip-fail2ban          Skip fail2ban configuration
  --skip-landing           Skip landing page installation
  --help                   Show help
```

### Examples

**Honeypot in front of a web service:**
```bash
sudo ./install.sh -d vault.example.com -b http://127.0.0.1:8080
```

**Standalone honeypot with landing page (no backend):**
```bash
sudo ./install.sh -d honeypot.example.com
```

**Dashboard accessible via Tailscale:**
```bash
sudo ./install.sh -d example.com -b http://127.0.0.1:8080 \
  --bind-host 100.x.y.z --bind-port 8888
```

**Dashboard accessible via SSH tunnel:**
```bash
# Install with default localhost binding
sudo ./install.sh -d example.com -b http://127.0.0.1:8080

# Then from your local machine:
ssh -L 8888:127.0.0.1:8888 yourserver
# Open http://localhost:8888
```

---

## Architecture

```
                         Internet
                            │
                            ▼
                    ┌───────────────┐
                    │  nginx (443)  │
                    └───────┬───────┘
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────────┐
        │ Honeypot │ │ Honeypot │ │  proxy_pass   │
        │  /.env   │ │ /admin   │ │  location /   │
        │  /wp-*   │ │ /.git/*  │ │               │
        └────┬─────┘ └────┬─────┘ └──────┬───────┘
             │             │              │
             ▼             ▼              ▼
      ┌─────────────────────┐    ┌──────────────┐
      │  honeypot.log       │    │ Your Backend │
      │  (nginx log file)   │    │  Service     │
      └──────────┬──────────┘    └──────────────┘
                 │
        ┌────────┴────────┐
        │                 │
        ▼                 ▼
  ┌───────────┐    ┌─────────────┐
  │ fail2ban  │    │  Dashboard  │
  │ (auto-ban │    │  (Flask)    │
  │  after 3  │    │  :8888      │
  │  hits)    │    └──────┬──────┘
  └───────────┘           │
                    ┌─────┴──────┐
                    │            │
                    ▼            ▼
             ┌──────────┐ ┌───────────┐
             │ fail2ban │ │ journalctl│
             │ SQLite   │ │ SSH logs  │
             │ database │ │ (24h)     │
             └──────────┘ └───────────┘
```

### How the proxy works

nginx uses **exact-match locations** (`location =`) for honeypot paths, which take priority over the general `location /` prefix match. This means:

- `GET /.env` → hits the honeypot, gets logged, attacker gets a fake `.env` file
- `GET /wp-login.php` → hits the honeypot, gets logged, attacker sees a fake WordPress login
- `GET /api/real-endpoint` → passes through to your backend service normally
- `POST /identity/connect/token` → passes through to your backend service normally

Your real service works exactly as before. Attackers just get trapped and logged on the way in.

---

## Honeypot Locations

The following paths are trapped by default:

| Category | Paths | Fake Response |
|----------|-------|---------------|
| **Environment files** | `/.env`, `/.env.backup` | Fake credentials, API keys |
| **WordPress** | `/wp-login.php`, `/wp-admin/`, `/xmlrpc.php`, `/wp-includes/*`, `/wp-content/*` | Fake login form, XML-RPC response |
| **Admin panels** | `/admin`, `/admin/login`, `/administrator` | Fake login form |
| **phpMyAdmin** | `/phpmyadmin`, `/phpmyadmin/index.php` | Fake phpMyAdmin login |
| **Git** | `/.git/config`, `/.git/HEAD`, `/.git/*` | Fake repo config with SSH URL |
| **Config/Backup** | `/config.php`, `/backup.sql` | Fake DB credentials, SQL dump |
| **Debug/Status** | `/debug`, `/server-status` | Fake debug info, Apache status |
| **APIs** | `/api/v1/users`, `/graphql` | Fake user data, GraphQL schema |
| **Scanners** | `/cgi-bin/*`, `/shell`, `/eval`, `/setup`, `/install`, `/console`, `/actuator`, `/solr` | 404 |

All responses contain **realistic but completely fake data** designed to waste attacker time and trigger further probing (which gets them banned faster).

### Adding Custom Honeypot Paths

Edit your nginx site config (`/etc/nginx/sites-available/fnord-*`) and add:

```nginx
location = /your-custom-trap {
    access_log /var/log/nginx/honeypot.log honeypot_log;
    default_type text/html;
    return 200 "your fake response here";
}
```

Reload nginx: `sudo systemctl reload nginx`

---

## Dashboard Sections

### 01 — Fail2Ban (INGSOC DEFENCE GRID)

| Metric | Description |
|--------|-------------|
| Bans Total | All-time ban count from fail2ban SQLite DB |
| Today | Bans today from fail2ban log |
| Currently Banned | IPs currently in the ban list (live from `fail2ban-client`) |
| Unique IPs | Distinct IPs ever banned |
| Attacks/Min | Found events per minute in the last hour |
| Attempts Today | Total "Found" events today |

**Charts:** 14-day ban timeline, 24-hour heatmap, top banned IPs with GeoIP, country breakdown with bar chart, repeat offenders list, live ban/unban/found event feed.

**Jail cards:** Each fail2ban jail gets its own card showing currently banned count, total bans, failed attempts, and a list of currently banned IPs.

### 23 — Attack Patterns / SSH Analysis (WE ARE LEGION)

Parses the last 24 hours of SSH logs from `journalctl -u ssh` and analyzes:

| Metric | Description |
|--------|-------------|
| Attempts | Total invalid user + failed password events |
| Attackers | Unique source IPs |
| Usernames | Unique usernames tried |
| Invalid User | Attempts with non-existent usernames |
| Failed PW | Attempts with wrong passwords for existing users |
| Accepted | Successful logins (should be low / only yours) |

**Username categorization** groups attempted usernames into:
- **system** — root, admin, test, guest, etc.
- **database** — postgres, mysql, oracle, redis, etc.
- **devops** — ubuntu, docker, ansible, jenkins, git, etc.
- **crypto** — solana, validator, miner, eth, bitcoin, etc.
- **services** — ftp, mail, nginx, apache, vpn, etc.
- **custom** — everything else

**Brute force detection** shows top attacker IPs with:
- Total attempts
- Attack velocity (attempts per minute)
- Number of unique usernames tried
- Sample usernames
- GeoIP data (country, ISP)

**Attack waves** visualize attempt density in 10-minute buckets over the last 12 hours, revealing coordinated attack patterns.

### 05 — Honeypot (EXPECT US)

| Metric | Description |
|--------|-------------|
| Total Hits | All-time honeypot access count |
| Today | Hits today |
| Unique IPs | Distinct attacker IPs |
| Top Attacker | Most active IP with country |

**Charts:** Top triggered paths (which traps are most popular), top attacker IPs with GeoIP, 14-day timeline, 24-hour heatmap, user agent analysis, live access feed.

---

## Configuration

After installation, the config file is at `/opt/fnord-proxy/fnord.conf`:

```ini
# Dashboard bind address
BIND_HOST=127.0.0.1
BIND_PORT=8888

# Log and database paths
HONEYPOT_LOG=/var/log/nginx/honeypot.log
F2B_DB=/var/lib/fail2ban/fail2ban.sqlite3
F2B_LOG=/var/log/fail2ban.log
```

Configuration can also be set via environment variables prefixed with `FNORD_`:
```bash
FNORD_BIND_HOST=0.0.0.0 FNORD_BIND_PORT=9999 python3 app.py
```

### fail2ban Tuning

Edit `/etc/fail2ban/jail.d/fnord-honeypot.conf`:

```ini
[fnord-honeypot]
enabled = true
filter = fnord-honeypot
logpath = /var/log/nginx/honeypot.log
maxretry = 3        # Ban after this many honeypot hits
findtime = 3600     # Within this window (seconds)
bantime = 86400     # Ban duration (seconds) — default 24h
```

---

## Project Structure

```
fnord-proxy-honeypot-ai/
├── app.py                          # Flask dashboard (Python backend + embedded 23-themed HTML/CSS/JS)
├── install.sh                      # Interactive installer with dependency checks
├── fnord.conf.example              # Configuration template
├── fnord-proxy.service             # systemd service unit
├── nginx/
│   ├── honeypot-log-format.conf    # Custom nginx log format for honeypot entries
│   └── fnord-proxy.conf.template   # Full nginx site config with 30+ honeypot locations
├── fail2ban/
│   ├── fnord-honeypot.conf         # fail2ban filter definition
│   └── jail-fnord.conf             # fail2ban jail configuration
├── landing/
│   └── index.html                  # 23-themed decoy landing page
├── LICENSE                         # MIT License
└── README.md
```

---

## Requirements

| Dependency | Purpose | Install |
|------------|---------|---------|
| **nginx** | Reverse proxy + honeypot locations | `apt install nginx` |
| **fail2ban** | Automatic IP banning | `apt install fail2ban` |
| **Python 3** | Dashboard backend | `apt install python3` |
| **Flask** | Web framework for dashboard | `pip3 install flask` |
| **SSL certificates** | HTTPS for the proxy | [Let's Encrypt](https://letsencrypt.org/) / `certbot` |

Tested on Debian 12 and Ubuntu 22.04/24.04. Should work on any systemd-based Linux distribution with nginx.

---

## Log Format

The honeypot uses a custom nginx log format:

```
$remote_addr|$time_iso8601|$request_uri|$status|$http_user_agent|$http_referer
```

Example entry:
```
203.0.113.42|2026-02-16T14:23:05+00:00|/.env|200|Mozilla/5.0 (compatible; scanner)|
```

Pipe-delimited for easy parsing. The dashboard reads this format directly.

---

## Security Notes

- The dashboard **only binds to localhost by default** — it is not exposed to the internet
- Access it via **SSH tunnel** or bind to a **VPN/Tailscale IP**
- The honeypot responses contain **only fake data** — no real credentials or information
- fail2ban bans are applied via **iptables** and affect all ports, not just HTTP
- GeoIP lookups use the free **ip-api.com** service (rate limited, results are cached in memory)

---

## Built with AI

This project was built interactively with **Claude Code** (Anthropic's CLI tool) as part of a homelab security setup. The entire codebase — nginx honeypot configs with 30+ realistic trap locations, a Flask dashboard with three separate analytics engines (fail2ban stats, SSH attack pattern analysis, honeypot access tracking), fail2ban filter and jail integration, a systemd service, an interactive install script, a themed landing page, and the full 23-themed dashboard UI with CRT effects — was developed through conversation and packaged into this repository.

No code was written manually. Every file was generated, tested, and iterated on through natural language prompts. The project went from "can we put honeypots in front of my Vaultwarden?" to a fully-featured, deployable security tool with real-time analytics in a single session.

## License

[MIT](LICENSE)

---

*FNORD // 2+2=5 // ILLUMINATUS!*

*"Everything is connected. Nothing is what it seems. Everything is possible."*
