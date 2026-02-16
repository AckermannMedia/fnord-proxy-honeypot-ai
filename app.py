#!/usr/bin/env python3
"""
FNORD-PROXY Dashboard
Honeypot analytics dashboard with fail2ban + SSH attack pattern analysis.
Themed after "23 - Nichts ist wie es scheint" / Anonymous / 1984.

Part of fnord-proxy: https://github.com/YOUR_USERNAME/fnord-proxy-honeypot-ai
"""

import os
import json
import sqlite3
import subprocess
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

# --- Configuration (override via environment or config file) ---
CONF_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fnord.conf")

def load_config():
    """Load config from fnord.conf if it exists."""
    cfg = {}
    if os.path.exists(CONF_FILE):
        with open(CONF_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    cfg[k.strip()] = v.strip().strip('"').strip("'")
    return cfg

_cfg = load_config()

HONEYPOT_LOG = _cfg.get("HONEYPOT_LOG", os.environ.get("FNORD_HONEYPOT_LOG", "/var/log/nginx/honeypot.log"))
HONEYPOT_LOG_OLD = HONEYPOT_LOG + ".1"
F2B_DB = _cfg.get("F2B_DB", os.environ.get("FNORD_F2B_DB", "/var/lib/fail2ban/fail2ban.sqlite3"))
F2B_LOG = _cfg.get("F2B_LOG", os.environ.get("FNORD_F2B_LOG", "/var/log/fail2ban.log"))
F2B_LOG_OLD = F2B_LOG + ".1"
BIND_HOST = _cfg.get("BIND_HOST", os.environ.get("FNORD_BIND_HOST", "127.0.0.1"))
BIND_PORT = int(_cfg.get("BIND_PORT", os.environ.get("FNORD_BIND_PORT", "8888")))

GEOIP_CACHE = {}


def parse_logfile(logfile):
    entries = []
    if not os.path.exists(logfile):
        return entries
    with open(logfile, "r") as f:
        for line in f:
            parts = line.strip().split("|")
            if len(parts) >= 5:
                raw_path = parts[2].split(" ")[0] if parts[2] else ""
                path = raw_path.split("?")[0]
                entries.append({
                    "ip": parts[0],
                    "time": parts[1],
                    "path": path,
                    "status": parts[3],
                    "ua": parts[4] if len(parts) > 4 else "",
                    "ref": parts[5] if len(parts) > 5 else "",
                })
    return entries


def parse_honeypot_logs():
    entries = []
    for logfile in (HONEYPOT_LOG_OLD, HONEYPOT_LOG):
        entries.extend(parse_logfile(logfile))
    return entries


def geoip_lookup(ip):
    if ip in GEOIP_CACHE:
        return GEOIP_CACHE[ip]
    try:
        import urllib.request
        resp = urllib.request.urlopen(
            f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp,query",
            timeout=3,
        )
        data = json.loads(resp.read())
        GEOIP_CACHE[ip] = data
        return data
    except:
        return {"country": "Unknown", "countryCode": "??", "city": "", "isp": ""}


def get_f2b_live_status():
    """Get live fail2ban status via fail2ban-client."""
    result = {"jails": []}
    try:
        out = subprocess.check_output(
            ["fail2ban-client", "status"], text=True, timeout=5
        )
        jails = []
        for line in out.splitlines():
            if "Jail list:" in line:
                jails = [j.strip() for j in line.split(":", 1)[1].split(",") if j.strip()]

        for jail in jails:
            try:
                jout = subprocess.check_output(
                    ["fail2ban-client", "status", jail], text=True, timeout=5
                )
                info = {"name": jail, "failed": 0, "total_failed": 0,
                        "banned": 0, "total_banned": 0, "banned_ips": []}
                for line in jout.splitlines():
                    line = line.strip()
                    if "Currently failed:" in line:
                        info["failed"] = int(line.split(":")[-1].strip())
                    elif "Total failed:" in line:
                        info["total_failed"] = int(line.split(":")[-1].strip())
                    elif "Currently banned:" in line:
                        info["banned"] = int(line.split(":")[-1].strip())
                    elif "Total banned:" in line:
                        info["total_banned"] = int(line.split(":")[-1].strip())
                    elif "Banned IP list:" in line:
                        ips_str = line.split(":", 1)[-1].strip()
                        if ips_str:
                            info["banned_ips"] = ips_str.split()
                result["jails"].append(info)
            except:
                pass
    except:
        pass
    return result


def get_f2b_db_stats():
    """Get historical fail2ban data from SQLite database."""
    stats = {
        "total_bans": 0,
        "unique_ips": 0,
        "top_banned": [],
        "recent_bans": [],
        "bans_timeline": [],
        "bans_by_hour": {},
        "repeat_offenders": [],
        "top_countries": [],
    }
    if not os.path.exists(F2B_DB):
        return stats

    try:
        conn = sqlite3.connect(F2B_DB)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        c.execute("SELECT COUNT(*) FROM bans")
        stats["total_bans"] = c.fetchone()[0]

        c.execute("SELECT COUNT(DISTINCT ip) FROM bans")
        stats["unique_ips"] = c.fetchone()[0]

        c.execute("""
            SELECT ip, COUNT(*) as cnt
            FROM bans GROUP BY ip ORDER BY cnt DESC LIMIT 15
        """)
        top_ips = []
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            top_ips.append({
                "ip": row["ip"], "count": row["cnt"],
                "country": geo.get("country", "?"), "cc": geo.get("countryCode", "??"),
                "city": geo.get("city", ""), "isp": geo.get("isp", ""),
            })
        stats["top_banned"] = top_ips

        c.execute("""
            SELECT ip, jail, datetime(timeofban, 'unixepoch') as time, bancount
            FROM bans ORDER BY timeofban DESC LIMIT 50
        """)
        stats["recent_bans"] = [
            {"ip": r["ip"], "jail": r["jail"], "time": r["time"], "bancount": r["bancount"]}
            for r in c.fetchall()
        ]

        cutoff = int((datetime.now() - timedelta(days=14)).timestamp())
        c.execute("""
            SELECT date(timeofban, 'unixepoch') as day, COUNT(*) as cnt
            FROM bans WHERE timeofban > ? GROUP BY day ORDER BY day
        """, (cutoff,))
        stats["bans_timeline"] = [
            {"date": r["day"], "count": r["cnt"]} for r in c.fetchall()
        ]

        c.execute("""
            SELECT strftime('%H', timeofban, 'unixepoch') as hour, COUNT(*) as cnt
            FROM bans GROUP BY hour
        """)
        stats["bans_by_hour"] = {r["hour"]: r["cnt"] for r in c.fetchall()}

        c.execute("""
            SELECT ip, COUNT(*) as cnt, datetime(MAX(timeofban), 'unixepoch') as last_ban
            FROM bans GROUP BY ip HAVING cnt > 1 ORDER BY cnt DESC LIMIT 15
        """)
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            stats["repeat_offenders"].append({
                "ip": row["ip"], "count": row["cnt"], "last_ban": row["last_ban"],
                "country": geo.get("country", "?"), "cc": geo.get("countryCode", "??"),
                "isp": geo.get("isp", ""),
            })

        c.execute("SELECT DISTINCT ip FROM bans")
        country_counter = Counter()
        for row in c.fetchall():
            geo = geoip_lookup(row["ip"])
            cc = geo.get("countryCode", "??")
            country = geo.get("country", "Unknown")
            country_counter[(cc, country)] += 1
        stats["top_countries"] = [
            {"cc": cc, "country": cn, "count": cnt}
            for (cc, cn), cnt in country_counter.most_common(10)
        ]

        conn.close()
    except Exception as e:
        stats["error"] = str(e)

    return stats


def get_attack_patterns():
    """Analyze SSH journal logs for attack patterns."""
    patterns = {
        "top_usernames": [], "attack_types": [], "brute_force_ips": [],
        "attack_waves": [], "username_categories": {}, "auth_methods": {},
        "velocity": [],
    }
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", "ssh", "--no-pager", "--since", "24 hours ago", "-o", "short-iso"],
            text=True, timeout=15,
        )
        lines = out.strip().split("\n")

        usernames = []
        ips_timestamps = defaultdict(list)
        invalid_users = []
        failed_passwords = []
        preauth_closed = 0
        accepted = 0
        timeout_count = 0
        methods = Counter()

        for line in lines:
            m = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
            if m:
                usernames.append(m.group(1))
                invalid_users.append({"user": m.group(1), "ip": m.group(2)})
                ts = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                if ts:
                    ips_timestamps[m.group(2)].append(ts.group(1))
                continue

            m = re.search(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)", line)
            if m:
                failed_passwords.append({"user": m.group(1), "ip": m.group(2)})
                ts = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
                if ts:
                    ips_timestamps[m.group(2)].append(ts.group(1))
                methods["password"] += 1
                continue

            m = re.search(r"Accepted (\S+) for (\S+) from ([\d.]+)", line)
            if m:
                accepted += 1
                methods[m.group(1)] += 1
                continue

            if "preauth" in line:
                preauth_closed += 1
            if "Timeout before authentication" in line:
                timeout_count += 1

        user_counts = Counter(usernames).most_common(20)
        patterns["top_usernames"] = [{"user": u, "count": c} for u, c in user_counts]

        categories = {
            "system": ["root", "admin", "administrator", "test", "user", "guest", "info", "support"],
            "database": ["postgres", "mysql", "oracle", "mongo", "redis", "db", "database"],
            "devops": ["ubuntu", "centos", "debian", "docker", "ansible", "jenkins", "git", "deploy", "ci"],
            "crypto": ["solana", "sol", "solv", "validator", "miner", "eth", "bitcoin", "node", "jito"],
            "services": ["ftp", "ftptest", "mail", "www", "nginx", "apache", "tomcat", "vpn", "proxy"],
            "custom": [],
        }
        cat_counts = defaultdict(int)
        for user in usernames:
            categorized = False
            for cat, names in categories.items():
                if user.lower() in names:
                    cat_counts[cat] += 1
                    categorized = True
                    break
            if not categorized:
                cat_counts["custom"] += 1
        patterns["username_categories"] = [
            {"category": k, "count": v} for k, v in sorted(cat_counts.items(), key=lambda x: -x[1])
        ]

        patterns["attack_types"] = [
            {"type": "Invalid User", "count": len(invalid_users), "color": "orange"},
            {"type": "Failed Password", "count": len(failed_passwords), "color": "red"},
            {"type": "Preauth Disconnect", "count": preauth_closed, "color": "amber"},
            {"type": "Timeout", "count": timeout_count, "color": "purple"},
            {"type": "Accepted", "count": accepted, "color": "green"},
        ]

        patterns["auth_methods"] = [{"method": k, "count": v} for k, v in methods.most_common()]

        ip_attempt_counts = Counter()
        for ip, user_data in [(e["ip"], e["user"]) for e in invalid_users + failed_passwords]:
            ip_attempt_counts[ip] += 1

        brute_force = []
        for ip, count in ip_attempt_counts.most_common(15):
            timestamps = ips_timestamps.get(ip, [])
            if len(timestamps) >= 2:
                try:
                    t0 = datetime.fromisoformat(timestamps[0])
                    t1 = datetime.fromisoformat(timestamps[-1])
                    duration = (t1 - t0).total_seconds()
                    velocity = count / (duration / 60) if duration > 0 else count
                except:
                    velocity = 0
            else:
                velocity = 0

            ip_users = set()
            for e in invalid_users + failed_passwords:
                if e["ip"] == ip:
                    ip_users.add(e["user"])

            geo = geoip_lookup(ip)
            brute_force.append({
                "ip": ip, "count": count, "velocity": round(velocity, 1),
                "unique_users": len(ip_users), "sample_users": sorted(ip_users)[:5],
                "country": geo.get("country", "?"), "cc": geo.get("countryCode", "??"),
                "isp": geo.get("isp", ""),
            })
        patterns["brute_force_ips"] = brute_force

        wave_counts = defaultdict(int)
        for ip, timestamps in ips_timestamps.items():
            for ts in timestamps:
                try:
                    bucket = ts[:15] + "0"
                    wave_counts[bucket] += 1
                except:
                    pass
        waves_sorted = sorted(wave_counts.items())[-72:]
        patterns["attack_waves"] = [{"time": t, "count": c} for t, c in waves_sorted]

        patterns["total_attempts"] = len(invalid_users) + len(failed_passwords)
        patterns["total_invalid"] = len(invalid_users)
        patterns["total_failed_pw"] = len(failed_passwords)
        patterns["total_accepted"] = accepted
        patterns["unique_attackers"] = len(ip_attempt_counts)
        patterns["unique_usernames"] = len(set(usernames))

    except Exception as e:
        patterns["error"] = str(e)

    return patterns


def parse_f2b_log():
    """Parse fail2ban log for recent activity."""
    events = []
    for logfile in (F2B_LOG_OLD, F2B_LOG):
        if not logfile or not os.path.exists(logfile):
            continue
        try:
            with open(logfile, "r") as f:
                for line in f:
                    m = re.match(
                        r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+\S+\s+\[(\d+)\]:\s+(\w+)\s+\[(\w+)\]\s+(Found|Ban|Unban|Restore Ban)\s+([\d.]+)",
                        line,
                    )
                    if m:
                        events.append({
                            "time": m.group(1), "level": m.group(3),
                            "jail": m.group(4), "action": m.group(5), "ip": m.group(6),
                        })
        except:
            pass
    return events


# --- Routes ---

@app.route("/")
def dashboard():
    return render_template_string(HTML)


@app.route("/api/stats")
def stats():
    entries = parse_honeypot_logs()
    now = datetime.now()
    today_str = now.strftime("%Y-%m-%d")

    if not entries:
        return jsonify({"total": 0, "today": 0, "unique_ips": 0, "paths": [], "ips": [],
                        "timeline": [], "recent": [], "ua": [], "hours": {}})

    today_entries = [e for e in entries if today_str in e["time"]]
    timeline = defaultdict(int)
    for e in entries:
        try:
            timeline[e["time"][:10]] += 1
        except:
            pass
    timeline_sorted = sorted(timeline.items())[-14:]
    path_counts = Counter(e["path"] for e in entries).most_common(10)
    ip_counts = Counter(e["ip"] for e in entries).most_common(15)
    ip_data = []
    for ip, count in ip_counts:
        geo = geoip_lookup(ip)
        ip_data.append({
            "ip": ip, "count": count,
            "country": geo.get("country", "?"), "cc": geo.get("countryCode", "??"),
            "city": geo.get("city", ""), "isp": geo.get("isp", ""),
        })
    ua_counts = Counter(e["ua"] for e in entries).most_common(10)
    recent = entries[-30:][::-1]
    hours = defaultdict(int)
    for e in entries:
        try:
            hours[e["time"][11:13]] += 1
        except:
            pass

    return jsonify({
        "total": len(entries), "today": len(today_entries),
        "unique_ips": len(set(e["ip"] for e in entries)),
        "unique_ips_today": len(set(e["ip"] for e in today_entries)),
        "paths": [{"path": p, "count": c} for p, c in path_counts],
        "ips": ip_data,
        "timeline": [{"date": d, "count": c} for d, c in timeline_sorted],
        "recent": recent,
        "ua": [{"ua": u, "count": c} for u, c in ua_counts],
        "hours": dict(hours),
    })


@app.route("/api/f2b")
def f2b_stats():
    live = get_f2b_live_status()
    db = get_f2b_db_stats()
    log_events = parse_f2b_log()

    recent_events = log_events[-100:][::-1]

    one_hour_ago = (datetime.now() - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
    recent_found = [e for e in log_events if e["action"] == "Found" and e["time"] >= one_hour_ago]
    attacks_per_min = len(recent_found) / 60.0 if recent_found else 0

    today_str = datetime.now().strftime("%Y-%m-%d")
    today_bans = [e for e in log_events if e["action"] in ("Ban", "Restore Ban") and e["time"].startswith(today_str)]
    today_found = [e for e in log_events if e["action"] == "Found" and e["time"].startswith(today_str)]

    return jsonify({
        "live": live, "db": db, "recent_events": recent_events,
        "attacks_per_min": round(attacks_per_min, 1),
        "today_bans": len(today_bans), "today_attempts": len(today_found),
    })


@app.route("/api/patterns")
def attack_patterns():
    return jsonify(get_attack_patterns())


# --- HTML Template (23 Theme) ---

HTML = r"""<!DOCTYPE html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>23 // FNORD-PROXY Dashboard</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap');
  :root {
    --bg: #0a0a0a;
    --card: #0e0404;
    --border: #2a0e0e;
    --text: #ccaaa8;
    --dim: #5a3a38;
    --red: #AF2B1E;
    --bright: #E03020;
    --glow: #FF3828;
    --dark: #1a0808;
    --amber: #cc6622;
    --green: #448844;
    --cyan: #668888;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'Share Tech Mono', monospace;
    font-size: 13px;
    line-height: 1.5;
    padding: 20px;
    position: relative;
  }
  body::before {
    content:'';
    position:fixed; top:0;left:0;right:0;bottom:0;
    background: repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(175,43,30,0.02) 2px,rgba(175,43,30,0.02) 4px);
    pointer-events:none; z-index:9999;
  }
  @keyframes flicker { 0%,97%,100%{opacity:1} 98%{opacity:0.92} 99%{opacity:0.96} }
  body { animation: flicker 10s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
  @keyframes glitch {
    0%,92%,100%{transform:translate(0)} 93%{transform:translate(-2px,1px)} 95%{transform:translate(1px,-1px)} 97%{transform:translate(0)}
  }

  .header {
    display:flex; align-items:center; gap:16px;
    margin-bottom:28px; padding-bottom:16px; border-bottom:1px solid var(--border);
  }
  .header .logo {
    font-family:'VT323',monospace; font-size:42px; color:var(--bright);
    text-shadow: 0 0 10px rgba(175,43,30,0.5); animation: glitch 12s infinite;
    line-height:1;
  }
  .header h1 { font-size:16px; color:var(--red); letter-spacing:3px; text-transform:uppercase; }
  .header .live {
    background:var(--red); color:#fff; font-size:9px; font-weight:700;
    padding:2px 8px; border-radius:2px; animation:pulse 2s infinite; letter-spacing:2px;
  }
  .header .sub { color:var(--dim); font-size:10px; letter-spacing:2px; }
  .header .refresh { color:var(--dim); font-size:10px; margin-left:auto; }

  .section {
    margin:32px 0 16px; padding-bottom:8px; border-bottom:1px solid var(--border);
    display:flex; align-items:baseline; gap:12px;
  }
  .section .num {
    font-family:'VT323',monospace; font-size:32px; color:var(--bright);
    text-shadow:0 0 8px rgba(175,43,30,0.3); line-height:1;
  }
  .section .title { font-size:12px; color:var(--red); text-transform:uppercase; letter-spacing:3px; font-weight:600; }
  .section .tag { font-size:9px; color:var(--dim); letter-spacing:2px; margin-left:auto; }

  .stats-row { display:grid; grid-template-columns:repeat(4,1fr); gap:10px; margin-bottom:16px; }
  .stats-row.six { grid-template-columns:repeat(6,1fr); }
  .stat-card { background:var(--card); border:1px solid var(--border); border-radius:3px; padding:14px; }
  .stat-card .label { color:var(--dim); font-size:9px; text-transform:uppercase; letter-spacing:2px; }
  .stat-card .value { font-family:'VT323',monospace; font-size:32px; color:var(--bright); margin-top:4px; line-height:1; }
  .stat-card .value.dim { color:var(--red); }
  .stat-card .value.muted { color:var(--amber); }
  .stat-card .value.subtle { color:var(--cyan); }
  .stat-card .value.ok { color:var(--green); }
  .stat-card .sub { color:var(--dim); font-size:9px; margin-top:4px; }

  .grid { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px; }
  .card { background:var(--card); border:1px solid var(--border); border-radius:3px; padding:14px; }
  .card h2 {
    font-size:10px; font-weight:600; margin-bottom:10px;
    color:var(--dim); text-transform:uppercase; letter-spacing:2px;
    border-bottom:1px solid var(--border); padding-bottom:6px;
  }

  .bar-row { display:flex; align-items:center; margin-bottom:5px; gap:6px; }
  .bar-label { min-width:180px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-size:11px; }
  .bar-count { min-width:35px; text-align:right; color:var(--bright); font-family:'VT323',monospace; font-size:16px; }
  .bar-bg { flex:1; height:12px; background:var(--dark); border-radius:1px; overflow:hidden; }
  .bar-fill { height:100%; border-radius:1px; background: linear-gradient(90deg, var(--red), #6a1510); }
  .bar-fill.sec { background: linear-gradient(90deg, var(--amber), #663311); }
  .bar-fill.tri { background: linear-gradient(90deg, var(--cyan), #334444); }
  .bar-fill.ok { background: linear-gradient(90deg, var(--green), #224422); }

  .ip-row { display:flex; align-items:center; padding:4px 0; border-bottom:1px solid #1a0a0a; font-size:11px; gap:8px; }
  .ip-row:last-child { border-bottom:none; }
  .ip-flag { font-size:14px; min-width:22px; }
  .ip-addr { color:var(--bright); min-width:120px; font-weight:500; }
  .ip-count { color:var(--amber); min-width:30px; text-align:right; font-family:'VT323',monospace; font-size:16px; }
  .ip-geo { color:var(--dim); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; font-size:10px; }

  .timeline { display:flex; align-items:flex-end; gap:2px; height:70px; padding-top:8px; }
  .timeline.tall { height:90px; }
  .tbar { flex:1; border-radius:1px 1px 0 0; min-width:6px; transition:height .5s; position:relative; background:var(--red); }
  .tbar:hover { opacity:.7; }
  .tbar .tip { display:none; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:#1a0808; border:1px solid var(--border); color:var(--text); padding:3px 8px; border-radius:2px; font-size:9px; white-space:nowrap; z-index:10; }
  .tbar:hover .tip { display:block; }
  .tlabels { display:flex; gap:2px; margin-top:3px; }
  .tlabels span { flex:1; text-align:center; font-size:8px; color:var(--dim); min-width:6px; }

  .heatmap { display:grid; grid-template-columns:repeat(24,1fr); gap:2px; margin-top:6px; }
  .hcell { aspect-ratio:1; border-radius:1px; position:relative; min-height:18px; }
  .hcell .tip { display:none; position:absolute; bottom:100%; left:50%; transform:translateX(-50%); background:#1a0808; border:1px solid var(--border); color:var(--text); padding:2px 6px; border-radius:2px; font-size:9px; white-space:nowrap; z-index:10; }
  .hcell:hover .tip { display:block; }
  .hlabels { display:grid; grid-template-columns:repeat(24,1fr); gap:2px; margin-top:2px; }
  .hlabels span { text-align:center; font-size:8px; color:var(--dim); }

  .feed { max-height:320px; overflow-y:auto; }
  .fentry { padding:4px 0; border-bottom:1px solid #1a0a0a; font-size:10px; display:flex; gap:8px; align-items:center; }
  .fentry:last-child { border-bottom:none; }
  .ftime { color:var(--dim); min-width:130px; }
  .fip { color:var(--bright); min-width:110px; }
  .fpath { color:var(--amber); font-weight:500; }
  .faction { font-size:9px; padding:1px 5px; border-radius:2px; font-weight:700; min-width:44px; text-align:center; }
  .faction.ban { background:rgba(175,43,30,0.2); color:var(--bright); }
  .faction.unban { background:rgba(68,136,68,0.2); color:var(--green); }
  .faction.found { background:rgba(204,102,34,0.15); color:var(--amber); }
  .fjail { color:var(--dim); font-size:9px; }

  .jail-card { background:var(--card); border:1px solid var(--border); border-radius:3px; padding:14px; margin-bottom:10px; }
  .jail-header { display:flex; align-items:center; gap:10px; margin-bottom:10px; }
  .jail-name { font-family:'VT323',monospace; font-size:22px; color:var(--bright); }
  .jail-badge { font-size:9px; padding:2px 8px; border-radius:2px; font-weight:700; letter-spacing:1px; }
  .jail-badge.active { background:rgba(175,43,30,0.2); color:var(--bright); }
  .jail-badge.clean { background:rgba(68,136,68,0.2); color:var(--green); }
  .jail-stats { display:grid; grid-template-columns:repeat(4,1fr); gap:8px; }
  .jail-stat .n { font-family:'VT323',monospace; font-size:24px; color:var(--bright); }
  .jail-stat .l { font-size:9px; color:var(--dim); text-transform:uppercase; letter-spacing:1px; }
  .banned-list { margin-top:8px; }
  .banned-ip { display:inline-block; background:rgba(175,43,30,0.15); color:var(--bright); padding:2px 6px; border-radius:2px; font-size:10px; margin:2px 3px 2px 0; }

  .crow { display:flex; align-items:center; padding:3px 0; gap:8px; font-size:11px; }
  .cflag { font-size:14px; min-width:22px; }
  .cname { min-width:110px; }
  .ccount { color:var(--amber); font-family:'VT323',monospace; font-size:16px; min-width:30px; text-align:right; }
  .cbar { flex:1; height:10px; background:var(--dark); border-radius:1px; overflow:hidden; }
  .cfill { height:100%; background:linear-gradient(90deg, var(--red), #4a1510); border-radius:1px; }

  .bf { padding:6px 0; border-bottom:1px solid #1a0a0a; font-size:11px; }
  .bf:last-child { border-bottom:none; }
  .bf-h { display:flex; align-items:center; gap:8px; }
  .bf-users { color:var(--dim); font-size:9px; margin-top:3px; }
  .bf-users span { background:rgba(175,43,30,0.1); color:var(--red); padding:1px 4px; border-radius:1px; margin-right:2px; }

  .cat-row { display:flex; align-items:center; gap:8px; padding:4px 0; font-size:11px; }
  .cat-icon { font-size:14px; min-width:22px; text-align:center; }
  .cat-name { min-width:90px; text-transform:capitalize; }
  .cat-count { font-family:'VT323',monospace; font-size:16px; color:var(--amber); min-width:30px; text-align:right; }
  .cat-bar { flex:1; height:10px; background:var(--dark); border-radius:1px; overflow:hidden; }
  .cat-fill { height:100%; background:linear-gradient(90deg, var(--red), #4a1510); border-radius:1px; }

  .full-width { grid-column: 1 / -1; }

  .footer {
    margin-top:40px; padding-top:12px; border-top:1px solid var(--border);
    display:flex; justify-content:space-between; font-size:9px; color:var(--dim); letter-spacing:2px;
  }

  @media (max-width:1100px) {
    .stats-row { grid-template-columns:repeat(2,1fr); }
    .stats-row.six { grid-template-columns:repeat(3,1fr); }
    .grid { grid-template-columns:1fr; }
  }
  @media (max-width:600px) {
    body { padding:10px; font-size:11px; }
    .header .logo { font-size:32px; }
    .stat-card .value { font-size:24px; }
  }
</style>
</head>
<body>

<div class="header">
  <span class="logo">23</span>
  <div>
    <h1>Nichts ist wie es scheint</h1>
    <div class="sub">FNORD-PROXY // LEVIATHAN MAINFRAME // SEKTOR 23</div>
  </div>
  <span class="live">LIVE</span>
  <span class="refresh" id="refresh">...</span>
</div>

<div class="section">
  <span class="num">01</span>
  <span class="title">Fail2Ban // Bannhammer</span>
  <span class="tag">INGSOC DEFENCE GRID</span>
</div>

<div class="stats-row six">
  <div class="stat-card"><div class="label">Bans Gesamt</div><div class="value" id="f-total">-</div></div>
  <div class="stat-card"><div class="label">Heute</div><div class="value muted" id="f-today">-</div></div>
  <div class="stat-card"><div class="label">Aktuell Gebannt</div><div class="value" id="f-banned">-</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value subtle" id="f-unique">-</div></div>
  <div class="stat-card"><div class="label">Angriffe/Min</div><div class="value dim" id="f-rate">-</div></div>
  <div class="stat-card"><div class="label">Versuche Heute</div><div class="value muted" id="f-attempts">-</div></div>
</div>

<div id="f2b-jails"></div>

<div class="grid">
  <div class="card"><h2>Ban Timeline (14 Tage)</h2><div class="timeline" id="f2b-timeline"></div><div class="tlabels" id="f2b-timeline-labels"></div></div>
  <div class="card"><h2>Angriffe nach Stunde</h2><div class="heatmap" id="f2b-heatmap"></div><div class="hlabels" id="f2b-heatmap-labels"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Gebannte IPs</h2><div id="f2b-top-ips"></div></div>
  <div class="card"><h2>Herkunftslaender</h2><div id="f2b-countries"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Wiederholungstaeter</h2><div id="f2b-repeaters"></div></div>
  <div class="card"><h2>Live Feed</h2><div class="feed" id="f2b-feed"></div></div>
</div>

<div class="section">
  <span class="num">23</span>
  <span class="title">Angriffsmuster // SSH Analyse (24h)</span>
  <span class="tag">WE ARE LEGION</span>
</div>

<div class="stats-row six">
  <div class="stat-card"><div class="label">Versuche</div><div class="value" id="a-total">-</div></div>
  <div class="stat-card"><div class="label">Angreifer</div><div class="value subtle" id="a-attackers">-</div></div>
  <div class="stat-card"><div class="label">Usernames</div><div class="value dim" id="a-users">-</div></div>
  <div class="stat-card"><div class="label">Invalid User</div><div class="value muted" id="a-invalid">-</div></div>
  <div class="stat-card"><div class="label">Failed PW</div><div class="value" id="a-failed">-</div></div>
  <div class="stat-card"><div class="label">Accepted</div><div class="value ok" id="a-accepted">-</div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Usernames</h2><div id="a-usernames"></div></div>
  <div class="card"><h2>Username-Kategorien</h2><div id="a-categories"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Brute-Force IPs</h2><div id="a-bruteforce" style="max-height:380px;overflow-y:auto"></div></div>
  <div class="card"><h2>Angriffsarten</h2><div id="a-types"></div><h2 style="margin-top:14px">Auth-Methoden</h2><div id="a-methods"></div></div>
</div>

<div class="grid">
  <div class="card full-width"><h2>Angriffswellen (10-Min Fenster)</h2><div class="timeline tall" id="a-waves"></div><div class="tlabels" id="a-waves-labels"></div></div>
</div>

<div class="section">
  <span class="num">05</span>
  <span class="title">Honeypot // Koeder</span>
  <span class="tag">EXPECT US</span>
</div>

<div class="stats-row">
  <div class="stat-card"><div class="label">Zugriffe Gesamt</div><div class="value" id="s-total">-</div></div>
  <div class="stat-card"><div class="label">Heute</div><div class="value muted" id="s-today">-</div></div>
  <div class="stat-card"><div class="label">Unique IPs</div><div class="value subtle" id="s-ips">-</div><div class="sub" id="s-ips-sub"></div></div>
  <div class="stat-card"><div class="label">Top Angreifer</div><div class="value dim" id="s-top">-</div><div class="sub" id="s-top-sub"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Top Koeder</h2><div id="paths"></div></div>
  <div class="card"><h2>Top Angreifer</h2><div id="ips"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>Timeline (14 Tage)</h2><div class="timeline" id="timeline"></div><div class="tlabels" id="timeline-labels"></div></div>
  <div class="card"><h2>Stunden-Heatmap</h2><div class="heatmap" id="heatmap"></div><div class="hlabels" id="heatmap-labels"></div></div>
</div>

<div class="grid">
  <div class="card"><h2>User Agents</h2><div id="useragents"></div></div>
  <div class="card"><h2>Live Feed</h2><div class="feed" id="feed"></div></div>
</div>

<div class="footer">
  <span>FNORD // 2+2=5 // ILLUMINATUS!</span>
  <span>ALLES IST MIT ALLEM VERBUNDEN</span>
  <span id="clock">23:23:23</span>
</div>

<script>
function flag(cc) {
  if (!cc || cc === '??' || cc.length !== 2) return '\u{1F310}';
  return String.fromCodePoint(...[...cc.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65));
}

function bars(el, items, key, cls) {
  const mx = items.length ? Math.max(...items.map(i => i.count)) : 1;
  el.innerHTML = items.map(i => `
    <div class="bar-row">
      <span class="bar-count">${i.count}</span>
      <span class="bar-label">${i[key]}</span>
      <div class="bar-bg"><div class="bar-fill ${cls||''}" style="width:${(i.count/mx*100).toFixed(0)}%"></div></div>
    </div>
  `).join('');
}

function heat(cId, lId, hours, r, g, b) {
  const mx = Math.max(1, ...Object.values(hours));
  let h='', l='';
  for (let i=0;i<24;i++) {
    const hh = String(i).padStart(2,'0');
    const c = hours[hh]||0;
    const n = c/mx;
    h += `<div class="hcell" style="background:${c>0?`rgb(${~~(r*n)},${~~(g*n)},${~~(b*n)})`:'#120505'}"><span class="tip">${hh}:00 - ${c}</span></div>`;
    l += `<span>${hh}</span>`;
  }
  document.getElementById(cId).innerHTML = h;
  document.getElementById(lId).innerHTML = l;
}

function tline(cId, lId, data, bg) {
  const mx = data.length ? Math.max(1,...data.map(t=>t.count)) : 1;
  document.getElementById(cId).innerHTML = data.map(t => `
    <div class="tbar" style="height:${Math.max(4,t.count/mx*100)}%;background:${bg}">
      <span class="tip">${t.date}: ${t.count}</span>
    </div>
  `).join('');
  document.getElementById(lId).innerHTML = data.map(t=>`<span>${t.date.slice(5)}</span>`).join('');
}

async function refreshHP() {
  const d = await (await fetch('/api/stats')).json();
  document.getElementById('s-total').textContent = d.total;
  document.getElementById('s-today').textContent = d.today;
  document.getElementById('s-ips').textContent = d.unique_ips;
  document.getElementById('s-ips-sub').textContent = 'Heute: '+(d.unique_ips_today||0);
  if (d.ips && d.ips.length) {
    document.getElementById('s-top').textContent = d.ips[0].ip;
    document.getElementById('s-top-sub').textContent = d.ips[0].count+'x - '+d.ips[0].country;
  }
  bars(document.getElementById('paths'), d.paths||[], 'path', '');
  document.getElementById('ips').innerHTML = (d.ips||[]).map(i=>`
    <div class="ip-row"><span class="ip-count">${i.count}</span><span class="ip-flag">${flag(i.cc)}</span><span class="ip-addr">${i.ip}</span><span class="ip-geo">${i.city?i.city+', ':''}${i.country} - ${i.isp}</span></div>
  `).join('');
  tline('timeline','timeline-labels', d.timeline||[], 'var(--red)');
  heat('heatmap','heatmap-labels', d.hours||{}, 175,43,30);
  bars(document.getElementById('useragents'), d.ua||[], 'ua', 'sec');
  document.getElementById('feed').innerHTML = (d.recent||[]).map(e=>`
    <div class="fentry"><span class="ftime">${e.time?e.time.replace('T',' ').slice(0,19):''}</span><span class="fip">${e.ip}</span><span class="fpath">${e.path}</span></div>
  `).join('');
}

async function refreshF2B() {
  const d = await (await fetch('/api/f2b')).json();
  const live=d.live||{}, db=d.db||{};
  document.getElementById('f-total').textContent = db.total_bans||0;
  document.getElementById('f-today').textContent = d.today_bans||0;
  document.getElementById('f-unique').textContent = db.unique_ips||0;
  document.getElementById('f-rate').textContent = d.attacks_per_min||0;
  document.getElementById('f-attempts').textContent = d.today_attempts||0;
  let tb=0; (live.jails||[]).forEach(j=>tb+=j.banned);
  document.getElementById('f-banned').textContent = tb;

  document.getElementById('f2b-jails').innerHTML = (live.jails||[]).map(j=>`
    <div class="jail-card">
      <div class="jail-header">
        <span class="jail-name">${j.name}</span>
        <span class="jail-badge ${j.banned>0?'active':'clean'}">${j.banned>0?j.banned+' GEBANNT':'CLEAN'}</span>
      </div>
      <div class="jail-stats">
        <div class="jail-stat"><div class="n" style="color:var(--bright)">${j.banned}</div><div class="l">Aktuell</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--red)">${j.total_banned}</div><div class="l">Gesamt</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--amber)">${j.failed}</div><div class="l">Fehlversuche</div></div>
        <div class="jail-stat"><div class="n" style="color:var(--dim)">${j.total_failed}</div><div class="l">Total</div></div>
      </div>
      ${j.banned_ips.length?'<div class="banned-list">'+j.banned_ips.map(ip=>'<span class="banned-ip">'+ip+'</span>').join('')+'</div>':''}
    </div>
  `).join('');

  tline('f2b-timeline','f2b-timeline-labels', db.bans_timeline||[], 'var(--red)');
  heat('f2b-heatmap','f2b-heatmap-labels', db.bans_by_hour||{}, 175,43,30);

  document.getElementById('f2b-top-ips').innerHTML = (db.top_banned||[]).map(i=>`
    <div class="ip-row"><span class="ip-count">${i.count}x</span><span class="ip-flag">${flag(i.cc)}</span><span class="ip-addr">${i.ip}</span><span class="ip-geo">${i.city?i.city+', ':''}${i.country} - ${i.isp}</span></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  const cs=db.top_countries||[], cMx=cs.length?Math.max(...cs.map(c=>c.count)):1;
  document.getElementById('f2b-countries').innerHTML = cs.map(c=>`
    <div class="crow"><span class="ccount">${c.count}</span><span class="cflag">${flag(c.cc)}</span><span class="cname">${c.country}</span><div class="cbar"><div class="cfill" style="width:${(c.count/cMx*100).toFixed(0)}%"></div></div></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  document.getElementById('f2b-repeaters').innerHTML = (db.repeat_offenders||[]).map(r=>`
    <div class="ip-row"><span class="ip-count">${r.count}x</span><span class="ip-flag">${flag(r.cc)}</span><span class="ip-addr">${r.ip}</span><span class="ip-geo">${r.country} - ${r.isp} - ${r.last_ban}</span></div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  document.getElementById('f2b-feed').innerHTML = (d.recent_events||[]).slice(0,50).map(e=>{
    let c=e.action==='Ban'||e.action==='Restore Ban'?'ban':e.action==='Unban'?'unban':'found';
    return `<div class="fentry"><span class="ftime">${e.time}</span><span class="faction ${c}">${e.action}</span><span class="fip">${e.ip}</span><span class="fjail">${e.jail}</span></div>`;
  }).join('')||'<div style="color:var(--dim)">-</div>';
}

async function refreshPatterns() {
  const p = await (await fetch('/api/patterns')).json();
  document.getElementById('a-total').textContent = p.total_attempts||0;
  document.getElementById('a-attackers').textContent = p.unique_attackers||0;
  document.getElementById('a-users').textContent = p.unique_usernames||0;
  document.getElementById('a-invalid').textContent = p.total_invalid||0;
  document.getElementById('a-failed').textContent = p.total_failed_pw||0;
  document.getElementById('a-accepted').textContent = p.total_accepted||0;

  bars(document.getElementById('a-usernames'), p.top_usernames||[], 'user', '');

  const cats=p.username_categories||[], catMx=cats.length?Math.max(...cats.map(c=>c.count)):1;
  const ic={system:'\u{1F464}',database:'\u{1F5C4}',devops:'\u2699',crypto:'\u26D3',services:'\u{1F50C}',custom:'\u2753'};
  document.getElementById('a-categories').innerHTML = cats.map(c=>`
    <div class="cat-row"><span class="cat-count">${c.count}</span><span class="cat-icon">${ic[c.category]||'\u2753'}</span><span class="cat-name">${c.category}</span><div class="cat-bar"><div class="cat-fill" style="width:${(c.count/catMx*100).toFixed(0)}%"></div></div></div>
  `).join('');

  const types=p.attack_types||[], tMx=types.length?Math.max(1,...types.map(t=>t.count)):1;
  document.getElementById('a-types').innerHTML = types.map(t=>`
    <div class="bar-row"><span class="bar-count">${t.count}</span><span class="bar-label">${t.type}</span><div class="bar-bg"><div class="bar-fill ${t.color==='green'?'ok':t.color==='amber'?'sec':''}" style="width:${(t.count/tMx*100).toFixed(0)}%"></div></div></div>
  `).join('');

  bars(document.getElementById('a-methods'), p.auth_methods||[], 'method', 'tri');

  document.getElementById('a-bruteforce').innerHTML = (p.brute_force_ips||[]).map(b=>`
    <div class="bf">
      <div class="bf-h"><span class="ip-flag">${flag(b.cc)}</span><span class="ip-addr">${b.ip}</span><span class="ip-count">${b.count}x</span><span style="color:var(--red);font-size:10px">${b.velocity} /min</span><span class="ip-geo">${b.country} - ${b.isp}</span></div>
      <div class="bf-users">${b.unique_users} Users: ${b.sample_users.map(u=>'<span>'+u+'</span>').join('')}${b.unique_users>5?' ...':''}</div>
    </div>
  `).join('')||'<div style="color:var(--dim)">-</div>';

  const w=p.attack_waves||[];
  if(w.length) {
    const wMx=Math.max(1,...w.map(x=>x.count));
    document.getElementById('a-waves').innerHTML = w.map(x=>`
      <div class="tbar" style="height:${Math.max(4,x.count/wMx*100)}%"><span class="tip">${x.time.replace('T',' ')}: ${x.count}</span></div>
    `).join('');
    document.getElementById('a-waves-labels').innerHTML = w.map((x,i)=>`<span>${i%6===0?x.time.slice(11,16):''}</span>`).join('');
  }
}

setInterval(()=>{
  const n=new Date(), s=n.getSeconds();
  const el=document.getElementById('clock');
  if(s===23){el.textContent='23:23:23';el.style.color='var(--bright)';}
  else{el.textContent=String(n.getHours()).padStart(2,'0')+':'+String(n.getMinutes()).padStart(2,'0')+':'+String(s).padStart(2,'0');el.style.color='';}
},1000);

async function refresh() {
  try {
    await Promise.all([refreshHP(), refreshF2B(), refreshPatterns()]);
    document.getElementById('refresh').textContent = new Date().toLocaleTimeString('de-DE') + ' // SYNCED';
  } catch(e) { console.error(e); }
}
refresh();
setInterval(refresh, 30000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    print(f"FNORD-PROXY Dashboard starting on {BIND_HOST}:{BIND_PORT}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=False)
