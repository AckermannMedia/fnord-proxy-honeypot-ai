#!/bin/bash
# ╔═══════════════════════════════════════════════════════════════╗
# ║  FNORD-PROXY Installer                                       ║
# ║  "Nichts ist wie es scheint"                                  ║
# ║                                                               ║
# ║  Honeypot reverse proxy with analytics dashboard              ║
# ║  Themed after 23 / Anonymous / 1984                           ║
# ╚═══════════════════════════════════════════════════════════════╝

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
DIM='\033[0;90m'
NC='\033[0m'

INSTALL_DIR="/opt/fnord-proxy"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${RED}"
echo '  ██████╗ ██████╗'
echo '  ╚═══██╗╚════██╗'
echo '   ████╔╝  █████╔╝'
echo '  ██╔═══╝  ╚═══██╗'
echo '  ███████╗██████╔╝'
echo '  ╚══════╝╚═════╝'
echo -e "${DIM}  FNORD-PROXY // Nichts ist wie es scheint${NC}"
echo ""

# --- Check root ---
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!]${NC} Bitte als root ausfuehren (sudo ./install.sh)"
    exit 1
fi

# --- Parse arguments ---
DOMAIN=""
BACKEND=""
BIND_HOST="127.0.0.1"
BIND_PORT="8888"
SKIP_NGINX=false
SKIP_F2B=false
SKIP_LANDING=false

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -d, --domain DOMAIN      Domain name (e.g. example.com)"
    echo "  -b, --backend URL        Backend service URL (e.g. http://127.0.0.1:8080)"
    echo "  -h, --bind-host HOST     Dashboard bind address (default: 127.0.0.1)"
    echo "  -p, --bind-port PORT     Dashboard port (default: 8888)"
    echo "  --skip-nginx             Don't install nginx config"
    echo "  --skip-fail2ban          Don't install fail2ban config"
    echo "  --skip-landing           Don't install landing page"
    echo "  --help                   Show this help"
    echo ""
    echo "Example:"
    echo "  sudo ./install.sh -d vault.example.com -b http://10.0.0.5:80"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -b|--backend) BACKEND="$2"; shift 2 ;;
        -h|--bind-host) BIND_HOST="$2"; shift 2 ;;
        -p|--bind-port) BIND_PORT="$2"; shift 2 ;;
        --skip-nginx) SKIP_NGINX=true; shift ;;
        --skip-fail2ban) SKIP_F2B=true; shift ;;
        --skip-landing) SKIP_LANDING=true; shift ;;
        --help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

# --- Interactive prompts if not provided ---
if [ -z "$DOMAIN" ]; then
    read -p "[?] Domain (e.g. example.com): " DOMAIN
fi
if [ -z "$BACKEND" ]; then
    read -p "[?] Backend URL (e.g. http://127.0.0.1:8080, leave empty for landing page only): " BACKEND
fi

echo ""
echo -e "${DIM}[*] Domain:    ${NC}${DOMAIN}"
echo -e "${DIM}[*] Backend:   ${NC}${BACKEND:-'(landing page only)'}"
echo -e "${DIM}[*] Dashboard: ${NC}${BIND_HOST}:${BIND_PORT}"
echo ""

# --- Check dependencies ---
echo -e "${DIM}[1/7]${NC} Checking dependencies..."

if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[!]${NC} python3 not found. Installing..."
    apt-get update -qq && apt-get install -y -qq python3 python3-pip
fi

if ! python3 -c "import flask" 2>/dev/null; then
    echo -e "${DIM}  -> Installing Flask...${NC}"
    pip3 install flask --quiet 2>/dev/null || pip3 install flask --break-system-packages --quiet
fi

if ! command -v nginx &>/dev/null; then
    echo -e "${RED}[!]${NC} nginx not found. Install it first: apt install nginx"
    SKIP_NGINX=true
fi

if ! command -v fail2ban-client &>/dev/null; then
    echo -e "${RED}[!]${NC} fail2ban not found. Install it first: apt install fail2ban"
    SKIP_F2B=true
fi

echo -e "${GREEN}[+]${NC} Dependencies OK"

# --- Install dashboard ---
echo -e "${DIM}[2/7]${NC} Installing dashboard to ${INSTALL_DIR}..."
mkdir -p "$INSTALL_DIR"
cp "$SCRIPT_DIR/app.py" "$INSTALL_DIR/app.py"
cp "$SCRIPT_DIR/fnord.conf.example" "$INSTALL_DIR/fnord.conf.example"

# Create config
cat > "$INSTALL_DIR/fnord.conf" <<EOF
BIND_HOST=${BIND_HOST}
BIND_PORT=${BIND_PORT}
HONEYPOT_LOG=/var/log/nginx/honeypot.log
F2B_DB=/var/lib/fail2ban/fail2ban.sqlite3
F2B_LOG=/var/log/fail2ban.log
DOMAIN=${DOMAIN}
BACKEND_URL=${BACKEND}
EOF

echo -e "${GREEN}[+]${NC} Dashboard installed"

# --- Install nginx config ---
if [ "$SKIP_NGINX" = false ]; then
    echo -e "${DIM}[3/7]${NC} Configuring nginx..."

    # Log format
    if ! grep -q "honeypot_log" /etc/nginx/nginx.conf 2>/dev/null; then
        cp "$SCRIPT_DIR/nginx/honeypot-log-format.conf" /etc/nginx/conf.d/honeypot-log-format.conf
        echo -e "${GREEN}[+]${NC} Honeypot log format installed"
    else
        echo -e "${DIM}  -> Log format already exists${NC}"
    fi

    # Site config
    NGINX_CONF="/etc/nginx/sites-available/fnord-${DOMAIN}"
    cp "$SCRIPT_DIR/nginx/fnord-proxy.conf.template" "$NGINX_CONF"
    sed -i "s|\${DOMAIN}|${DOMAIN}|g" "$NGINX_CONF"

    if [ -n "$BACKEND" ]; then
        sed -i "s|\${BACKEND_URL}|${BACKEND}|g" "$NGINX_CONF"
    else
        # No backend - serve landing page instead
        sed -i '/--- REAL BACKEND PROXY ---/,/^    }/c\    # --- LANDING PAGE ---\n    location / {\n        root /var/www/fnord-landing;\n        index index.html;\n        try_files $uri $uri/ /index.html;\n    }' "$NGINX_CONF"
    fi

    # Enable site
    if [ -d /etc/nginx/sites-enabled ]; then
        ln -sf "$NGINX_CONF" "/etc/nginx/sites-enabled/fnord-${DOMAIN}"
    fi

    # Test nginx
    if nginx -t 2>/dev/null; then
        echo -e "${GREEN}[+]${NC} Nginx config installed: ${NGINX_CONF}"
        echo -e "${DIM}  -> Review and reload: nginx -t && systemctl reload nginx${NC}"
    else
        echo -e "${RED}[!]${NC} Nginx config has errors - review ${NGINX_CONF}"
        echo -e "${DIM}  -> You may need to adjust SSL cert paths${NC}"
    fi

    # Create log file
    touch /var/log/nginx/honeypot.log
    chown www-data:adm /var/log/nginx/honeypot.log
else
    echo -e "${DIM}[3/7]${NC} Skipping nginx config"
fi

# --- Install landing page ---
if [ "$SKIP_LANDING" = false ]; then
    echo -e "${DIM}[4/7]${NC} Installing landing page..."
    mkdir -p /var/www/fnord-landing
    cp "$SCRIPT_DIR/landing/index.html" /var/www/fnord-landing/index.html
    echo -e "${GREEN}[+]${NC} Landing page installed to /var/www/fnord-landing/"
else
    echo -e "${DIM}[4/7]${NC} Skipping landing page"
fi

# --- Install fail2ban ---
if [ "$SKIP_F2B" = false ]; then
    echo -e "${DIM}[5/7]${NC} Configuring fail2ban..."
    cp "$SCRIPT_DIR/fail2ban/fnord-honeypot.conf" /etc/fail2ban/filter.d/fnord-honeypot.conf
    cp "$SCRIPT_DIR/fail2ban/jail-fnord.conf" /etc/fail2ban/jail.d/fnord-honeypot.conf
    echo -e "${GREEN}[+]${NC} Fail2ban filter + jail installed"
    echo -e "${DIM}  -> Reload: systemctl reload fail2ban${NC}"
else
    echo -e "${DIM}[5/7]${NC} Skipping fail2ban config"
fi

# --- Install systemd service ---
echo -e "${DIM}[6/7]${NC} Installing systemd service..."
cp "$SCRIPT_DIR/fnord-proxy.service" /etc/systemd/system/fnord-proxy.service
systemctl daemon-reload
systemctl enable fnord-proxy
echo -e "${GREEN}[+]${NC} Service installed and enabled"

# --- Start ---
echo -e "${DIM}[7/7]${NC} Starting fnord-proxy..."
systemctl restart fnord-proxy

sleep 2
if systemctl is-active --quiet fnord-proxy; then
    echo -e "${GREEN}[+]${NC} Dashboard running on ${BIND_HOST}:${BIND_PORT}"
else
    echo -e "${RED}[!]${NC} Service failed to start. Check: journalctl -u fnord-proxy"
fi

echo ""
echo -e "${RED}═══════════════════════════════════════════════════${NC}"
echo -e "${RED}  FNORD-PROXY installed successfully${NC}"
echo -e "${DIM}  Dashboard: http://${BIND_HOST}:${BIND_PORT}${NC}"
echo -e "${DIM}  Config:    ${INSTALL_DIR}/fnord.conf${NC}"
echo -e "${DIM}  Nginx:     Review & reload: systemctl reload nginx${NC}"
echo -e "${DIM}  Fail2ban:  Reload: systemctl reload fail2ban${NC}"
echo -e "${RED}═══════════════════════════════════════════════════${NC}"
echo ""
echo -e "${DIM}  FNORD // 2+2=5 // ILLUMINATUS!${NC}"
echo ""
