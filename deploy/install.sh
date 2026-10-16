#!/bin/sh
# Install or upgrade VLAN Flow as a systemd service.
# Usage (from the repository folder):  sudo sh deploy/install.sh
set -eu

APP_DIR=/opt/vlan-flow
CONF_DIR=/etc/vlan-flow
UNIT=/etc/systemd/system/vlan-flow.service
REPO="$(cd "$(dirname "$0")/.." && pwd)"

say() { printf '\n==> %s\n' "$*"; }
fail() { printf '\nERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Run this with sudo: sudo sh deploy/install.sh"
command -v systemctl >/dev/null || fail "systemd was not found. Use Docker instead (see README.md)."
command -v python3 >/dev/null || fail "python3 is not installed. Install it first, e.g. 'sudo apt install python3'."
python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || fail "Python 3.9 or newer is required (found $(python3 --version 2>&1))."

say "Running the self-tests"
(cd "$REPO" && python3 -m unittest -q test_server.py) || fail "Self-tests failed; nothing was installed."

if [ -d "$APP_DIR" ]; then
  backup="$APP_DIR.bak-$(date +%Y%m%d-%H%M%S)"
  say "Existing installation found; backing it up to $backup"
  cp -a "$APP_DIR" "$backup"
fi

say "Copying the application to $APP_DIR"
install -d -m 0755 "$APP_DIR"
install -m 0644 "$REPO/server.py" "$REPO/dashboard.html" "$REPO/app.js" "$REPO/style.css" \
  "$REPO/config.example.json" "$APP_DIR/"

install -d -m 0755 "$CONF_DIR"
first_install=no
if [ ! -f "$CONF_DIR/config.json" ]; then
  install -m 0644 "$REPO/config.example.json" "$CONF_DIR/config.json"
  first_install=yes
  say "Created $CONF_DIR/config.json from the example"
else
  say "Keeping your existing $CONF_DIR/config.json"
fi

say "Checking the configuration"
python3 -c "import sys; sys.path.insert(0, '$APP_DIR'); import server; server.load_config('$CONF_DIR/config.json')" \
  || fail "Fix $CONF_DIR/config.json (message above), then run this script again."

install -m 0644 "$REPO/deploy/vlan-flow.service" "$UNIT"
systemctl daemon-reload
systemctl enable vlan-flow.service >/dev/null
systemctl restart vlan-flow.service
sleep 2
systemctl is-active --quiet vlan-flow.service || {
  journalctl -u vlan-flow.service -n 20 --no-pager
  fail "The service did not start (log above)."
}

say "VLAN Flow is running"
echo "  Dashboard : http://<this-server-ip>:8787"
echo "  Syslog    : UDP port 5514 on this server"
echo "  Config    : $CONF_DIR/config.json   (then: sudo systemctl restart vlan-flow)"
echo "  Logs      : journalctl -u vlan-flow -f"
if [ "$first_install" = yes ]; then
  echo
  echo "  Next: edit $CONF_DIR/config.json with your own networks, router IP(s) and"
  echo "  dashboard address, restart the service, then send your firewall syslog to this server."
  echo "  Step-by-step guide: docs/router-setup.md"
fi
