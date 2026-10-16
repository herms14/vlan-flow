# VLAN Flow

**See which traffic your firewall allows and blocks between your networks, live, as a map.**

VLAN Flow listens for the syslog messages your router or firewall sends when a rule with logging
matches a connection. It draws every *allowed* and *denied* path between your VLANs on an
interactive map, lets you look up a single connection ("was 192.168.10.5 → 192.168.20.8 port 22
blocked?"), and shows everything else your devices log (clients joining, DHCP leases, device events).

- **One small Python program.** Standard library only: nothing to `pip install`, no database server.
- **Runs anywhere Python 3.9+ or Docker runs**: a Raspberry Pi, a VM, an LXC container.
- **Works with most routers and firewalls**: key=value logs, Linux netfilter (OpenWrt, UniFi, ufw),
  pf filterlog (pfSense, OPNsense) and MikroTik. See [supported formats](docs/router-setup.md#supported-log-formats).
- **Read-only.** It never logs in to your router or changes your network; it only receives syslog.
- **Your networks, your names.** Everything about your environment lives in one `config.json`.

> [!NOTE]
> VLAN Flow shows **logged firewall decisions**, not every packet. A path appears only when a
> firewall rule with **logging** turned on matches it. A permit means the firewall allowed it, not that the
> application answered. "No evidence" never means "blocked".

---

## How it works

```
 Router / firewall ── syslog (UDP 5514) ──►  VLAN Flow  ──►  Dashboard (http://server:8787)
   "action=deny src=… dst=… dport=22"        • keeps 7 days of firewall decisions (SQLite)
                                             • maps each IP to your networks (config.json)
```

---

## Quick start

You need: a Linux machine on your network that the gateway can reach, and either **Docker** or
**Python 3.9+ with systemd**. It takes about 10 minutes.

### 1. Get the code

```sh
git clone https://github.com/herms14/vlan-flow.git
cd vlan-flow
```

### 2. Describe your network

```sh
cp config.example.json config.json
nano config.json
```

Change three things (details in [docs/configuration.md](docs/configuration.md)):

| Setting | What to put there |
|---|---|
| `networks` | One line per VLAN: an ID, a name and its subnet, e.g. `{ "id": 30, "name": "IoT", "subnet": "192.168.30.0/24" }` |
| `senders` | The IP addresses your syslog will come from, usually your router. Anything else is ignored. |
| `allowed_hosts` | The address you will type in the browser, e.g. `"192.168.20.50:8787"` or `"vlanflow.example.com"` |

### 3. Start it

**Option A: Docker** (recommended)

```sh
docker compose up -d --build
docker compose logs -f        # should print "VLAN Flow: dashboard http://0.0.0.0:8787 ..."
```

**Option B: systemd service** (no Docker)

```sh
sudo sh deploy/install.sh     # runs the tests, installs to /opt/vlan-flow, starts the service
sudo nano /etc/vlan-flow/config.json    # the installer copies the example here on first install
sudo systemctl restart vlan-flow
```

### 4. Point your router at it

In your router or firewall, send syslog to **this server's IP, UDP port 5514**, and turn on
**logging** for the firewall rules you want to see. Step-by-step, with examples for common
platforms: [docs/router-setup.md](docs/router-setup.md).

### 5. Open the dashboard

Browse to `http://<server-ip>:8787`. Within a few seconds the **Network activity** table at the
bottom shows incoming syslog; the map fills as logged firewall rules match traffic.

No logging rules yet? Click **Explore demo** to see how it looks with synthetic data based on your own
networks.

---

## Using the dashboard

| Part | What it tells you |
|---|---|
| **Traffic explorer** (map) | One card per network. Green arrows = allowed, red = denied. Click an arrow or a card for details; drag cards to rearrange; scroll to zoom. |
| **Connection troubleshoot** | Enter source IP, destination IP and port to search the logs for that exact connection: allowed, denied, mixed or no evidence. It does not send any packets. |
| **Connection decisions** | The raw firewall events behind the map. Click a row to inspect it, or **Export CSV**. |
| **Network activity** | Every syslog message received (last 300, memory only): firewall, client, DHCP, device and other events. |
| **Collector health** | Messages received, firewall events parsed, rejected senders. If "Rejected" grows, add that IP to `senders`. |

---

## Security

- **The dashboard has no login.** It shows IP addresses and traffic patterns from your network. Only
  expose it on a trusted network, or put it behind a reverse proxy with authentication
  (Authentik, Authelia, Cloudflare Access, basic auth…). See [docs/reverse-proxy.md](docs/reverse-proxy.md).
- Syslog is only accepted from the IPs in `senders`.
- The dashboard only answers to the host names in `allowed_hosts` (protection against DNS rebinding).
- No secrets are needed or stored. `config.json` holds only network names and IPs and is ignored by git.
- The systemd unit runs as an unprivileged, sandboxed user; the Docker image runs as a non-root user.

---

## Documentation

| Guide | |
|---|---|
| [Router setup](docs/router-setup.md) | Supported log formats, sending syslog, enabling rule logging |
| [Configuration](docs/configuration.md) | Every `config.json` setting, ports and environment variables |
| [Reverse proxy & login](docs/reverse-proxy.md) | HTTPS and authentication with Caddy, nginx or Traefik |
| [Troubleshooting](docs/troubleshooting.md) | Nothing shows up, rejected senders, wrong networks, Docker notes |

## Updating

```sh
git pull
docker compose up -d --build      # Docker
sudo sh deploy/install.sh         # systemd: backs up the old version and keeps your config
```

## Development

```sh
python -m unittest -v test_server.py
python server.py --config config.json --http-bind 127.0.0.1    # then open http://127.0.0.1:8787
```

## License

[MIT](LICENSE)
