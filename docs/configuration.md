# Configuration

All settings for your environment live in **`config.json`**. Start from the example:

```sh
cp config.example.json config.json
```

Where the file lives:

| How you run it | Config file |
|---|---|
| Docker Compose | `config.json` next to `docker-compose.yml` (mounted read-only into the container) |
| systemd (`deploy/install.sh`) | `/etc/vlan-flow/config.json` |
| By hand | `config.json` in the current folder, or `--config /path/to/config.json` |

After editing, restart: `docker compose restart` or `sudo systemctl restart vlan-flow`.
If the file has a mistake, VLAN Flow stops with a message that says what to fix.

---

## Settings

Keys starting with `_` are comments and are ignored.

### `networks` (required)

One entry per VLAN or subnet you want on the map.

```json
"networks": [
  { "id": 10, "name": "Trusted", "role": "Trusted clients", "subnet": "192.168.10.0/24" },
  { "id": 20, "name": "Servers", "role": "Compute & storage", "subnet": "10.20.0.0/16" }
]
```

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | A number shown on the card, normally the VLAN ID. Must be unique. |
| `subnet` | yes | The network in CIDR form. Any size and any private range works. |
| `name` | no | Short name on the card (default `Network <id>`). |
| `role` | no | Small caption under the name, e.g. "Smart devices". |

- The map places the cards in the **order you list them**, clockwise from the top.
- If subnets overlap, the **most specific** one wins (a `/24` inside a `/16` takes priority).
- Traffic to addresses outside every subnet (the internet, multicast) is listed in the event table
  as `External/?` but not drawn on the map.
- About 4–12 networks fit the map comfortably.

### `senders` (required)

The IP addresses allowed to send syslog. Messages from anywhere else are counted as *rejected* and
dropped. See [router-setup.md](router-setup.md#which-ip-will-the-messages-come-from).

```json
"senders": ["192.168.20.1", "192.168.0.2"]
```

### `sender_labels`

Friendly names for senders in the **Network activity** table.

```json
"sender_labels": { "192.168.20.1": "Router", "192.168.0.2": "Controller" }
```

### `allowed_hosts`

The addresses you open the dashboard with. Requests using any other `Host` header get a short
"add this address" message. This blocks DNS-rebinding attacks from web pages you visit.

```json
"allowed_hosts": ["vlanflow.example.com", "192.168.20.50:8787"]
```

- Include the port unless it is 80/443 (for example behind a reverse proxy).
- `127.0.0.1:<port>`, `localhost:<port>` and the bind address are always allowed.
- `["*"]` accepts any host name. Only do this on a trusted network.

### Other settings

| Key | Default | Meaning |
|---|---|---|
| `title` | `"VLAN Flow"` | Browser tab title. |
| `site_name` | `"My network"` | Shown above the logo. |
| `timezone` | `""` (browser time) | IANA time zone for the header clock, e.g. `"Europe/Berlin"`. |
| `retention_days` | `7` | How long firewall events are kept. |
| `max_events` | `100000` | Maximum firewall events kept; the oldest are deleted first. |

---

## Ports, addresses and environment variables

Ports are set on the command line or with environment variables (Docker Compose `environment:`, or
`/etc/vlan-flow/vlan-flow.env` for systemd). Command-line options win.

| Option | Environment variable | Default | Meaning |
|---|---|---|---|
| `--config` | `VLANFLOW_CONFIG` | `config.json` | Config file |
| `--db` | `VLANFLOW_DB` | `data/events.sqlite3` | Event database (created automatically) |
| `--http-bind` | `VLANFLOW_HTTP_BIND` | `127.0.0.1` (Docker/systemd: `0.0.0.0`) | Dashboard listen address |
| `--port` | `VLANFLOW_PORT` | `8787` | Dashboard port |
| `--syslog-bind` | `VLANFLOW_SYSLOG_BIND` | `0.0.0.0` | Syslog listen address |
| `--syslog-port` | `VLANFLOW_SYSLOG_PORT` | `5514` | Syslog UDP port |
| `--senders` | — | from config | Comma-separated sender IPs, replaces `senders` |

Example `/etc/vlan-flow/vlan-flow.env` to serve the dashboard only on one interface:

```sh
VLANFLOW_HTTP_BIND=192.168.20.50
```

> Why port 5514 and not 514? Ports below 1024 need root. 5514 lets VLAN Flow run unprivileged.

---

## API

The dashboard uses a small read-only JSON API you can also script against:

| Endpoint | Returns |
|---|---|
| `GET /healthz` | `ok` |
| `GET /api/config` | Networks, labels and display settings (no senders or host rules) |
| `GET /api/state?minutes=60` | Health counters, per-path totals, the latest 2,000 events and the activity feed |
| `GET /api/trace?src=IP&dst=IP&port=N&proto=TCP&minutes=60` | Matching events and a verdict: `allow`, `deny`, `mixed` or `unknown` |
