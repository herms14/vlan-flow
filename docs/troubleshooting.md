# Troubleshooting

Start with the **Collector health** box on the right of the dashboard and the service log:

```sh
docker compose logs -f vlan-flow       # Docker
journalctl -u vlan-flow -f             # systemd
```

---

### The service will not start: "Configuration error: …"

The message names the problem, for example a missing subnet or a typo in the JSON. Fix
`config.json` and start again. Common JSON mistakes: a trailing comma after the last item, or
single quotes instead of double quotes.

### "VLAN Flow does not accept the address …"

You opened the dashboard with an address that is not in `allowed_hosts`. Add exactly the text shown
in the message (including `:8787` if it is there) and restart.

### Status says "Waiting for syslog", Messages stays at 0

Nothing is arriving. Check, in order:

1. Remote logging on your router points at the right IP, **UDP port 5514**
   ([router-setup.md](router-setup.md)).
2. The packets reach the server: `sudo tcpdump -ni any udp port 5514`.
   - Nothing in tcpdump: a firewall (the server's, or your own inter-VLAN firewall rules) blocks UDP 5514.
   - Packets in tcpdump but still 0 in the dashboard: see the next item.
3. VLAN Flow listens where you think: the startup log line shows the syslog address and port.

### Rejected / errors keeps growing

Syslog arrives from an IP that is not in `senders`. Find the source IP in tcpdump
(`IP 192.168.20.1.xxxxx > 192.168.20.50.5514`), add it to `senders`, and restart.

### Messages arrive but the map stays empty

- The **Network activity** table shows client/DHCP/device events but no `FIREWALL` rows: no rule
  with **logging** enabled has matched yet. Turn on logging for at least one rule and generate
  matching traffic.
- Firewall lines arrive but are listed as `OTHER`: the line has no allow/deny word. On netfilter
  (OpenWrt, UniFi, iptables) and MikroTik, give the rule a **log prefix** such as `DROP-GUEST`
  ([router-setup.md](router-setup.md#supported-log-formats)). Other format? Open an issue with an
  example line.
- `FIREWALL` rows exist but no arrows: the IPs do not fall inside any `networks` subnet (they show as
  `External/?` in the table), or the source and destination are in the same network. Check your
  subnets in `config.json`.
- The time window (top left) is too short. Try **Last 24 hours**.

### Wrong network on a card

Overlapping subnets: the most specific subnet wins. Make sure each VLAN's subnet is listed exactly.

### Docker: all syslog is rejected, sender shows as `172.17.0.1`

Without host networking, Docker can replace the sender's real IP. The supplied
`docker-compose.yml` uses `network_mode: host` to avoid this. On Docker Desktop (Windows/macOS) host
networking is limited; run VLAN Flow on a Linux host, or use the systemd install.

### Dashboard shows "Collector unavailable"

The browser cannot reach the API. The service stopped, or a reverse proxy in front of it is
failing. Check the service log and `curl http://<server>:8787/healthz` from the server.

### The database grows too large

Lower `retention_days` or `max_events` in `config.json`, or turn Logging off for very busy permit
rules (DNS is the usual culprit).

### Reset everything

```sh
docker compose down -v && docker compose up -d       # Docker: deletes the event volume
sudo systemctl stop vlan-flow && sudo rm -rf /var/lib/private/vlan-flow && sudo systemctl start vlan-flow
```
