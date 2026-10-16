# Router and firewall setup

VLAN Flow works with any router or firewall that can do two things:

1. **Send its logs over syslog** (UDP) to the VLAN Flow server, port `5514`.
2. **Log the firewall rules** you want to see, with an allow or deny decision in each line.

Almost every router, firewall and Linux box can do both. This guide covers the general steps and
the common log formats.

---

## Supported log formats

VLAN Flow recognises these formats automatically. You don't need to choose one.

| Format | Typical sources | What a line looks like |
|---|---|---|
| **key=value** | Many SMB/enterprise routers and firewalls (FortiGate, Sophos, and others) | `action=deny srcip=10.0.10.5 dstip=10.0.20.8 dstport=22 proto=6 policyid=7` |
| **Linux netfilter** (iptables / nftables `log`) | OpenWrt, UniFi gateways, ufw, firewalld, any Linux router | `[UFW BLOCK] IN=eth0 OUT= SRC=10.0.10.5 DST=10.0.20.8 PROTO=TCP SPT=51515 DPT=22` |
| **pf filterlog** | pfSense, OPNsense | `filterlog: 5,,,1000000103,igb1,match,block,in,4,…,tcp,60,10.0.10.5,10.0.20.8,51515,22,…` |
| **MikroTik** | RouterOS | `DROP-GUEST forward: in:bridge out:ether2, … proto TCP (SYN), 10.0.10.5:51234->10.0.20.8:22, len 60` |

A line counts as a decision only when it says **allow** or **deny**: words such as `allow`,
`accept`, `pass`, `permit`, `deny`, `drop`, `block` or `reject`, or the `-A`/`-D`/`-R` rule suffix
some gateways use. Everything else (DHCP, clients joining, link changes) still shows up in the
**Network activity** table, but it isn't drawn on the map.

> [!IMPORTANT]
> **netfilter and MikroTik logs don't include the action**: it comes from the rule's **log prefix**.
> Give each logging rule a prefix that contains the decision, e.g. `DROP-GUEST`, `[BLOCK IoT]`,
> `ALLOW-ADMIN`. A rule logged without such a word is listed as activity, not as a decision.

Your device isn't recognised? Open an issue with one example log line (replace real IPs) and it can
be added.

---

## 1. Send syslog to VLAN Flow

Look for a setting called **Remote logging**, **Remote syslog**, **Syslog server** or **Log
forwarding** in your router's admin page. Enter:

- **Server**: the IP of the machine running VLAN Flow
- **Port**: `5514`
- **Protocol**: UDP
- If you can choose what to send, include **firewall** (or "filter" / "traffic") logs.

Common examples (menu names change between versions, so look for the closest match):

| Platform | Where |
|---|---|
| pfSense / OPNsense | *Status → System Logs → Settings → Remote Logging*: add the server as `IP:5514` and tick **Firewall events**. |
| OpenWrt | *System → System → Logging*: **External system log server** = VLAN Flow IP, port `5514`, protocol UDP. |
| UniFi | *Settings → System/CyberSecure → Remote logging / SIEM server*: VLAN Flow IP, port `5514`. |
| MikroTik | `/system logging action add name=vlanflow target=remote remote=<VLAN-Flow-IP> remote-port=5514`<br>`/system logging add topics=firewall action=vlanflow` |
| Linux (rsyslog) | `/etc/rsyslog.d/90-vlanflow.conf`: `kern.* @<VLAN-Flow-IP>:5514`, then `sudo systemctl restart rsyslog` |

### Which IP will the messages come from?

VLAN Flow only accepts syslog from the IPs listed in `senders` in `config.json`. A router usually
sends from **its own address on the network where VLAN Flow runs**: if the server is
`192.168.20.50`, the router's source is probably `192.168.20.1`. If a management controller or
another device also logs to VLAN Flow, add its IP too.

Not sure? Start VLAN Flow, wait a minute, and look at **Collector health → Rejected / errors**, or
watch the port:

```sh
sudo tcpdump -ni any udp port 5514
```

Add the source IP you see to `senders` and restart VLAN Flow.

---

## 2. Turn on logging for firewall rules

In your firewall rules, enable **Log** (or "Logging") on the rules you want to see.

- Log every **block/deny** rule between your networks: these are the interesting ones.
- Log important **allow** rules too (admin access, backups) if you want to see them.
- Leave logging off for very busy allows such as DNS, or the event log fills quickly.
- On netfilter-based and MikroTik devices, set a **log prefix with the decision** (see above).

Examples:

| Platform | How |
|---|---|
| pfSense / OPNsense | Edit the rule → tick **Log packets that are handled by this rule**. |
| OpenWrt | Edit the rule or zone → enable **Log** (fw4 adds prefixes such as `reject lan forward:`). |
| ufw | `sudo ufw logging on` (prefixes `[UFW BLOCK]`/`[UFW ALLOW]` are built in). |
| iptables | `-j LOG --log-prefix "DROP-GUEST "` before the `DROP` rule. |
| MikroTik | `/ip firewall filter set [find comment="guest isolation"] log=yes log-prefix="DROP-GUEST"` |

---

## 3. Check it works

1. Open the dashboard. The status bar should say **Collector connected · Last message …**.
2. From a device in one network, try something a logged rule controls, e.g. SSH to another VLAN.
3. Within a few seconds an arrow appears between the two networks, and the event is listed under
   **Connection decisions**.

Still empty? See [troubleshooting.md](troubleshooting.md).

---

## Firewall on the VLAN Flow server

If the server runs a firewall, allow:

| Port | From | Why |
|---|---|---|
| UDP 5514 | your router (and other senders) | syslog |
| TCP 8787 | your admin devices (or only the reverse proxy) | dashboard |

```sh
# ufw example
sudo ufw allow from 192.168.20.1 to any port 5514 proto udp
sudo ufw allow from 192.168.10.0/24 to any port 8787 proto tcp
```

If you filter traffic **between your own VLANs**, make sure the router can still reach the VLAN Flow
server on UDP 5514, or the logs get blocked by the very rules you are watching.
