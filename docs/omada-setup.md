# Omada setup

VLAN Flow needs two things from your Omada network:

1. **Syslog** sent to the VLAN Flow server (UDP port 5514).
2. **Logging turned on** for the Gateway ACL rules you want to see.

Menu names differ slightly between controller versions (software controller, OC200/OC300 hardware
controller, Omada Cloud). Look for the closest match.

---

## 1. Send syslog to VLAN Flow

1. Open the Omada controller and select your **site**.
2. Go to **Settings → Services → Remote Logging** (older versions: **Settings → Services → Syslog**,
   or **Settings → Site → Remote Logging**).
3. Turn **Remote Logging** on and enter:
   - **Syslog server IP**: the IP of the machine running VLAN Flow
   - **Port**: `5514`
4. If there is a **Client detail log** option, turn it on to also see clients joining and leaving.
5. Save.

### Which IP will the messages come from?

VLAN Flow only accepts syslog from the IPs listed in `senders`. Two sources are common:

| Sender | Its IP |
|---|---|
| **Gateway** (ER605, ER7206, …): sends the ACL decisions | Usually the gateway's address **on the VLAN where VLAN Flow runs**, e.g. `192.168.20.1` if the server is in `192.168.20.0/24`. |
| **Controller**: sends client and device events | The controller's own IP. |

Not sure? Start VLAN Flow, wait a minute, and look at **Collector health → Rejected / errors** in the
dashboard, or at the service log. Then add the right IP to `senders` and restart:

```sh
# The quickest check: watch what arrives on the port
sudo tcpdump -ni any udp port 5514
```

---

## 2. Turn on logging for ACL rules

1. Go to **Settings → Network Security → ACL → Gateway ACL**.
2. Edit each rule you care about and switch **Logging** on.
   - Turn it on for every **Deny** rule: these are the interesting ones.
   - Turn it on for important **Permit** rules (admin access, backups) if you want to see them too.
   - Leave it off for very busy permits such as DNS, or the event log fills quickly.
3. Save. Omada pushes the change to the gateway in a few seconds.

> [!TIP]
> No ACL rules yet? The **Network activity** table still shows syslog arriving, and the status bar
> says so. The map stays empty until a rule with Logging enabled matches traffic.

---

## 3. Check it works

1. Open the dashboard. The status bar should say **Collector connected · Last message …**.
2. From a device in one VLAN, try something a logged rule controls, e.g. ping or SSH to another VLAN.
3. Within a few seconds an arrow appears between the two networks, and the event is listed under
   **Connection decisions**.

Still empty? See [troubleshooting.md](troubleshooting.md).

---

## Firewall on the VLAN Flow server

If the server runs a firewall, allow:

| Port | From | Why |
|---|---|---|
| UDP 5514 | gateway and controller | syslog |
| TCP 8787 | your admin devices (or only the reverse proxy) | dashboard |

```sh
# ufw example
sudo ufw allow from 192.168.20.1 to any port 5514 proto udp
sudo ufw allow from 192.168.10.0/24 to any port 8787 proto tcp
```

If you use **inter-VLAN ACLs** yourself, remember the gateway and controller must be allowed to reach
the VLAN Flow server on UDP 5514, or the logs will be blocked by the very rules you are watching.
