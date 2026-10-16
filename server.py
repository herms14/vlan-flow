"""VLAN Flow: collect firewall syslog and map logged allow/deny decisions between networks.

Python 3.9+ standard library only. See README.md for setup.
"""
import argparse
from collections import Counter, deque
from contextlib import contextmanager
import ipaddress
import json
import os
import re
import socketserver
import sqlite3
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

HERE = Path(__file__).resolve().parent
# Syslog framing: RFC 5424 "<PRI>1 TIMESTAMP HOST APP PROCID MSGID SD MSG" (some devices put spaces in
# TIMESTAMP/HOST, hence the first form) or RFC 3164 "<PRI>Mon DD HH:MM:SS HOST: MSG".
HEADER = re.compile(r'^<\d{1,3}>(?:1 .{1,120}? - - - |1 \S+ \S+ \S+ \S+ \S+ (?:-|\[[^\]]*\]) |'
                    r'[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d \S+: )')
RECENT_LIMIT = 300
DEFAULTS = {'title': 'VLAN Flow', 'site_name': 'My network', 'timezone': '', 'networks': [],
            'senders': [], 'sender_labels': {}, 'allowed_hosts': [], 'retention_days': 7,
            'max_events': 100000}


class ConfigError(ValueError):
    pass


def load_config(path):
    """Read and validate config.json; raise ConfigError with a message a person can act on."""
    try:
        raw = json.loads(Path(path).read_text(encoding='utf-8'))
    except FileNotFoundError:
        raise ConfigError(f'Config file not found: {path}. Copy config.example.json to config.json and edit it.')
    except json.JSONDecodeError as error:
        raise ConfigError(f'{path} is not valid JSON (line {error.lineno}, column {error.colno}): {error.msg}')
    config = {**DEFAULTS, **{k: v for k, v in raw.items() if not k.startswith('_')}}
    networks, seen = [], set()
    for index, net in enumerate(config['networks']):
        try:
            number = int(net['id'])
            subnet = ipaddress.ip_network(net['subnet'], strict=False)
        except (KeyError, TypeError, ValueError):
            raise ConfigError(f'networks[{index}] needs a numeric "id" and a valid "subnet" such as "192.168.10.0/24".')
        if number in seen:
            raise ConfigError(f'networks[{index}]: id {number} is used twice.')
        seen.add(number)
        networks.append({'id': number, 'name': str(net.get('name') or f'Network {number}'),
                         'role': str(net.get('role') or '').upper(), 'subnet': str(subnet)})
    if not networks:
        raise ConfigError('Add at least one entry to "networks" in the config file.')
    for key in ('senders', 'allowed_hosts'):
        if not isinstance(config[key], list):
            raise ConfigError(f'"{key}" must be a list.')
    for sender in config['senders']:
        try:
            ipaddress.ip_address(sender)
        except ValueError:
            raise ConfigError(f'"senders" entry {sender!r} is not an IP address.')
    if not config['senders']:
        raise ConfigError('Add your router/firewall IP to "senders"; syslog from anything else is ignored.')
    config['networks'] = networks
    config['retention_days'] = max(1, int(config['retention_days']))
    config['max_events'] = max(1000, int(config['max_events']))
    return config


class NetworkMap:
    """Resolve an IP to the configured network it belongs to (most specific subnet wins)."""

    def __init__(self, networks):
        nets = [(ipaddress.ip_network(n['subnet']), n['id']) for n in networks]
        self.nets = sorted(nets, key=lambda item: item[0].prefixlen, reverse=True)

    def lookup(self, ip):
        address = ipaddress.ip_address(ip)
        for net, number in self.nets:
            if address.version == net.version and address in net:
                return number
        return None


def classify(line):
    """Label every received message so non-firewall syslog stays visible instead of silently counted."""
    if extract(line):
        return 'acl'
    upper = line.upper()
    if 'DHCP' in upper:
        return 'dhcp'
    if '[CLIENT:' in upper or re.search(r'\b(ASSOCIATED|DISASSOCIATED|WENT ONLINE|WENT OFFLINE|CONNECTED TO|DISCONNECTED FROM)\b', upper):
        return 'client'
    if re.search(r'\[(SWITCH|AP|GATEWAY):|\bADOPT|\bLINK (UP|DOWN)\b|\bPORT \S+ (UP|DOWN)\b', upper):
        return 'device'
    return 'system'


def summary(line):
    text = HEADER.sub('', line.strip(), count=1)
    return re.sub(r'\s+', ' ', text)[:400]


# ---------------------------------------------------------------------------
# Firewall log formats. Each parser returns a dict with action/src/dst/proto/sport/dport/rule
# or None. A line only counts as a decision when it states allow or deny explicitly.
# ---------------------------------------------------------------------------

ALLOW_WORDS = {'allow', 'allowed', 'accept', 'accepted', 'pass', 'passed', 'permit', 'permitted'}
DENY_WORDS = {'deny', 'denied', 'drop', 'dropped', 'block', 'blocked', 'reject', 'rejected'}
PROTOCOLS = {'6': 'TCP', '17': 'UDP', '1': 'ICMP', '58': 'ICMPV6'}
KV = re.compile(r'(?<![\w.-])([A-Za-z_][\w.-]*)=("[^"]*"|[^,\s]*)')
ALIASES = {
    'action': ('action', 'act', 'log_subtype', 'disposition', 'verdict'),
    'src': ('src', 'srcip', 'src_ip', 'source', 'sourceip', 'source_ip', 'saddr'),
    'dst': ('dst', 'dstip', 'dst_ip', 'destination', 'destip', 'dest_ip', 'daddr'),
    'sport': ('sport', 'srcport', 'src_port', 'spt', 'sourceport', 'source_port'),
    'dport': ('dport', 'dstport', 'dst_port', 'dpt', 'destport', 'dest_port'),
    'proto': ('proto', 'protocol', 'ip_protocol'),
    'rule': ('desc', 'rule', 'rule_id', 'ruleid', 'rule_name', 'rulename', 'policyid', 'policy_id',
             'policyname', 'policy', 'fw_rule_id'),
}


def word_action(text):
    """allow/deny from a log prefix or rule name, e.g. '[DROP]', 'BLOCK-GUEST', UniFi '...-2000-D'."""
    words = set(re.findall(r'[a-z]+', text.lower()))
    if words & DENY_WORDS:
        return 'deny'
    if words & ALLOW_WORDS:
        return 'allow'
    suffix = re.search(r'-([ADR])\]?\s*$', text.strip())
    if suffix:
        return 'allow' if suffix.group(1) == 'A' else 'deny'
    return None


def decision(action, src, dst, proto='', sport=None, dport=None, rule=''):
    try:
        src, dst = str(ipaddress.ip_address(src)), str(ipaddress.ip_address(dst))
        ports = [int(p) if p not in (None, '') else None for p in (sport, dport)]
    except (TypeError, ValueError):
        return None
    if any(p is not None and not 0 <= p <= 65535 for p in ports):
        return None
    proto = str(proto or '?').upper()
    return dict(action=action, src=src, dst=dst, proto=PROTOCOLS.get(proto, proto)[:16],
                sport=ports[0], dport=ports[1], rule=str(rule)[:128])


def parse_keyvalue(text):
    """key=value logs (many routers and firewalls), e.g. 'action=deny srcip=… dstip=… dstport=22'."""
    raw = {k.lower(): v.strip('"') for k, v in KV.findall(text)}
    fields = {name: next((raw[k] for k in keys if raw.get(k)), None) for name, keys in ALIASES.items()}
    if not fields['action'] or not fields['src'] or not fields['dst']:
        return None
    action = fields['action'].lower()
    action = 'allow' if action in ALLOW_WORDS else 'deny' if action in DENY_WORDS else None
    if not action:
        return None
    return decision(action, fields['src'], fields['dst'], fields['proto'], fields['sport'], fields['dport'],
                    fields['rule'] or '')


def parse_netfilter(text):
    """Linux netfilter/iptables LOG lines (OpenWrt, UniFi, ufw, firewalld): '<prefix> IN=… SRC=… DST=… DPT=…'."""
    match = re.search(r'(.*?)\bIN=\S*\s+OUT=', text)
    if not match or 'SRC=' not in text:
        return None
    raw = dict(KV.findall(text))
    # Keep only the rule's log prefix: drop "host kernel:", "program:" and the "[ 1234.567]" uptime stamp.
    parts = [p for p in re.split(r'kernel:\s*|:\s', match.group(1)) if p.strip()]
    prefix = parts[-1] if parts else ''
    prefix = re.sub(r'\[\s*\d+\.\d+\]\s*', '', prefix).strip()
    action = word_action(prefix)
    if not action:
        return None
    return decision(action, raw.get('SRC'), raw.get('DST'), raw.get('PROTO'), raw.get('SPT'), raw.get('DPT'),
                    prefix.strip('[] '))


def parse_filterlog(text):
    """pf filterlog CSV (pfSense, OPNsense)."""
    # With an RFC 5424 header the "filterlog" tag is stripped and the CSV starts the message.
    match = (re.search(r'filterlog(?:\[\d+\])?:\s*(\S+)', text)
             or re.match(r'(\d*,[^,]*,[^,]*,[^,]*,[^,]+,\w+,(?:pass|block|reject),(?:in|out),[46],\S*)', text))
    if not match:
        return None
    f = match.group(1).split(',')
    try:
        action = {'pass': 'allow', 'block': 'deny', 'reject': 'deny'}.get(f[6])
        if not action:
            return None
        if f[8] == '4':
            proto, src, dst, rest = f[16], f[18], f[19], f[20:]
        elif f[8] == '6':
            proto, src, dst, rest = f[12], f[15], f[16], f[17:]
        else:
            return None
    except IndexError:
        return None
    ports = rest[:2] if proto.lower() in ('tcp', 'udp') and len(rest) >= 2 else (None, None)
    return decision(action, src, dst, proto, ports[0], ports[1], f[3] or f[0])


def parse_mikrotik(text):
    """MikroTik firewall log: '<prefix> forward: in:… proto TCP (SYN), 10.0.0.5:51234->10.0.1.9:22, len 60'.
    The action comes from the rule's log prefix, so give logging rules a prefix such as DROP or ALLOW."""
    match = re.search(r'(?:^|\s)(\S[^:]*?)?\s*(?:forward|input|output|prerouting|postrouting):\s.*?'
                      r'proto (\w+)(?: \([^)]*\))?, \[?([\w.:]+?)\]?(?::(\d+))?->\[?([\w.:]+?)\]?(?::(\d+))?,', text)
    if not match:
        return None
    prefix = match.group(1) or ''
    action = word_action(prefix)
    if not action:
        return None
    return decision(action, match.group(3), match.group(5), match.group(2), match.group(4), match.group(6),
                    prefix.strip())


PARSERS = (parse_filterlog, parse_netfilter, parse_mikrotik, parse_keyvalue)


def extract(line):
    text = HEADER.sub('', line.strip(), count=1)
    for parser in PARSERS:
        event = parser(text)
        if event:
            event['format'] = parser.__name__[6:]
            return event
    return None


def parse_event(line, networks):
    # Do not infer decisions from timeouts, byte counters or unrelated syslog.
    event = extract(line)
    if event is None:
        return None
    stamp = re.search(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?', line)
    event.pop('format')
    return dict(event, svlan=networks.lookup(event['src']), dvlan=networks.lookup(event['dst']),
                device_time=stamp.group(0) if stamp else '')


class Store:
    def __init__(self, path, senders, networks, retention_days=7, max_events=100000):
        self.path = str(path)
        self.senders = set(senders)
        self.networks = networks
        self.retention = retention_days * 86400
        self.max_events = max_events
        self.lock = threading.Lock()
        self.health = dict(started=time.time(), received=0, parsed=0, unparsed=0,
                           rejected=0, errors=0, last_received=None, last_event=None)
        # Recent raw messages are memory-only diagnostics; only explicit firewall decisions are persisted.
        self.recent = deque(maxlen=RECENT_LIMIT)
        self.kinds = Counter()
        with self.connect() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('''CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY, received REAL, sender TEXT, action TEXT,
                src TEXT, dst TEXT, svlan INTEGER, dvlan INTEGER, proto TEXT,
                sport INTEGER, dport INTEGER, rule TEXT, device_time TEXT)''')
            db.execute('CREATE INDEX IF NOT EXISTS event_time ON events(received)')
        self.prune_at = 0

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        try:
            with db:
                yield db
        finally:
            db.close()

    def ingest(self, message, sender):
        if sender not in self.senders:
            with self.lock:
                self.health['rejected'] += 1
            return
        now = time.time()
        kind = classify(message)
        with self.lock:
            self.health['received'] += 1
            self.health['last_received'] = now
            self.kinds[kind] += 1
            self.recent.append(dict(received=now, sender=sender, kind=kind, text=summary(message)))
        event = parse_event(message, self.networks)
        if event is None:
            with self.lock:
                self.health['unparsed'] += 1
            return
        with self.connect() as db:
            db.execute('''INSERT INTO events
                (received,sender,action,src,dst,svlan,dvlan,proto,sport,dport,rule,device_time)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)''',
                [now, sender] + [event[k] for k in ('action', 'src', 'dst', 'svlan', 'dvlan', 'proto',
                                                    'sport', 'dport', 'rule', 'device_time')])
            if now > self.prune_at:
                db.execute('DELETE FROM events WHERE received < ?', (now - self.retention,))
                db.execute('DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM events)',
                           (self.max_events,))
                self.prune_at = now + 60
        with self.lock:
            self.health['parsed'] += 1
            self.health['last_event'] = now

    def snapshot(self, minutes):
        since = time.time() - minutes * 60
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            flows = [dict(row) for row in db.execute('''SELECT svlan,dvlan,action,COUNT(*) count,
                MAX(received) latest FROM events WHERE received >= ? GROUP BY svlan,dvlan,action''', (since,))]
            events = [dict(row) for row in db.execute(
                'SELECT * FROM events WHERE received >= ? ORDER BY id DESC LIMIT 2000', (since,))]
            count = db.execute('SELECT COUNT(*) FROM events WHERE received >= ?', (since,)).fetchone()[0]
        with self.lock:
            health = dict(self.health, kinds=dict(self.kinds))
            recent = list(reversed(self.recent))
        return dict(health=health, events=events, flows=flows, total=count, minutes=minutes,
                    event_limit=2000, allowed_senders=sorted(self.senders),
                    recent=recent, recent_limit=RECENT_LIMIT)

    def trace(self, query):
        src = str(ipaddress.ip_address(query.get('src', [''])[0]))
        dst = str(ipaddress.ip_address(query.get('dst', [''])[0]))
        port = int(query.get('port', [''])[0])
        proto = query.get('proto', ['TCP'])[0].upper()
        if not 1 <= port <= 65535 or proto not in ('TCP', 'UDP'):
            raise ValueError('Use TCP or UDP and a destination port from 1 to 65535')
        minutes = min(10080, max(1, int(query.get('minutes', ['60'])[0])))
        args = [time.time() - minutes * 60, src, dst, port, proto]
        where = 'received >= ? AND src=? AND dst=? AND dport=? AND proto=?'
        sport = query.get('sport', [''])[0]
        if sport:
            sport = int(sport)
            if not 0 <= sport <= 65535:
                raise ValueError('Invalid source port')
            where += ' AND sport=?'
            args.append(sport)
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            counts = {r['action']: r['n'] for r in db.execute(
                'SELECT action,COUNT(*) n FROM events WHERE ' + where + ' GROUP BY action', args)}
            events = [dict(r) for r in db.execute(
                'SELECT * FROM events WHERE ' + where + ' ORDER BY id DESC LIMIT 500', args)]
        verdict = 'mixed' if len(counts) > 1 else next(iter(counts), 'unknown')
        return dict(src=src, dst=dst, svlan=self.networks.lookup(src), dvlan=self.networks.lookup(dst),
                    port=port, proto=proto, sport=sport, minutes=minutes, counts=counts, verdict=verdict,
                    events=events, total=sum(counts.values()), limit=500)


def public_config(config):
    """The subset of the config the browser needs. Never includes senders or host rules."""
    return {k: config[k] for k in ('title', 'site_name', 'timezone', 'networks', 'sender_labels')}


def run(args):
    config = load_config(args.config)
    if args.senders:
        config['senders'] = [s.strip() for s in args.senders.split(',') if s.strip()]
    networks = NetworkMap(config['networks'])
    args.db.parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.db, config['senders'], networks, config['retention_days'], config['max_events'])
    client_config = json.dumps(public_config(config)).encode()

    class UDP(socketserver.BaseRequestHandler):
        def handle(self):
            try:
                store.ingest(self.request[0].decode('utf-8', 'replace'), self.client_address[0])
            except Exception:
                with store.lock:
                    store.health['errors'] += 1

    receiver = socketserver.UDPServer((args.syslog_bind, args.syslog_port), UDP)
    receiver.max_packet_size = 65535
    hosts = set(config['allowed_hosts'])
    any_host = '*' in hosts
    hosts.update({f'127.0.0.1:{args.port}', f'localhost:{args.port}', f'{args.http_bind}:{args.port}'})

    class HTTP(BaseHTTPRequestHandler):
        def do_GET(self):
            # Host allowlist guards against DNS rebinding; "*" in allowed_hosts turns it off.
            host = self.headers.get('Host', '')
            if not any_host and host not in hosts:
                body = (f'VLAN Flow does not accept the address "{host}".\n'
                        f'Add "{host}" to "allowed_hosts" in the config file and restart the service.\n').encode()
                self.send_response(403)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            target = urlparse(self.path)
            if target.path == '/healthz':
                body, mime = b'ok\n', 'text/plain'
            elif target.path == '/api/config':
                body, mime = client_config, 'application/json'
            elif target.path == '/api/state':
                try:
                    minutes = min(10080, max(1, int(parse_qs(target.query).get('minutes', ['60'])[0])))
                except ValueError:
                    self.send_error(400)
                    return
                body, mime = json.dumps(store.snapshot(minutes)).encode(), 'application/json'
            elif target.path == '/api/trace':
                try:
                    result = store.trace(parse_qs(target.query))
                except ValueError:
                    self.send_error(400, 'Invalid IP, port, protocol or time window')
                    return
                body, mime = json.dumps(result).encode(), 'application/json'
            elif target.path == '/':
                body, mime = (HERE / 'dashboard.html').read_bytes(), 'text/html; charset=utf-8'
            elif target.path in ('/app.js', '/style.css'):
                body = (HERE / target.path[1:]).read_bytes()
                mime = 'text/javascript' if target.path.endswith('.js') else 'text/css'
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header('Content-Type', mime)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *unused):
            pass

    http = ThreadingHTTPServer((args.http_bind, args.port), HTTP)
    threading.Thread(target=receiver.serve_forever, daemon=True).start()
    print(f'VLAN Flow: dashboard http://{args.http_bind}:{args.port} · syslog UDP {args.syslog_bind}:{args.syslog_port} · '
          f'{len(config["networks"])} networks · accepting syslog from {", ".join(config["senders"])}', flush=True)
    try:
        http.serve_forever()
    finally:
        receiver.shutdown()
        receiver.server_close()
        http.server_close()


def main():
    env = os.environ.get
    parser = argparse.ArgumentParser(description='VLAN Flow: firewall syslog collector and dashboard')
    parser.add_argument('--config', type=Path, default=Path(env('VLANFLOW_CONFIG', 'config.json')),
                        help='Path to config.json (env VLANFLOW_CONFIG)')
    parser.add_argument('--db', type=Path, default=Path(env('VLANFLOW_DB', 'data/events.sqlite3')),
                        help='SQLite database file (env VLANFLOW_DB)')
    parser.add_argument('--http-bind', default=env('VLANFLOW_HTTP_BIND', '127.0.0.1'),
                        help='Address for the dashboard (env VLANFLOW_HTTP_BIND)')
    parser.add_argument('--port', type=int, default=int(env('VLANFLOW_PORT', '8787')),
                        help='Dashboard port (env VLANFLOW_PORT)')
    parser.add_argument('--syslog-bind', default=env('VLANFLOW_SYSLOG_BIND', '0.0.0.0'),
                        help='Address for the syslog receiver (env VLANFLOW_SYSLOG_BIND)')
    parser.add_argument('--syslog-port', type=int, default=int(env('VLANFLOW_SYSLOG_PORT', '5514')),
                        help='UDP syslog port (env VLANFLOW_SYSLOG_PORT)')
    parser.add_argument('--senders', default='', help='Comma-separated sender IPs; overrides "senders" in the config')
    args = parser.parse_args()
    try:
        run(args)
    except ConfigError as error:
        raise SystemExit(f'Configuration error: {error}')


if __name__ == '__main__':
    main()
