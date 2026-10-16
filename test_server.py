import json
import tempfile
import unittest
from pathlib import Path

from server import ConfigError, NetworkMap, Store, classify, load_config, parse_event, public_config, summary

NETWORKS = NetworkMap([
    {'id': 1, 'subnet': '192.168.0.0/24'},
    {'id': 10, 'subnet': '192.168.10.0/24'},
    {'id': 20, 'subnet': '10.20.0.0/16'},
    {'id': 21, 'subnet': '10.20.5.0/24'},
])
GATEWAY = '192.168.0.1'
CONTROLLER_IP = '192.168.0.2'
CONTROLLER = ('<142>1 2026-01-01 12:00:00 Network Controller - Site - - - [client:AA-BB-CC-00-00-01] '
              'went online on [switch:AA-BB-CC-00-00-02] on Servers VLAN network.')
GATEWAY_DHCP = ('<13>Jan  1 12:00:00 Gateway: 2026-01-01 12:00:00 dhcp_server<5>: DHCP Server '
                'allocated IP address 192.168.10.53 for the [client:aa:bb:cc:00:00:03 ].')
ALLOW = ('<165>2026-01-01T12:00:00+00:00 router firewall<5>: [FIREWALL]DESC=123,ACTION=Allow,'
         'SRC=192.168.10.10,DST=10.20.1.16,PROTO=TCP,Sport=49000,Dport=8787')
# One real-world line per supported format; expected (action, src, dst, proto, dport, rule).
FORMATS = {
    'keyvalue quoted': ('<189>date=2026-01-01 time=12:00:00 devname="fw01" type="traffic" action="deny" '
                        'srcip=192.168.10.10 srcport=51515 dstip=10.20.1.16 dstport=22 proto=6 policyid=7',
                        ('deny', '192.168.10.10', '10.20.1.16', 'TCP', 22, '7')),
    'keyvalue subtype': ('<30>device_name="FW" log_type="Firewall" log_subtype="Allowed" src_ip=192.168.10.10 '
                         'dst_ip=10.20.1.16 protocol="UDP" src_port=5353 dst_port=53 fw_rule_id=4',
                         ('allow', '192.168.10.10', '10.20.1.16', 'UDP', 53, '4')),
    'netfilter ufw': ('<4>Jan  1 12:00:00 host kernel: [ 1234.567890] [UFW BLOCK] IN=eth0 OUT= MAC=00:11 '
                      'SRC=192.168.10.10 DST=10.20.1.16 LEN=60 TOS=0x00 PROTO=TCP SPT=51515 DPT=22 WINDOW=64240 SYN',
                      ('deny', '192.168.10.10', '10.20.1.16', 'TCP', 22, 'UFW BLOCK')),
    'netfilter unifi': ('<4>Jan  1 12:00:00 UDM kernel: [LAN_IN-RET-2000-A]IN=br0 OUT=br20 MAC=00:11 '
                        'SRC=192.168.10.10 DST=10.20.1.16 LEN=52 PROTO=TCP SPT=40000 DPT=443',
                        ('allow', '192.168.10.10', '10.20.1.16', 'TCP', 443, 'LAN_IN-RET-2000-A')),
    'netfilter openwrt': ('<4>Jan  1 12:00:00 OpenWrt kernel: [  99.1] reject lan_iot forward: IN=br-lan OUT=br-iot '
                          'SRC=192.168.10.10 DST=10.20.1.16 PROTO=UDP SPT=5000 DPT=1900',
                          ('deny', '192.168.10.10', '10.20.1.16', 'UDP', 1900, 'reject lan_iot forward')),
    'filterlog ipv4': ('<134>Jan  1 12:00:00 pfsense filterlog[123]: 5,,,1000000103,igb1,match,block,in,4,0x0,,64,0,0,'
                       'DF,6,tcp,60,192.168.10.10,10.20.1.16,51515,22,0,S,1,,64240,,mss',
                       ('deny', '192.168.10.10', '10.20.1.16', 'TCP', 22, '1000000103')),
    'filterlog ipv6': ('<134>1 2026-01-01T12:00:00Z opnsense filterlog 123 - [meta] 82,,,fae5593,vtnet0,match,pass,out,6,'
                       '0x00,0x00000,64,udp,17,40,fd00::10,fd00:1::20,5353,53,40',
                       ('allow', 'fd00::10', 'fd00:1::20', 'UDP', 53, 'fae5593')),
    'mikrotik': ('<134>Jan  1 12:00:00 MikroTik DROP-GUEST forward: in:bridge out:ether2, connection-state:new '
                 'src-mac aa:bb:cc:dd:ee:ff, proto TCP (SYN), 192.168.10.10:51234->10.20.1.16:22, len 60',
                 ('deny', '192.168.10.10', '10.20.1.16', 'TCP', 22, 'MikroTik DROP-GUEST')),
}
NO_DECISION = (
    'connection timed out',
    '<189>action="close" srcip=192.168.10.10 dstip=10.20.1.16 dstport=22',             # session end, not a verdict
    '<4>kernel: [ 1.0] [UFW AUDIT] IN=eth0 OUT= SRC=192.168.10.10 DST=10.20.1.16 PROTO=TCP DPT=22',
    '<134>MikroTik LOG forward: in:a out:b, proto TCP (SYN), 192.168.10.10:1->10.20.1.16:22, len 60',
    '<134>filterlog[1]: 5,,,1,igb1,match,nat,in,4',
)


def store(folder, senders=(GATEWAY,)):
    return Store(Path(folder) / 'events.db', list(senders), NETWORKS)


class CollectorTests(unittest.TestCase):
    def test_explicit_allow_and_deny(self):
        event = parse_event(ALLOW, NETWORKS)
        self.assertEqual((event['action'], event['svlan'], event['dvlan'], event['dport']), ('allow', 10, 20, 8787))
        self.assertEqual(parse_event(ALLOW.replace('Allow', 'Block'), NETWORKS)['action'], 'deny')

    def test_do_not_invent_decisions(self):
        for raw in NO_DECISION + (ALLOW.replace('Allow', 'Unknown'), ALLOW.replace('192.168.10.10', 'invalid'),
                                  ALLOW.replace('8787', '99999')):
            self.assertIsNone(parse_event(raw, NETWORKS), raw)

    def test_supported_log_formats(self):
        for name, (raw, expected) in FORMATS.items():
            with self.subTest(name):
                event = parse_event(raw, NETWORKS)
                self.assertIsNotNone(event, raw)
                got = (event['action'], event['src'], event['dst'], event['proto'], event['dport'], event['rule'])
                self.assertEqual(got, expected)
                self.assertEqual(classify(raw), 'acl')

    def test_network_lookup_uses_subnets_and_most_specific_match(self):
        self.assertEqual(NETWORKS.lookup('192.168.0.2'), 1)
        self.assertEqual(NETWORKS.lookup('10.20.9.9'), 20)
        self.assertEqual(NETWORKS.lookup('10.20.5.9'), 21)
        for ip in ('8.8.8.8', '239.255.255.250', '192.168.99.2', 'fe80::1'):
            self.assertIsNone(NETWORKS.lookup(ip))

    def test_sender_filter_persistence_and_aggregation(self):
        with tempfile.TemporaryDirectory() as folder:
            s = store(folder)
            s.ingest(ALLOW, '192.168.10.99')
            s.ingest('unrelated system event', GATEWAY)
            s.ingest(ALLOW, GATEWAY)
            s.ingest(ALLOW.replace('Allow', 'Deny'), GATEWAY)
            data = s.snapshot(60)
            self.assertEqual(data['total'], 2)
            self.assertEqual(len(data['flows']), 2)
            self.assertEqual(data['health']['rejected'], 1)
            self.assertEqual(data['health']['unparsed'], 1)
            self.assertEqual(store(folder).snapshot(60)['total'], 2)

    def test_exact_trace_verdicts_and_validation(self):
        with tempfile.TemporaryDirectory() as folder:
            s = store(folder)
            query = {'src': ['192.168.10.10'], 'dst': ['10.20.1.16'], 'port': ['8787'], 'proto': ['TCP']}
            self.assertEqual(s.trace(query)['verdict'], 'unknown')
            s.ingest(ALLOW, GATEWAY)
            self.assertEqual(s.trace(query)['verdict'], 'allow')
            s.ingest(ALLOW.replace('Allow', 'Deny').replace('PROTO=TCP', 'PROTO=6'), GATEWAY)
            self.assertEqual(s.trace(query)['verdict'], 'mixed')
            self.assertEqual(s.trace({**query, 'port': ['443']})['total'], 0)
            self.assertEqual(s.trace({**query, 'sport': ['49001']})['total'], 0)
            with self.assertRaises(ValueError):
                s.trace({**query, 'src': ['not-an-ip']})
            with self.assertRaises(ValueError):
                s.trace({**query, 'port': ['70000']})

    def test_other_messages_are_classified_not_counted_as_decisions(self):
        self.assertEqual(classify(CONTROLLER), 'client')
        self.assertEqual(classify(GATEWAY_DHCP), 'dhcp')
        self.assertEqual(classify(ALLOW), 'acl')
        self.assertIsNone(parse_event(CONTROLLER, NETWORKS))
        self.assertTrue(summary(CONTROLLER).startswith('[client:AA-BB-CC-00-00-01] went online'))
        self.assertTrue(summary(GATEWAY_DHCP).startswith('2026-01-01 12:00:00 dhcp_server'))

    def test_recent_feed_keeps_non_acl_messages_in_memory_only(self):
        with tempfile.TemporaryDirectory() as folder:
            s = store(folder, [CONTROLLER_IP])
            s.ingest(CONTROLLER, CONTROLLER_IP)
            s.ingest(GATEWAY_DHCP, '192.168.10.99')
            data = s.snapshot(60)
            self.assertEqual(data['total'], 0)
            self.assertEqual([r['kind'] for r in data['recent']], ['client'])
            self.assertEqual(data['health']['kinds'], {'client': 1})
            self.assertEqual(store(folder, [CONTROLLER_IP]).snapshot(60)['recent'], [])


class ConfigTests(unittest.TestCase):
    def write(self, folder, data):
        path = Path(folder) / 'config.json'
        path.write_text(json.dumps(data) if not isinstance(data, str) else data, encoding='utf-8')
        return path

    def test_example_config_is_valid_and_public_view_hides_senders(self):
        config = load_config(Path(__file__).with_name('config.example.json'))
        self.assertGreaterEqual(len(config['networks']), 2)
        public = public_config(config)
        self.assertNotIn('senders', public)
        self.assertNotIn('allowed_hosts', public)

    def test_clear_errors(self):
        good = {'networks': [{'id': 1, 'subnet': '192.168.0.0/24'}], 'senders': ['192.168.0.1']}
        with tempfile.TemporaryDirectory() as folder:
            self.assertEqual(load_config(self.write(folder, good))['networks'][0]['name'], 'Network 1')
            cases = {
                'not valid JSON': '{"networks": [',
                'at least one': {**good, 'networks': []},
                'valid "subnet"': {**good, 'networks': [{'id': 1, 'subnet': 'nope'}]},
                'used twice': {**good, 'networks': good['networks'] * 2},
                'not an IP': {**good, 'senders': ['gateway']},
                'Add your router': {**good, 'senders': []},
            }
            for message, data in cases.items():
                with self.assertRaises(ConfigError) as caught:
                    load_config(self.write(folder, data))
                self.assertIn(message, str(caught.exception))
            with self.assertRaises(ConfigError):
                load_config(Path(folder) / 'missing.json')


if __name__ == '__main__':
    unittest.main()
