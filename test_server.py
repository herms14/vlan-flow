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
CONTROLLER = ('<142>1 2026-01-01 12:00:00 Omada Controller - Site - - - [client:AA-BB-CC-00-00-01] '
              'went online on [switch:AA-BB-CC-00-00-02] on Servers VLAN network.')
GATEWAY_DHCP = ('<13>Jan  1 12:00:00 Gateway: 2026-01-01 12:00:00 dhcp_server<5>: [OMADA]DHCP Server '
                'allocated IP address 192.168.10.53 for the [client:aa:bb:cc:00:00:03 ].')
ALLOW = ('<165>2026-01-01T12:00:00+00:00 router firewall<5>: [ACL]DESC=123,ACTION=Allow,'
         'SRC=192.168.10.10,DST=10.20.1.16,PROTO=TCP,Sport=49000,Dport=8787')


def store(folder, senders=(GATEWAY,)):
    return Store(Path(folder) / 'events.db', list(senders), NETWORKS)


class CollectorTests(unittest.TestCase):
    def test_explicit_allow_and_deny(self):
        event = parse_event(ALLOW, NETWORKS)
        self.assertEqual((event['action'], event['svlan'], event['dvlan'], event['dport']), ('allow', 10, 20, 8787))
        self.assertEqual(parse_event(ALLOW.replace('Allow', 'Block'), NETWORKS)['action'], 'deny')

    def test_do_not_invent_decisions(self):
        for raw in ('connection timed out', ALLOW.replace('[ACL]', '[DHCP]'),
                    ALLOW.replace('Allow', 'Unknown'), ALLOW.replace('192.168.10.10', 'invalid'),
                    ALLOW.replace('8787', '99999')):
            self.assertIsNone(parse_event(raw, NETWORKS))

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

    def test_omada_messages_are_classified_not_counted_as_acl(self):
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
                'Add your gateway': {**good, 'senders': []},
            }
            for message, data in cases.items():
                with self.assertRaises(ConfigError) as caught:
                    load_config(self.write(folder, data))
                self.assertIn(message, str(caught.exception))
            with self.assertRaises(ConfigError):
                load_config(Path(folder) / 'missing.json')


if __name__ == '__main__':
    unittest.main()
