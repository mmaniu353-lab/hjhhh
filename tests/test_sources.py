import base64
from datetime import datetime, timedelta, timezone
import importlib.util
from pathlib import Path
import threading
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('source_gate', Path(__file__).resolve().parents[1] / 'vpngate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def row(host='vpn100', country='JP', port=443):
    config = base64.b64encode(f'proto tcp\nremote 8.8.8.8 {port}\n'.encode()).decode()
    return {'host': host, 'ip': '8.8.8.8', 'country_long': 'Japan' if country == 'JP' else 'United States',
            'country_short': country, 'config_b64': config}


def official_csv(rows):
    header = '#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,OpenVPN_ConfigData_Base64'
    return '\n'.join([header] + [','.join([r['host'], r['ip'], '1', '1', '1', r['country_long'],
                                         r['country_short'], r['config_b64']]) for r in rows])


def published(nodes, age_hours=1):
    timestamp = (datetime.now(timezone.utc) - timedelta(hours=age_hours)).strftime('%Y-%m-%d %H:%M:%S UTC')
    return {'generated_at': timestamp, 'available': nodes}


def previous_node(host='vpn300.opengw.net', **changes):
    result = {'host': host, 'port': 1443, 'ip': '8.8.4.4', 'country': 'Japan', 'country_code': 'JP',
              'protocol': 'sstp', 'success': True, 'verification_passes': 2, 'https_checks': 2,
              'exit': {'ip': '8.8.4.4', 'country': 'Japan', 'country_code': 'JP'}}
    result.update(changes)
    return result


def response(text='', data=None):
    result = Mock()
    result.text = text
    result.json.return_value = data
    return result


class SourceTests(unittest.TestCase):
    def get_sources(self, official, mirror, previous):
        sources = {gate.VPNGATE_API: official, gate.VPNGATE_MIRROR: mirror,
                   gate.SITE_URL + '/data.json': previous}

        def get(url, **kwargs):
            value = sources[url]
            if isinstance(value, Exception):
                raise value
            return value

        return patch.object(gate.requests, 'get', side_effect=get)

    def test_official_default_uses_https(self):
        self.assertTrue(gate.VPNGATE_API.startswith('https://'))

    def test_successful_official_source_also_fetches_mirror_and_previous_candidates(self):
        a, b = row(), row('vpn200')
        with self.get_sources(response(official_csv([a])), response(data=[{'servers': [a, b]}]),
                              response(data=published([previous_node()]))):
            rows, source = gate.fetch_vpngate()
        nodes = gate.dedupe(gate.to_sstp_nodes(rows))
        self.assertEqual({(n['host'], n['port']) for n in nodes},
                         {('vpn100.opengw.net', 443), ('vpn200.opengw.net', 443), ('vpn300.opengw.net', 1443)})
        self.assertIn('github-mirror', source)
        self.assertIn('previous-pages', source)
        reused = next(n for n in nodes if n['host'] == 'vpn300.opengw.net')
        self.assertNotIn('success', reused)
        self.assertNotIn('exit', reused)

    def test_official_and_mirror_fetches_overlap(self):
        both_started = threading.Barrier(2)

        def get(url, **kwargs):
            if url == gate.SITE_URL + '/data.json':
                return response(data=published([]))
            both_started.wait(timeout=2)
            return response(official_csv([row()])) if url == gate.VPNGATE_API else response(data=[row('vpn200')])

        with patch.object(gate.requests, 'get', side_effect=get):
            rows, _ = gate.fetch_vpngate()
        self.assertEqual(len(gate.dedupe(gate.to_sstp_nodes(rows))), 2)

    def test_one_failed_source_does_not_discard_independent_sources(self):
        with self.get_sources(RuntimeError('official offline'), response(data=[row('vpn200')]),
                              RuntimeError('pages offline')):
            rows, source = gate.fetch_vpngate()
        self.assertEqual(gate.to_sstp_nodes(rows)[0]['host'], 'vpn200.opengw.net')
        self.assertEqual(source, 'github-mirror')

    def test_fresh_previous_candidates_can_be_reverified_during_source_outage(self):
        with self.get_sources(RuntimeError('official offline'), RuntimeError('mirror offline'),
                              response(data=published([previous_node()]))):
            rows, source = gate.fetch_vpngate()
        self.assertEqual(source, 'previous-pages')
        self.assertEqual(gate.to_sstp_nodes(rows)[0]['port'], 1443)

    def test_all_unavailable_sources_fail_closed(self):
        with self.get_sources(RuntimeError('official offline'), RuntimeError('mirror offline'),
                              RuntimeError('pages offline')):
            with self.assertRaises(SystemExit):
                gate.fetch_vpngate()

    def test_stale_future_or_malformed_previous_generation_is_rejected(self):
        for data in [published([previous_node()], 25), published([previous_node()], -1),
                     {'generated_at': 'bad timestamp', 'available': [previous_node()]},
                     {'available': [previous_node()]}]:
            with self.subTest(data=data), self.get_sources(RuntimeError('official offline'),
                                                          RuntimeError('mirror offline'), response(data=data)):
                with self.assertRaises(SystemExit):
                    gate.fetch_vpngate()

    def test_previous_discovery_rejects_unusable_fields_and_is_bounded(self):
        invalid = [None, previous_node(success='true'), previous_node(protocol='http'),
                   previous_node(host='vpn100.opengw.net/evil'), previous_node(port=True),
                   previous_node(port=65536), previous_node(ip='not an ip')]
        valid = [previous_node(f'vpn{1000 + index}.opengw.net') for index in range(700)]
        with self.get_sources(RuntimeError('official offline'), RuntimeError('mirror offline'),
                              response(data=published(invalid + valid))):
            rows, _ = gate.fetch_vpngate()
        nodes = gate.dedupe(gate.to_sstp_nodes(rows))
        self.assertGreater(len(nodes), 0)
        self.assertLessEqual(len(nodes), 512)
        self.assertTrue(all(n['host'].startswith('vpn1') for n in nodes))

    def test_explicit_sstp_port_is_validated_and_bad_rows_do_not_abort_batch(self):
        explicit = dict(row(), config_b64='', sstp_port=1443)
        bad = [None, {}, dict(explicit, sstp_port=True), dict(explicit, sstp_port=3.5),
               dict(explicit, sstp_port=0), dict(explicit, sstp_port=65536),
               dict(explicit, host='evil.example'), dict(explicit, host='vpn/evil'),
               dict(explicit, ip='invalid')]
        self.assertEqual(gate.to_sstp_nodes(bad + [explicit]),
                         [{'host': 'vpn100.opengw.net', 'port': 1443, 'ip': '8.8.8.8',
                           'country': 'Japan', 'country_code': 'JP'}])

    def test_mirror_malformed_items_are_skipped(self):
        parsed = gate.parse_mirror_json([{'servers': [None, [], row()]}, 'broken', row('vpn200')])
        self.assertEqual(len(gate.to_sstp_nodes(parsed)), 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
