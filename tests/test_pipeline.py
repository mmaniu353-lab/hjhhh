import copy
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('gate', Path(__file__).resolve().parents[1]/'vpngate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

def node(host='vpn100.opengw.net', delay=100):
    return {'host':host,'port':443,'ip':'192.0.2.1','country':'Japan','country_code':'JP',
            'success':True,'residential':'residential','latency_ms':delay,'exit':{'ip':'8.8.8.8'}}

class PipelineTests(unittest.TestCase):
    def setUp(self):
        entry=patch.object(gate,'get_entry_addresses',return_value=['104.21.50.169'])
        entry.start()
        self.addCleanup(entry.stop)

    def test_success_string_is_not_a_usable_node(self):
        session=Mock()
        session.get.return_value.status_code=200
        session.get.return_value.json.return_value={'success':'false','exit':{'ip':'203.0.113.1'}}
        self.assertFalse(gate.check_one(node(), session)['success'])

    def test_zero_success_does_not_publish_empty_subscription(self):
        with patch.object(gate,'fetch_vpngate',return_value=([{}],'fixture')), \
             patch.object(gate,'to_sstp_nodes',return_value=[node()]), \
             patch.object(gate,'check_all',return_value=[dict(node(),success=False)]), \
             patch.object(gate,'write_outputs',return_value=('data','index','chains','hosts','sub')) as write:
            with self.assertRaises(SystemExit): gate.main()
            write.assert_not_called()

    def test_node_names_survive_reordering(self):
        a,b=node('vpn100.opengw.net',100),node('vpn200.opengw.net',200)
        first=gate.build_outputs([a,b],2,2,'fixture')
        a,b=copy.deepcopy(a),copy.deepcopy(b)
        a['latency_ms'],b['latency_ms']=300,50
        second=gate.build_outputs([a,b],2,2,'fixture')
        def names(data):
            return {line.split('$sstp://')[1]:line.split('$sstp://')[0] for line in gate.build_chains_text(data).splitlines() if '$sstp://' in line and not line.startswith('#')}
        self.assertEqual(names(first),names(second))

    def test_transient_node_cannot_enter_stable_pool(self):
        if not hasattr(gate,'check_stable_node'): self.fail('No repeated verification exists')
        with patch.object(gate,'VERIFY_PASSES',2), patch.object(gate,'check_one',side_effect=[node(),dict(node(),success=False,error='offline')]):
            self.assertFalse(gate.check_stable_node(node())['success'])

    def test_exit_change_cannot_enter_stable_pool(self):
        if not hasattr(gate,'check_stable_node'): self.fail('No repeated verification exists')
        changed=dict(node(),exit={'ip':'8.8.4.4'})
        with patch.object(gate,'VERIFY_PASSES',2), patch.object(gate,'check_one',side_effect=[node(),changed]):
            self.assertFalse(gate.check_stable_node(node())['success'])

    def test_mihomo_pool_excludes_datacenter_and_keeps_dns_on_selected_exit(self):
        if not hasattr(gate,'build_mihomo_config'): self.fail('No automatically updated strict configuration exists')
        data=gate.build_outputs([node(),dict(node('dc.opengw.net'),residential='datacenter')],2,2,'fixture')
        cfg,pool=gate.build_mihomo_config(data)
        self.assertEqual(len(pool['proxies']),1)
        self.assertIn('#住宅出口',cfg['dns']['nameserver'][0])
        self.assertFalse(cfg['dns'].get('fallback'))
        self.assertTrue(cfg['tun']['strict-route'])
        self.assertEqual(cfg['rules'][-1],'MATCH,住宅出口')
        self.assertFalse(any('DIRECT' in group.get('proxies',[]) for group in cfg['proxy-groups']))
        for group in cfg['proxy-groups']:
            if group['type']=='fallback':
                self.assertEqual(group['proxies'],['REJECT'])

    def test_incomplete_or_malformed_exit_never_becomes_successful(self):
        for body in [{'success':True}, {'success':True,'exit':'broken'},
                     {'success':True,'exit':{'ip':'8.8.8.8','asn':'broken'}}]:
            with self.subTest(body=body):
                session=Mock()
                session.get.return_value.status_code=200
                session.get.return_value.json.return_value=body
                self.assertFalse(gate.check_one(node(),session).get('success'))

    def test_no_residential_success_preserves_previous_subscription(self):
        with patch.object(gate,'fetch_vpngate',return_value=([{}],'fixture')), \
             patch.object(gate,'to_sstp_nodes',return_value=[node()]), \
             patch.object(gate,'check_all',return_value=[dict(node(),residential='datacenter')]), \
             patch.object(gate,'write_outputs',return_value=('data','index','chains','hosts','sub')) as write:
            with self.assertRaises(SystemExit): gate.main()
            write.assert_not_called()

if __name__=='__main__': unittest.main(verbosity=2)
