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

    def test_japan_group_selects_fastest_healthy_exit_and_rejects_empty_pool(self):
        data=gate.build_outputs([node()],1,1,'fixture')
        cfg,_=gate.build_mihomo_config(data)
        group=next(group for group in cfg['proxy-groups'] if group['name']=='日本住宅自动')
        self.assertEqual(group['type'],'url-test')
        self.assertEqual(group['interval'],120)
        self.assertEqual(group['tolerance'],100)
        self.assertEqual(group['url'],'https://1.1.1.1/')
        self.assertEqual(group['expected-status'],301)
        self.assertEqual(group['empty-fallback'],'REJECT')
        self.assertEqual(group['proxies'],['REJECT'])
        self.assertEqual(cfg['proxy-providers']['住宅节点']['health-check']['url'],group['url'])
        self.assertEqual(cfg['proxy-providers']['住宅节点']['health-check']['expected-status'],301)

    def test_full_https_latency_orders_country_and_generated_proxy_pool(self):
        slow=dict(node('vpn100.opengw.net',50),https_latency_ms=1500)
        fast=dict(node('vpn200.opengw.net',900),https_latency_ms=300)
        invalid=[dict(node(f'vpn{300+index}.opengw.net',1),https_latency_ms=value)
                 for index,value in enumerate([None,True,'1',-1,float('nan'),float('inf')])]
        data=gate.build_outputs([slow]+invalid+[fast],8,8,'fixture')
        self.assertEqual([n['host'] for n in data['countries']['Japan']['nodes'][:2]],
                         ['vpn200.opengw.net','vpn100.opengw.net'])
        _,pool=gate.build_mihomo_config(data)
        self.assertEqual([n['name'] for n in pool['proxies'][:2]],
                         [gate.node_name(fast),gate.node_name(slow)])

    def test_stable_japan_exit_is_default_and_switches_only_on_failure(self):
        cfg,_=gate.build_mihomo_config(gate.build_outputs([node()],1,1,'fixture'))
        stable=next(g for g in cfg['proxy-groups'] if g['name']=='日本住宅稳定')
        self.assertEqual(stable['type'],'fallback')
        self.assertEqual(stable['filter'],'^日本-住宅-')
        self.assertEqual(stable['proxies'],['REJECT'])
        self.assertEqual(stable['empty-fallback'],'REJECT')
        self.assertEqual(stable['interval'],120)
        self.assertEqual(cfg['proxy-groups'][0]['proxies'][0],'日本住宅稳定')

    def test_confirmed_exit_country_overrides_source_for_groups_and_names(self):
        source=dict(node(),country='United States',country_code='US',
                    exit={'ip':'8.8.8.8','country':'Japan','country_code':'JP'})
        data=gate.build_outputs([source],1,1,'fixture')
        self.assertEqual(data['available'][0]['country_code'],'JP')
        self.assertEqual(set(data['countries']),{'Japan'})
        cfg,pool=gate.build_mihomo_config(data)
        self.assertIn('日本住宅自动',[g['name'] for g in cfg['proxy-groups']])
        self.assertTrue(pool['proxies'][0]['name'].startswith('日本-住宅-'))
        self.assertEqual(source['country_code'],'US')

    def test_invalid_exit_country_code_preserves_source_country(self):
        source=dict(node(),exit={'ip':'8.8.8.8','country':'unexpected','country_code':'bad/code'})
        data=gate.build_outputs([source],1,1,'fixture')
        self.assertEqual(data['available'][0]['country_code'],'JP')
        self.assertEqual(set(data['countries']),{'Japan'})

    def test_limited_checks_prioritize_japan_candidates(self):
        jp=node('vpn300.opengw.net')
        us=dict(node('vpn100.opengw.net'),country='United States',country_code='US')
        with patch.object(gate,'MAX_CHECK_NODES',1), \
             patch.object(gate,'fetch_vpngate',return_value=([{},{}],'fixture')), \
             patch.object(gate,'to_sstp_nodes',return_value=[us,jp]), \
             patch.object(gate,'check_all',return_value=[jp]) as check, \
             patch.object(gate,'verify_end_to_end',side_effect=lambda results:results), \
             patch.object(gate,'write_outputs',return_value=('data','index','chains','hosts','sub')):
            gate.main()
        self.assertEqual(check.call_args.args[0],[jp])

    def test_verified_entry_survives_https_latency_reordering(self):
        entries=['172.64.155.1','172.64.144.1']
        slow=dict(node('vpn100.opengw.net'),https_latency_ms=1500,entry_address=entries[0])
        fast=dict(node('vpn200.opengw.net'),https_latency_ms=300,entry_address=entries[1])
        data=gate.build_outputs([slow,fast],2,2,'fixture')
        with patch.object(gate,'get_entry_addresses',return_value=entries):
            _,pool=gate.build_mihomo_config(data)
        self.assertEqual({n['name']:n['server'] for n in pool['proxies']},
                         {gate.node_name(slow):entries[0],gate.node_name(fast):entries[1]})

    def test_unknown_verified_entry_cannot_override_configured_front_ips(self):
        for entry in ['8.8.8.8','evil.example',None,True]:
            with self.subTest(entry=entry):
                data=gate.build_outputs([dict(node(),entry_address=entry)],1,1,'fixture')
                _,pool=gate.build_mihomo_config(data)
                self.assertEqual(pool['proxies'][0]['server'],'104.21.50.169')

if __name__=='__main__': unittest.main(verbosity=2)
