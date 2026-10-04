import copy
import importlib.util
import inspect
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

class WorkerBudgetTests(unittest.TestCase):
    def test_expired_worker_budget_never_requests_or_inherits_success(self):
        self.assertIn('deadline',inspect.signature(gate.check_one).parameters)
        session=Mock()
        with patch.object(gate.time,'monotonic',return_value=5):
            result=gate.check_one(dict(node(),check_attempted=True),session,deadline=5)
        self.assertFalse(result['success'])
        self.assertIn('budget',result['error'])
        session.get.assert_not_called()
        self.assertIs(result.get('check_attempted'),False)

    def test_one_exit_check_before_budget_expiry_is_not_stable_success(self):
        self.assertIn('deadline',inspect.signature(gate.check_stable_node).parameters)
        clock=[0.0]
        def first(*args,**kwargs):
            clock[0]=5.0
            return node()
        with patch.object(gate.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(gate,'VERIFY_PASSES',2), \
             patch.object(gate,'check_one',side_effect=first) as check:
            result=gate.check_stable_node(node(),deadline=5)
        self.assertFalse(result['success'])
        self.assertEqual(check.call_count,1)
        self.assertLess(result['verification_passes'],2)
        self.assertIs(result.get('check_attempted'),True)

    def test_late_valid_exit_response_does_not_qualify(self):
        self.assertIn('deadline',inspect.signature(gate.check_one).parameters)
        clock=[0.0]
        response=Mock(status_code=200)
        response.json.return_value={'success':True,'exit':{'ip':'8.8.8.8','is_datacenter':False,'asn':{'org':'KDDI'}}}
        session=Mock()
        def request(*args,**kwargs):
            clock[0]=5.0
            return response
        session.get.side_effect=request
        with patch.object(gate.time,'monotonic',side_effect=lambda:clock[0]):
            result=gate.check_one(node(),session,deadline=5)
        self.assertFalse(result['success'])

    def test_worker_connect_and_read_timeouts_fit_remaining_budget(self):
        self.assertIn('deadline',inspect.signature(gate.check_one).parameters)
        session=Mock()
        session.get.return_value.status_code=503
        with patch.object(gate.time,'monotonic',return_value=4):
            gate.check_one(node(),session,deadline=5)
        timeout=session.get.call_args.kwargs['timeout']
        self.assertLessEqual(sum(timeout) if isinstance(timeout,tuple) else timeout,1)

    def test_worker_stage_has_no_unbounded_queue_or_unchecked_success(self):
        self.assertTrue(hasattr(gate,'CHECK_STAGE_BUDGET_SECONDS'),'Worker stage has no budget')
        clock=[0.0]
        release=threading.Event()
        submitted=threading.Event()
        count=[]
        class RecordingPool(ThreadPoolExecutor):
            def submit(self,*args,**kwargs):
                future=super().submit(*args,**kwargs)
                count.append(future)
                if len(count)==2:
                    submitted.set()
                return future
        nodes=[node(f'vpn{i}.opengw.net') for i in range(7)]
        def verify(n,deadline=None):
            release.wait(2)
            return dict(n,success=False,status='failed',error='budget exhausted',verification_passes=0)
        outputs=[]
        with patch.object(gate.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(gate,'ThreadPoolExecutor',RecordingPool), \
             patch.object(gate,'CONCURRENCY',2), \
             patch.object(gate,'CHECK_STAGE_BUDGET_SECONDS',5), \
             patch.object(gate,'check_stable_node',side_effect=verify):
            thread=threading.Thread(target=lambda:outputs.extend(gate.check_all(nodes)))
            thread.start()
            try:
                self.assertTrue(submitted.wait(2))
                self.assertEqual(len(count),2)
                clock[0]=5.0
            finally:
                release.set()
                thread.join(3)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(count),2)
        self.assertEqual(len(outputs),7)
        self.assertTrue(all(n['success'] is False for n in outputs))
        self.assertTrue(all(n.get('verification_passes',0)<2 for n in outputs))

    def test_real_blocked_worker_http_wait_uses_remaining_budget(self):
        self.assertIn('deadline',inspect.signature(gate.check_one).parameters)
        requested=threading.Event()
        release=threading.Event()
        class SlowChecker(BaseHTTPRequestHandler):
            def do_GET(self):
                requested.set()
                release.wait(2)
                self.send_response(503)
                self.end_headers()
            def log_message(self,*args):
                pass
        server=ThreadingHTTPServer(('127.0.0.1',0),SlowChecker)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=0.01),daemon=True)
        thread.start()
        try:
            with gate.requests.Session() as session, \
                 patch.object(gate,'WORKER_CHECK_URL',f'http://127.0.0.1:{server.server_port}/check?sstp='):
                session.trust_env=False
                started=time.monotonic()
                result=gate.check_one(node(),session,deadline=started+0.15)
                elapsed=time.monotonic()-started
            self.assertTrue(requested.is_set())
            self.assertFalse(result['success'])
            self.assertLess(elapsed,0.75)
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(2)

    def test_disabled_budget_preserves_two_successful_checks(self):
        self.assertTrue(hasattr(gate,'CHECK_STAGE_BUDGET_SECONDS'),'Worker stage has no budget')
        response=Mock(status_code=200)
        response.json.return_value={'success':True,'responseTime':100,
            'exit':{'ip':'8.8.8.8','is_datacenter':False,'asn':{'org':'KDDI'}}}
        session=Mock()
        session.get.return_value=response
        with patch.object(gate,'VERIFY_PASSES',2), \
             patch.object(gate.requests,'Session') as factory:
            factory.return_value.__enter__.return_value=session
            result=gate.check_stable_node(node())
        self.assertTrue(result['success'])
        self.assertEqual(result['verification_passes'],2)
        self.assertEqual(session.get.call_count,2)

    def test_ample_stage_budget_preserves_original_read_timeout(self):
        session=Mock()
        session.get.return_value.status_code=503
        with patch.object(gate.time,'monotonic',return_value=0), \
             patch.object(gate,'CHECK_TIMEOUT',45):
            gate.check_one(node(),session,deadline=900)
        self.assertEqual(session.get.call_args.kwargs['timeout'][1],45)

    def test_bounded_worker_request_cannot_follow_redirect_outside_budget(self):
        session=Mock()
        session.get.return_value.status_code=302
        with patch.object(gate.time,'monotonic',return_value=0):
            result=gate.check_one(node(),session,deadline=5)
        self.assertFalse(result['success'])
        self.assertIs(session.get.call_args.kwargs.get('allow_redirects'),False)

    def test_completed_stable_node_survives_budget_and_unstarted_candidates_fail(self):
        clock=[0.0]
        nodes=[node(f'vpn{i}.opengw.net') for i in range(3)]
        def verify(n,deadline=None):
            clock[0]=5.0
            return dict(n,verification_passes=2)
        with patch.object(gate.time,'monotonic',side_effect=lambda:clock[0]), \
             patch.object(gate,'CHECK_STAGE_BUDGET_SECONDS',5), \
             patch.object(gate,'CONCURRENCY',1), \
             patch.object(gate,'check_stable_node',side_effect=verify):
            results=gate.check_all(nodes)
        self.assertEqual(sum(n['success'] is True for n in results),1)
        self.assertEqual(results[0]['verification_passes'],2)
        self.assertTrue(all(n['success'] is False for n in results[1:]))
        self.assertTrue(all(n.get('exit') is None for n in results[1:]))
        self.assertEqual([n['host'] for n in results],[n['host'] for n in nodes])

    def test_statistics_count_actual_attempts_and_report_budget_skips(self):
        passed=dict(node('vpn100.opengw.net'),check_attempted=True)
        partial=dict(node('vpn200.opengw.net'),check_attempted=True,success=False,verification_passes=1)
        untouched=dict(node('vpn300.opengw.net'),check_attempted=False,success=False,verification_passes=0)
        stats=gate.build_outputs([passed,partial,untouched],3,3,'fixture')['stats']
        self.assertIn('candidates',stats)
        self.assertEqual(stats['candidates'],3)
        self.assertEqual(stats['checked'],2)
        self.assertEqual(stats['success'],1)
        self.assertEqual(stats['failed'],1)
        self.assertEqual(stats['budget_skipped'],1)
        self.assertEqual(stats['checked'],stats['success']+stats['failed'])

    def test_statistics_support_legacy_results_without_attempt_flag(self):
        stats=gate.build_outputs([node(),dict(node('vpn200.opengw.net'),success=False)],2,2,'fixture')['stats']
        self.assertEqual(stats['checked'],2)
        self.assertEqual(stats.get('budget_skipped'),0)

    def test_unattempted_historical_success_cannot_inflate_current_statistics(self):
        data=gate.build_outputs([dict(node(),check_attempted=False)],1,1,'fixture')
        self.assertEqual(data['stats']['checked'],0)
        self.assertEqual(data['stats']['success'],0)
        self.assertEqual(data['stats']['failed'],0)
        self.assertEqual(data['available'],[])

if __name__=='__main__': unittest.main(verbosity=2)
