import unittest
import threading
import inspect
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch

import end_to_end
from end_to_end import HTTPS_CASES, STABILITY_CASES, check_https_node, check_entry_routes


class HttpsVerificationTests(unittest.TestCase):
    def node(self):
        return {'host':'vpn100.opengw.net','port':443,'country_code':'JP',
                'residential':'residential','success':True,'status':'success','latency_ms':100}

    def test_checker_success_is_rejected_when_real_tls_fails(self):
        session=Mock()
        response=Mock(status_code=504)
        response.json.return_value={'message':'TLS EOF'}
        session.get.return_value=response
        result=check_https_node(self.node(),session,'http://127.0.0.1:19090')
        self.assertFalse(result['success'])
        self.assertEqual(result['status'],'failed')
        self.assertIn('HTTPS',result['error'])

    def test_both_https_destinations_must_succeed(self):
        session=Mock()
        first=Mock(status_code=200)
        first.json.return_value={'delay':300}
        first_state=Mock(status_code=200)
        first_state.json.return_value={'extra':{HTTPS_CASES[0][0]:{'alive':True}}}
        second=Mock(status_code=504)
        second.json.return_value={'message':'TLS EOF'}
        session.get.side_effect=[first,first_state,second]
        self.assertFalse(check_https_node(self.node(),session,'http://127.0.0.1:19090')['success'])

    def test_validated_https_latency_and_expected_status_are_recorded(self):
        session=Mock()
        response=Mock(status_code=200)
        response.json.return_value={'delay':450,'extra':{url:{'alive':True} for url,expected in HTTPS_CASES+STABILITY_CASES}}
        session.get.return_value=response
        result=check_https_node(self.node(),session,'http://127.0.0.1:19090')
        self.assertTrue(result['success'])
        self.assertEqual(result['https_checks'],2)
        self.assertEqual(result['stability_tls_checks'],2)
        self.assertEqual(result['https_latency_ms'],450)
        for call in session.get.call_args_list:
            if 'params' in call.kwargs:
                self.assertTrue(call.kwargs['params']['url'].startswith('https://'))
                self.assertIn(call.kwargs['params']['expected'],['200','204','301'])

    def test_positive_delay_cannot_hide_wrong_http_status(self):
        session=Mock()
        response=Mock(status_code=200)
        response.json.return_value={'delay':450,'extra':{url:{'alive':False} for url,expected in HTTPS_CASES}}
        session.get.return_value=response
        self.assertFalse(check_https_node(self.node(),session,'http://127.0.0.1:19090')['success'])

    def test_malformed_delay_does_not_mark_node_healthy(self):
        for delay in [None,True,'300',-1]:
            with self.subTest(delay=delay):
                session=Mock()
                session.get.return_value.status_code=200
                session.get.return_value.json.return_value={'delay':delay}
                self.assertFalse(check_https_node(self.node(),session,'http://127.0.0.1:19090')['success'])

    def test_route_alias_is_used_for_actual_https_checks(self):
        session=Mock()
        session.get.return_value.status_code=200
        session.get.return_value.json.return_value={'delay':300,'extra':{url:{'alive':True} for url,_ in HTTPS_CASES+STABILITY_CASES}}
        check_https_node(self.node(),session,'http://127.0.0.1:19090',proxy_name='route@172.64.155.1')
        self.assertTrue(all('/route%40172.64.155.1' in call.args[0] for call in session.get.call_args_list))

    def test_failed_first_entry_retries_second_and_records_verified_route(self):
        failed=dict(self.node(),success=False,error='timeout')
        passed=dict(self.node(),https_checks=2,https_latency_ms=300)
        with patch('end_to_end.check_https_node',side_effect=[failed,passed]) as check:
            result=check_entry_routes(self.node(),Mock(),'http://localhost', ['172.64.155.1','172.64.144.1'])
        self.assertTrue(result['success'])
        self.assertEqual(result['entry_address'],'172.64.144.1')
        self.assertEqual(check.call_count,2)

    def test_successful_first_entry_is_preserved_and_stops_retry(self):
        with patch('end_to_end.check_https_node',return_value=self.node()) as check:
            result=check_entry_routes(self.node(),Mock(),'http://localhost', ['172.64.155.1','172.64.144.1'])
        self.assertEqual(result['entry_address'],'172.64.155.1')
        self.assertEqual(check.call_count,1)

    def test_all_failed_routes_cannot_publish_stale_entry(self):
        source=dict(self.node(),entry_address='stale')
        with patch('end_to_end.check_https_node',return_value=dict(source,success=False,error='timeout')):
            result=check_entry_routes(source,Mock(),'http://localhost',['172.64.155.1'])
        self.assertFalse(result['success'])
        self.assertNotIn('entry_address',result)

    def test_two_successful_websites_cannot_hide_repeated_tls_failure(self):
        session=Mock()
        valid=Mock(status_code=200)
        valid.json.return_value={'delay':300,'extra':{url:{'alive':True} for url,_ in HTTPS_CASES}}
        failed=Mock(status_code=503)
        session.get.side_effect=[valid,valid,valid,valid,failed]
        self.assertFalse(check_https_node(self.node(),session,'http://localhost')['success'])

    def test_expired_budget_never_starts_http_or_preserves_old_verification(self):
        self.assertIn('deadline',inspect.signature(check_https_node).parameters)
        session=Mock()
        source=dict(self.node(),https_checks=2,stability_tls_checks=2,
                    https_latency_ms=100,entry_address='old')
        with patch('end_to_end.time.monotonic',return_value=5):
            result=check_https_node(source,session,'http://localhost',deadline=5)
        self.assertFalse(result['success'])
        self.assertIn('budget',result['error'])
        session.get.assert_not_called()
        for field in ['https_checks','stability_tls_checks','https_latency_ms','entry_address']:
            self.assertNotIn(field,result)

    def test_budget_after_two_websites_cannot_publish_partial_verification(self):
        self.assertIn('deadline',inspect.signature(check_https_node).parameters)
        clock=[0.0]
        session=Mock()
        valid=Mock(status_code=200)
        valid.json.return_value={'delay':100,'extra':{url:{'alive':True} for url,_ in HTTPS_CASES+STABILITY_CASES}}
        calls=[]
        def request(*args,**kwargs):
            calls.append(kwargs)
            if len(calls)==4:
                clock[0]=5.0
            return valid
        session.get.side_effect=request
        with patch('end_to_end.time.monotonic',side_effect=lambda:clock[0]):
            result=check_https_node(self.node(),session,'http://localhost',deadline=5)
        self.assertFalse(result['success'])
        self.assertEqual(len(calls),4)
        self.assertNotIn('https_checks',result)

    def test_http_timeouts_shrink_to_remaining_stage_budget(self):
        self.assertIn('deadline',inspect.signature(check_https_node).parameters)
        session=Mock()
        session.get.return_value.status_code=503
        with patch('end_to_end.time.monotonic',return_value=4):
            check_https_node(self.node(),session,'http://localhost',deadline=5)
        call=session.get.call_args
        self.assertLessEqual(call.kwargs['params']['timeout'],1000)
        timeout=call.kwargs['timeout']
        self.assertLessEqual(sum(timeout) if isinstance(timeout,tuple) else timeout,1)

    def test_expired_budget_never_starts_second_entry(self):
        self.assertIn('deadline',inspect.signature(check_entry_routes).parameters)
        clock=[0.0]
        def fail(*args,**kwargs):
            clock[0]=5.0
            return dict(self.node(),success=False,error='first entry failed')
        with patch('end_to_end.time.monotonic',side_effect=lambda:clock[0]), \
             patch('end_to_end.check_https_node',side_effect=fail) as check:
            result=check_entry_routes(self.node(),Mock(),'http://localhost',['entry1','entry2'],deadline=5)
        self.assertFalse(result['success'])
        self.assertEqual(check.call_count,1)
        self.assertIn('budget',result['error'])

    def test_stage_never_queues_more_than_workers_and_fails_unstarted_nodes(self):
        bounded=getattr(end_to_end,'check_candidates',None)
        self.assertTrue(callable(bounded),'Stage needs bounded candidate scheduling')
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
        nodes=[dict(self.node(),host=f'vpn{i}.opengw.net') for i in range(7)]
        def verify(node):
            release.wait(2)
            return dict(node,success=False,status='failed',error='budget exhausted')
        outputs=[]
        with patch('end_to_end.time.monotonic',side_effect=lambda:clock[0]), \
             patch('end_to_end.ThreadPoolExecutor',RecordingPool):
            thread=threading.Thread(target=lambda:outputs.extend(bounded(nodes,verify,2,deadline=5)))
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

    def test_unlimited_stage_still_checks_every_candidate(self):
        bounded=getattr(end_to_end,'check_candidates',None)
        self.assertTrue(callable(bounded),'Stage needs bounded candidate scheduling')
        nodes=[dict(self.node(),host=f'vpn{i}.opengw.net') for i in range(6)]
        results=bounded(nodes,lambda node:dict(node,https_checks=2),workers=2)
        self.assertEqual([node['host'] for node in results],[node['host'] for node in nodes])
        self.assertTrue(all(node['success'] for node in results))

    def test_finished_verification_survives_budget_while_unstarted_nodes_fail(self):
        clock=[0.0]
        nodes=[dict(self.node(),host=f'vpn{i}.opengw.net') for i in range(3)]
        def verify(node):
            # A fully checked result completed before the scheduler observes expiry.
            clock[0]=5.0
            return dict(node,https_checks=2,stability_tls_checks=2,https_latency_ms=100)
        with patch('end_to_end.time.monotonic',side_effect=lambda:clock[0]):
            results=end_to_end.check_candidates(nodes,verify,workers=1,deadline=5)
        self.assertTrue(results[0]['success'])
        self.assertEqual(results[0]['stability_tls_checks'],2)
        self.assertTrue(all(not n['success'] for n in results[1:]))
        self.assertEqual([n['host'] for n in results],[n['host'] for n in nodes])

    def test_remaining_budget_bounds_real_loopback_http_wait(self):
        requested=threading.Event()
        release=threading.Event()
        class SlowController(BaseHTTPRequestHandler):
            def do_GET(self):
                requested.set()
                release.wait(2)
                self.send_response(503)
                self.end_headers()
            def log_message(self,*args):
                pass
        server=ThreadingHTTPServer(('127.0.0.1',0),SlowController)
        thread=threading.Thread(target=lambda:server.serve_forever(poll_interval=0.01),daemon=True)
        thread.start()
        try:
            with end_to_end.requests.Session() as session:
                session.trust_env=False
                started=time.monotonic()
                result=check_https_node(self.node(),session,
                    f'http://127.0.0.1:{server.server_port}',deadline=started+0.15)
                elapsed=time.monotonic()-started
            self.assertTrue(requested.is_set())
            self.assertFalse(result['success'])
            self.assertLess(elapsed,0.75,'Controller wait exceeded the remaining stage budget')
        finally:
            release.set()
            server.shutdown()
            server.server_close()
            thread.join(2)


if __name__=='__main__':
    unittest.main()
