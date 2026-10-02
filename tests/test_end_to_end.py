import unittest
from unittest.mock import Mock, patch

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


if __name__=='__main__':
    unittest.main()
