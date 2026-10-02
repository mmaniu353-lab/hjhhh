import unittest
from unittest.mock import Mock

from end_to_end import HTTPS_CASES, check_https_node


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
        second=Mock(status_code=504)
        second.json.return_value={'message':'TLS EOF'}
        session.get.side_effect=[first,second]
        self.assertFalse(check_https_node(self.node(),session,'http://127.0.0.1:19090')['success'])

    def test_validated_https_latency_and_expected_status_are_recorded(self):
        session=Mock()
        response=Mock(status_code=200)
        response.json.return_value={'delay':450,'extra':{url:{'alive':True} for url,expected in HTTPS_CASES}}
        session.get.return_value=response
        result=check_https_node(self.node(),session,'http://127.0.0.1:19090')
        self.assertTrue(result['success'])
        self.assertEqual(result['https_checks'],2)
        self.assertEqual(result['https_latency_ms'],450)
        for call in session.get.call_args_list:
            if 'params' in call.kwargs:
                self.assertTrue(call.kwargs['params']['url'].startswith('https://'))
                self.assertIn(call.kwargs['params']['expected'],['200','204'])

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


if __name__=='__main__':
    unittest.main()
