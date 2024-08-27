import os
import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError

from FireEyeEX import FireEyeEX, arg_to_boolean, get_alerts, get_alert_details, release_quarantined_emails, get_reports, \
    list_allowedlist, update_allowedlist, list_blockedlist, update_blockedlist, delete_blockedlist, arg_get_alerts, \
    get_data_from_rq_param, write_data_to_file, check_alert_id

INTEGRATION_CONTEXT_NAME = 'FireEyeEX'


class TestFireeyeEX(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://example.com',
            'username': 'user',
            'password': 'pass',
            'insecure': 'false',
            'proxy': 'false',
            'max_fetch': '50',
            'first_fetch': '3 days',
            'info_level': 'concise'
        }.get(key, None)

        mock_request.return_value = MagicMock(status_code=200, json=lambda: {'key': 'value'})

        fe = FireEyeEX()

        response = fe.http_request('GET', '/test_url')

        self.assertEqual(response, {'key': 'value'})

    @patch('orenctl.getParam')
    @patch('orenctl.results')
    @patch('orenctl.error')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_error, mock_results, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://example.com',
            'username': 'user',
            'password': 'pass',
            'insecure': 'false',
            'proxy': 'false',
            'max_fetch': '50',
            'first_fetch': '3 days',
            'info_level': 'concise'
        }.get(key, None)

        mock_request.return_value = MagicMock(status_code=500, content=b'Error')

        fe = FireEyeEX()

        with self.assertRaises(HTTPError):
            fe.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    @patch('FireEyeEX.arg_to_boolean')
    def test_init(self, mock_arg_to_boolean, mock_get_param):
        mock_get_param.side_effect = lambda param: {
            "url": "http://example.com",
            "username": "testuser",
            "password": "testpassword",
            "insecure": "true",
            "proxy": "false",
            "max_fetch": "100",
            "first_fetch": "7 days",
            "info_level": "verbose"
        }.get(param, None)

        mock_arg_to_boolean.side_effect = lambda x: x == "true"

        fe = FireEyeEX()

        self.assertEqual(fe.url, 'http://example.com/wsapis/v2.0.0/')
        self.assertTrue(not fe.insecure)
        self.assertIsInstance(fe.session, requests.Session)

    def test_boolean_true(self):
        self.assertTrue(arg_to_boolean(True))

    def test_boolean_false(self):
        self.assertFalse(arg_to_boolean(False))

    def test_string_false(self):
        self.assertFalse(arg_to_boolean('false'))

    def test_string_true(self):
        self.assertTrue(arg_to_boolean('true'))

    def test_invalid_string(self):
        with self.assertRaises(ValueError):
            arg_to_boolean('maybe')

    def test_non_string_non_boolean(self):
        with self.assertRaises(ValueError):
            arg_to_boolean(123)

    def test_empty_string(self):
        with self.assertRaises(ValueError):
            arg_to_boolean('')

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('FireEyeEX.arg_get_alerts')
    @patch('FireEyeEX.get_data_from_rq_param')
    def test_get_alerts(self, mock_get_data_from_rq_param, mock_arg_get_alerts, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client
        mock_client.get_alerts_request.return_value = {
            'alert': [{'uuid': '1', 'message': 'Test alert 1'}, {'uuid': '2', 'message': 'Test alert 2'}]
        }

        mock_getArg.side_effect = lambda key: {
            'info_level': 'detailed',
            'limit': '1'
        }.get(key, None)

        mock_arg_get_alerts.return_value = (
            None, None, None, None, None, None, None, None, None, None, None, None, None, None)
        mock_get_data_from_rq_param.return_value = None

        get_alerts()

        with patch('FireEyeEX.orenctl.results') as mock_results:
            get_alerts()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('FireEyeEX.arg_to_list')
    def test_get_alert_details_success(self, mock_arg_to_list, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client
        mock_client.get_alert_details_request.return_value = {
            'alert': {'uuid': '1', 'message': 'Test alert details'}
        }

        mock_getArg.side_effect = lambda key: {
            'alert_id': ['123', '456'],
            'timeout': '60'
        }.get(key, None)

        mock_arg_to_list.return_value = ['123', '456']

        get_alert_details()

        with patch('FireEyeEX.orenctl.results') as mock_results:
            get_alert_details()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    def test_release_quarantined_emails_success(self, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_response = MagicMock()
        mock_response.text = ''
        mock_response.json.return_value = {}
        mock_client.release_quarantined_emails_request.return_value = mock_response

        mock_getArg.side_effect = lambda key: {
            'queue_ids': '123,456'
        }.get(key, None)

        with patch('FireEyeEX.orenctl.results') as mock_results:
            release_quarantined_emails()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('FireEyeEX.file_result')
    @patch('orenctl.results')
    def test_get_reports_success(self, mock_results, mock_file_result, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_response = b"Mock CSV Data"
        mock_client.get_reports_request.return_value = mock_response

        mock_getArg.side_effect = lambda key: {
            'alert_id': '12345',
            'end_time': '2024-08-01T00:00:00Z',
            'infection_id': '67890',
            'infection_type': 'malware',
            'interface': 'eth0',
            'limit': '10',
            'report_type': 'empsEmailAVReport',
            'start_time': '2024-07-01T00:00:00Z',
            'timeout': '30'
        }.get(key, None)

        mock_file_result.return_value = {'file': 'report_empsEmailAVReport_1234567890.csv'}

        get_reports()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('FireEyeEX.file_result')
    @patch('orenctl.results')
    def test_get_reports_alert_not_found(self, mock_results, mock_file_result, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_client.get_reports_request.side_effect = Exception('WSAPI_REPORT_ALERT_NOT_FOUND')

        mock_getArg.side_effect = lambda key: {
            'alert_id': '12345',
            'end_time': '2024-08-01T00:00:00Z',
            'infection_id': '67890',
            'infection_type': 'malware',
            'interface': 'eth0',
            'limit': '10',
            'report_type': 'empsEmailAVReport',
            'start_time': '2024-07-01T00:00:00Z',
            'timeout': '30'
        }.get(key, None)

        get_reports()

        expected_results = {'readable_output': 'Report empsEmailAVReport was not found with the given arguments.'}
        mock_results.assert_called_once_with(expected_results)

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_list_allowedlist_success(self, mock_results, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_response = [
            {'name': 'allowed_item_1'},
            {'name': 'allowed_item_2'},
            {'name': 'allowed_item_3'}
        ]
        mock_client.list_allowedlist_request.return_value = mock_response

        mock_getArg.side_effect = lambda key: {
            'type': 'malware',
            'limit': '2'
        }.get(key, None)

        list_allowedlist()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_update_allowedlist_success(self, mock_results, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_client.list_allowedlist_request.return_value = [{'name': 'existing_entry'}]

        mock_getArg.side_effect = lambda key: {
            'type': 'malware',
            'entry_value': 'existing_entry',
            'matches': '10'
        }.get(key, None)

        update_allowedlist()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_list_blockedlist_success(self, mock_results, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_client.list_blockedlist_request.return_value = [{'name': 'blocked_item_1'}, {'name': 'blocked_item_2'}]

        mock_getArg.side_effect = lambda key: {
            'type': 'malware',
            'limit': '1'
        }.get(key, None)

        list_blockedlist()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_update_blockedlist_success(self, mock_results, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_client.list_blockedlist_request.return_value = [{'name': 'blocked_item_1'}, {'name': 'blocked_item_2'}]

        mock_getArg.side_effect = lambda key: {
            'type': 'malware',
            'entry_value': 'blocked_item_1',
            'matches': '5'
        }.get(key, None)

        update_blockedlist()

    @patch('FireEyeEX.FireEyeEX')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_delete_blockedlist_success(self, mock_results, mock_getArg, MockFireEyeEX):
        mock_client = MagicMock()
        MockFireEyeEX.return_value = mock_client

        mock_client.list_blockedlist_request.return_value = [{'name': 'blocked_item_1'}, {'name': 'blocked_item_2'}]

        mock_getArg.side_effect = lambda key: {
            'type': 'malware',
            'entry_value': 'blocked_item_1'
        }.get(key, None)

        delete_blockedlist()

    @patch('orenctl.getArg')
    @patch('FireEyeEX.to_fe_datetime_converter')
    def test_arg_get_alerts(self, mock_to_fe_datetime_converter, mock_getArg):
        mock_getArg.side_effect = lambda key: {
            'alert_id': '12345',
            'start_time': '2024-08-27T00:00:00Z',
            'end_time': '2024-08-28T00:00:00Z',
            'duration': '1d',
            'callback_domain': 'example.com',
            'dst_ip': '192.168.1.1',
            'src_ip': '10.0.0.1',
            'file_name': 'malicious.exe',
            'file_type': 'exe',
            'malware_name': 'malware',
            'malware_type': 'ransomware',
            'recipient_email': 'user@example.com',
            'sender_email': 'attacker@example.com',
            'url': 'http://malicious.com'
        }.get(key, '')

        mock_to_fe_datetime_converter.side_effect = lambda x: f'converted_{x}'

        result = arg_get_alerts()
        self.assertIsNotNone(result)

    def test_get_data_from_rq_param(self):
        alert_id = '12345'
        callback_domain = 'example.com'
        dst_ip = '192.168.1.1'
        duration = '1d'
        end_time = '2024-08-28T00:00:00Z'
        file_name = 'malicious.exe'
        file_type = 'exe'
        malware_name = 'malware'
        src_ip = '10.0.0.1'
        start_time = '2024-08-27T00:00:00Z'

        request_param = {}

        get_data_from_rq_param(alert_id, callback_domain, dst_ip, duration, end_time, file_name, file_type,
                               malware_name, request_param, src_ip, start_time)

        expected_param = {
            'start_time': '2024-08-27T00:00:00Z',
            'end_time': '2024-08-28T00:00:00Z',
            'duration': '1d',
            'alert_id': '12345',
            'callback_domain': 'example.com',
            'dst_ip': '192.168.1.1',
            'src_ip': '10.0.0.1',
            'file_name': 'malicious.exe',
            'file_type': 'exe',
            'malware_name': 'malware'
        }

        self.assertEqual(request_param, expected_param)

    def test_write_data_to_file(self):
        investigation_id = 'test_investigation'
        temp = 'tempfile'
        data = b'Test binary data'

        expected_file_name = f"{investigation_id}_{temp}"

        write_data_to_file(investigation_id, temp, data)

        self.assertTrue(os.path.exists(expected_file_name))

        with open(expected_file_name, 'rb') as f:
            file_content = f.read()

        self.assertEqual(file_content, data)
        os.remove(expected_file_name)

    def test_valid_alert_id_only(self):
        try:
            check_alert_id('12345', 'Invalid input', '', '')
        except ValueError:
            self.fail("check_alert_id() raised ValueError unexpectedly!")

    def test_valid_infection_details_only(self):
        try:
            check_alert_id('', 'Invalid input', '67890', 'virus')
        except ValueError:
            self.fail("check_alert_id() raised ValueError unexpectedly!")

    def test_invalid_both_alert_id_and_infection(self):
        with self.assertRaises(ValueError):
            check_alert_id('12345', 'Invalid input', '67890', 'virus')

    def test_invalid_neither_alert_id_nor_infection(self):
        with self.assertRaises(ValueError):
            check_alert_id('', 'Invalid input', '', '')