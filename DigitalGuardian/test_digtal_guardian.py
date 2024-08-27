import json
import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError

import orenctl
from DigitalGuardian import DigitalGuardian, add_entry_to_watchlist, check_watchlist_entry, rm_entry_from_watchlist, \
    add_entry_to_component_list, check_componentlist_entry, rm_entry_from_componentlist

CLIENT_HEADERS = {'Authorization': ''}


class TestDigitalGuardian(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        digi = DigitalGuardian()

        result = digi.http_request('GET', '/test_url')

        self.assertEqual(result, {"key": "value"})
        mock_request.assert_called_once_with(
            method='GET',
            url='/test_url',
            verify=False
        )

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=500, content=b'Error')

        digi = DigitalGuardian()

        with self.assertRaises(HTTPError):
            digi.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'auth_sever': 'http://example.com',
            'auth_url': 'http://example.com',
            'arc_url': 'http://example.com',
            'client_id': '1233',
            'client_secret': 'secret',
            'export_profile': 'export_profile',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        digi = DigitalGuardian()

        self.assertEqual(digi.client_id, '1233')
        self.assertTrue(digi.insecure)
        self.assertEqual(digi.proxy, 'http://proxy.example.com')
        self.assertIsInstance(digi.session, requests.Session)

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.post')
    def test_add_entry_to_watchlist_success(self, mock_requests_post, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'watchlist_name': 'test_watchlist',
            'watchlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_watchlist_id.return_value = '1234'

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'OK'
        mock_requests_post.return_value = mock_response

        expected_results = 'added watchlist entry (test_entry) to watchlist name (test_watchlist)'

        add_entry_to_watchlist()

        mock_client.get_watchlist_id.assert_called_once_with('test_watchlist')

        mock_results.assert_called_once_with(expected_results)

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_check_watchlist_entry_found(self, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'watchlist_name': 'test_watchlist',
            'watchlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_watchlist_entry_id.return_value = 'entry_id'

        expected_results = {
            "readable_output": 'Watchlist found',
            "outputs": {'DigitalGuardian.Watchlist.Found': True},
            "raw_response": 'Watchlist found'
        }

        check_watchlist_entry()

        # Assertions
        mock_client.get_watchlist_entry_id.assert_called_once_with('test_watchlist', 'test_entry')
        mock_results.assert_called_once_with(expected_results)

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_check_watchlist_entry_not_found(self, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'watchlist_name': 'test_watchlist',
            'watchlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_watchlist_entry_id.return_value = None

        check_watchlist_entry()

        mock_client.get_watchlist_entry_id.assert_called_once_with('test_watchlist', 'test_entry')

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_check_watchlist_entry_missing_args(self, mock_results, mock_getArg, MockDigitalGuardian):
        MockDigitalGuardian.return_value = MagicMock()
        mock_getArg.side_effect = lambda x: None

        check_watchlist_entry()

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.delete')
    def test_rm_entry_from_watchlist_success(self, mock_delete, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'watchlist_name': 'test_watchlist',
            'watchlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_watchlist_id.return_value = 'watchlist_id'
        mock_client.get_watchlist_entry_id.return_value = 'entry_id'
        mock_delete.return_value = MagicMock(status_code=200)

        expected_results = 'removed watchlist entry (test_entry) from watchlist name (test_watchlist)'

        rm_entry_from_watchlist()

        mock_client.get_watchlist_id.assert_called_once_with('test_watchlist')
        mock_client.get_watchlist_entry_id.assert_called_once_with('test_watchlist', 'test_entry')
        mock_results.assert_called_once_with(expected_results)

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.delete')
    def test_rm_entry_from_watchlist_failure(self, mock_delete, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'watchlist_name': 'test_watchlist',
            'watchlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_watchlist_id.return_value = 'watchlist_id'
        mock_client.get_watchlist_entry_id.return_value = 'entry_id'
        mock_delete.return_value = MagicMock(status_code=400, text='Bad Request')  # Simulate a failed delete request

        rm_entry_from_watchlist()

        mock_client.get_watchlist_id.assert_called_once_with('test_watchlist')
        mock_client.get_watchlist_entry_id.assert_called_once_with('test_watchlist', 'test_entry')

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.put')
    def test_add_entry_to_component_list_success(self, mock_put, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'componentlist_name': 'test_component_list',
            'componentlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_list_id.return_value = 'list_id'
        mock_put.return_value = MagicMock(status_code=200)

        expected_results = 'added componentlist entry (test_entry) to componentlist name (test_component_list)'

        add_entry_to_component_list()

        # Assertions
        mock_client.get_list_id.assert_called_once_with('test_component_list', 'component_list')

        mock_results.assert_called_once_with(expected_results)

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.put')
    def test_add_entry_to_component_list_failure(self, mock_put, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'componentlist_name': 'test_component_list',
            'componentlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_list_id.return_value = 'list_id'
        mock_put.return_value = MagicMock(status_code=400, text='Bad Request')  # Simulate a failed put request

        expected_results = (
            'Failed to add componentlist entry(test_entry) to componentlist name (test_component_list). '
            'The response failed with status code 400. The response was: Bad Request'
        )

        add_entry_to_component_list()

        mock_client.get_list_id.assert_called_once_with('test_component_list', 'component_list')

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.get')
    def test_check_componentlist_entry_success(self, mock_get, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'componentlist_name': 'test_component_list',
            'componentlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_list_id.return_value = 'list_id'
        mock_get.return_value = MagicMock(
            status_code=200,
            text=json.dumps([{'content_value': 'test_entry'}])
        )

        with patch('DigitalGuardian.check_componentlist') as mock_check_componentlist:
            check_componentlist_entry()

            mock_client.get_list_id.assert_called_once_with('test_component_list', 'component_list')
            mock_check_componentlist.assert_called_once_with('test_entry')

    @patch('DigitalGuardian.DigitalGuardian')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('requests.post')
    def test_rm_entry_from_componentlist_success(self, mock_post, mock_results, mock_getArg, MockDigitalGuardian):
        mock_client = MagicMock()
        MockDigitalGuardian.return_value = mock_client
        mock_getArg.side_effect = lambda x: {
            'componentlist_name': 'test_component_list',
            'componentlist_entry': 'test_entry'
        }.get(x, None)

        mock_client.get_list_id.return_value = 'list_id'
        mock_post.return_value = MagicMock(
            status_code=200,
            text='Success'
        )

        rm_entry_from_componentlist()

        mock_client.get_list_id.assert_called_once_with('test_component_list', 'component_list')
        mock_results.assert_called_once_with(
            'removed componentlist entry (test_entry) from componentlist name (test_component_list)')

    @patch('requests.get')
    @patch('orenctl.results')
    def test_get_list_id_success(self, mock_results, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        orenctl.set_params({
            "auth_url": "http:",
            "arc_url": "http:",
        })
        mock_response.text = json.dumps([
            {'name': 'test_list', 'id': '12345'},
            {'name': 'other_list', 'id': '67890'}
        ])
        mock_get.return_value = mock_response

        client = DigitalGuardian()
        client.arc_url = 'http://example.com'
        client.insecure = True

        list_id = client.get_list_id('test_list', 'component_list')

        self.assertEqual(list_id, '12345')
        mock_results.assert_not_called()

    @patch('requests.get')
    @patch('orenctl.results')
    def test_get_watchlist_entry_id_success(self, mock_results, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        orenctl.set_params({
            "auth_url": "http:",
            "arc_url": "http:",
        })
        mock_response.text = json.dumps([
            {'value_name': 'test_entry', 'value_id': 'entry123'},
            {'value_name': 'another_entry', 'value_id': 'entry456'}
        ])
        mock_get.return_value = mock_response

        client = DigitalGuardian()
        client.arc_url = 'http://example.com'
        client.insecure = True

        entry_id = client.get_watchlist_entry_id('test_watchlist', 'test_entry')

        self.assertEqual(entry_id, 'entry123')
