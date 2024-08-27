import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError

from Stealthwatch import Stealthwatch, cisco_stealthwatch_query_flows_initialize_command, \
    cisco_stealthwatch_query_flows_status_command, cisco_stealthwatch_query_flows_results_command, \
    cisco_stealthwatch_get_tag_command, cisco_stealthwatch_get_tag_hourly_traffic_report_command, \
    cisco_stealthwatch_get_top_alarming_tags_command, cisco_stealthwatch_list_security_events_initialize_command, \
    cisco_stealthwatch_list_security_events_status_command, cisco_stealthwatch_list_security_events_results_command, \
    utcfromtimestamp, times_handler, remove_empty_elements

OUTPUT_PREFIX = 'CiscoStealthwatch.FlowStatus'
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'


class TestStealthwatch(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        sw = Stealthwatch()

        result = sw.http_request('GET', '/test_url')

        self.assertEqual(result, {"key": "value"})
        mock_request.assert_called_once_with(
            method='GET',
            url='http://example.com/test_url',
            verify=False
        )

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=500, content=b'Error')

        sw = Stealthwatch()

        with self.assertRaises(HTTPError):
            sw.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'username': 'admin',
            'password': 'pw',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        sw = Stealthwatch()

        self.assertEqual(sw.url, 'http://example.com')
        self.assertTrue(sw.insecure)
        self.assertEqual(sw.proxy, 'http://proxy.example.com')
        self.assertIsInstance(sw.session, requests.Session)

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('Stealthwatch.times_handler')
    @patch('Stealthwatch.remove_empty_elements')
    @patch('Stealthwatch.dict_safe_get')
    def test_cisco_stealthwatch_query_flows_initialize_command_success(self, mock_dict_safe_get,
                                                                       mock_remove_empty_elements, mock_times_handler,
                                                                       mock_orenctl_results, mock_orenctl_get_arg,
                                                                       mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'start_time': '2024-08-01T00:00:00Z',
            'end_time': '2024-08-02T00:00:00Z',
            'time_range': None,
            'limit': 100,
            'ip_addresses': ['192.168.1.1']
        }[arg]
        mock_times_handler.return_value = ('2024-08-01T00:00:00Z', '2024-08-02T00:00:00Z')
        mock_remove_empty_elements.return_value = {
            "startDateTime": '2024-08-01T00:00:00Z',
            "endDateTime": '2024-08-02T00:00:00Z',
            "recordLimit": 100,
            "subject": {
                "ipAddresses": {
                    "includes": ['192.168.1.1']
                }
            }
        }
        mock_response = {
            'data': {'query': 'some_query'}
        }
        mock_stealthwatch_instance.initialize_flow_search.return_value = mock_response
        mock_dict_safe_get.return_value = 'some_query'

        with patch('orenctl.error') as mock_orenctl_error:
            cisco_stealthwatch_query_flows_initialize_command()

        expected_results = {
            "outputs_prefix": 'CiscoStealthwatch.FlowStatus',
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": 'some_query'
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.initialize_flow_search.assert_called_once_with('tenant_123', {
            "startDateTime": '2024-08-01T00:00:00Z',
            "endDateTime": '2024-08-02T00:00:00Z',
            "recordLimit": 100,
            "subject": {
                "ipAddresses": {
                    "includes": ['192.168.1.1']
                }
            }
        })

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('Stealthwatch.dict_safe_get')
    def test_cisco_stealthwatch_query_flows_status_command_success(self, mock_dict_safe_get, mock_orenctl_results,
                                                                   mock_orenctl_get_arg, mock_stealthwatch):
        # Mock the function calls and return values
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'search_id': 'search_456'
        }[arg]
        mock_response = {
            'data': {'query': {'status': 'completed'}}
        }
        mock_stealthwatch_instance.check_flow_search_progress.return_value = mock_response
        mock_dict_safe_get.return_value = {'status': 'completed'}

        cisco_stealthwatch_query_flows_status_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": {'status': 'completed', 'id': 'search_456'}
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.check_flow_search_progress.assert_called_once_with('tenant_123', 'search_456')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('Stealthwatch.dict_safe_get')
    def test_cisco_stealthwatch_query_flows_results_command_success(self, mock_dict_safe_get, mock_orenctl_results,
                                                                    mock_orenctl_get_arg, mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'search_id': 'search_456'
        }[arg]
        mock_response = {
            'data': {'flows': [{'id': 'flow_1'}, {'id': 'flow_2'}]}
        }
        mock_stealthwatch_instance.get_flow_search_results.return_value = mock_response
        mock_dict_safe_get.return_value = [{'id': 'flow_1'}, {'id': 'flow_2'}]

        cisco_stealthwatch_query_flows_results_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": [{'id': 'flow_1'}, {'id': 'flow_2'}]
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.get_flow_search_results.assert_called_once_with('tenant_123', 'search_456')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_cisco_stealthwatch_get_tag_command_success(self, mock_orenctl_results, mock_orenctl_get_arg,
                                                        mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'tag_id': 'tag_456'
        }[arg]
        mock_response = {
            'data': {'id': 'tag_456', 'name': 'Important Tag'}
        }
        mock_stealthwatch_instance.get_tag.return_value = mock_response

        cisco_stealthwatch_get_tag_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": {'id': 'tag_456', 'name': 'Important Tag'}
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.get_tag.assert_called_once_with('tenant_123', 'tag_456')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_cisco_stealthwatch_get_tag_hourly_traffic_report_command_success(self, mock_orenctl_results,
                                                                              mock_orenctl_get_arg, mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'tag_id': 'tag_456'
        }[arg]
        mock_response = {
            'data': {
                'data': [
                    {'value': {'id': '1', 'traffic': 100}},
                    {'value': {'id': '2', 'traffic': 200}}
                ]
            }
        }
        mock_stealthwatch_instance.tag_hourly_traffic.return_value = mock_response

        cisco_stealthwatch_get_tag_hourly_traffic_report_command()

        expected_outputs = [
            {'id': '1', 'traffic': 100, 'tag_id': 'tag_456', 'tenant_id': 'tenant_123'},
            {'id': '2', 'traffic': 200, 'tag_id': 'tag_456', 'tenant_id': 'tenant_123'}
        ]
        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": expected_outputs
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.tag_hourly_traffic.assert_called_once_with('tenant_123', 'tag_456')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_cisco_stealthwatch_get_top_alarming_tags_command_success(self, mock_orenctl_results, mock_orenctl_get_arg,
                                                                      mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123'
        }[arg]
        mock_response = {
            'data': {
                'data': [
                    {'id': 'tag_1', 'count': 10},
                    {'id': 'tag_2', 'count': 5}
                ]
            }
        }
        mock_stealthwatch_instance.get_top_alarms.return_value = mock_response

        cisco_stealthwatch_get_top_alarming_tags_command()

        expected_outputs = [
            {'id': 'tag_1', 'count': 10, 'tenant_id': 'tenant_123'},
            {'id': 'tag_2', 'count': 5, 'tenant_id': 'tenant_123'}
        ]
        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": expected_outputs
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.get_top_alarms.assert_called_once_with('tenant_123')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('orenctl.error')
    @patch('Stealthwatch.times_handler')
    @patch('Stealthwatch.dict_safe_get')
    def test_cisco_stealthwatch_list_security_events_initialize_command_success(self, mock_dict_safe_get,
                                                                                mock_times_handler, mock_orenctl_error,
                                                                                mock_orenctl_results,
                                                                                mock_orenctl_get_arg,
                                                                                mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'start_time': '2024-01-01T00:00:00Z',
            'end_time': '2024-01-02T00:00:00Z',
            'time_range': None
        }[arg]
        mock_times_handler.return_value = ('2024-01-01T00:00:00Z', '2024-01-02T00:00:00Z')
        mock_response = {
            'data': {
                'searchJob': {'id': 'job_123', 'status': 'initialized'}
            }
        }
        mock_stealthwatch_instance.initialize_security_events_search.return_value = mock_response
        mock_dict_safe_get.return_value = mock_response['data']['searchJob']

        cisco_stealthwatch_list_security_events_initialize_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": {'id': 'job_123', 'status': 'initialized'}
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.initialize_security_events_search.assert_called_once_with('tenant_123', {
            "timeRange": {
                "from": '2024-01-01T00:00:00Z',
                "to": '2024-01-02T00:00:00Z'
            }
        })

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_cisco_stealthwatch_list_security_events_status_command_success(self, mock_orenctl_results,
                                                                            mock_orenctl_get_arg, mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'search_id': 'search_456'
        }[arg]
        mock_response = {
            'data': {'status': 'completed', 'progress': '100%'}
        }
        mock_stealthwatch_instance.check_security_events_search_progress.return_value = mock_response

        cisco_stealthwatch_list_security_events_status_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": {'status': 'completed', 'progress': '100%', 'id': 'search_456'}
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.check_security_events_search_progress.assert_called_once_with('tenant_123',
                                                                                                 'search_456')

    @patch('Stealthwatch.Stealthwatch')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_cisco_stealthwatch_list_security_events_results_command_success(self, mock_orenctl_results,
                                                                             mock_orenctl_get_arg, mock_stealthwatch):
        mock_stealthwatch_instance = MagicMock()
        mock_stealthwatch.return_value = mock_stealthwatch_instance
        mock_orenctl_get_arg.side_effect = lambda arg: {
            'tenant_id': 'tenant_123',
            'search_id': 'search_456',
            'limit': '5'
        }[arg]
        mock_response = {
            'data': {'results': [{'id': 'event_1'}, {'id': 'event_2'}, {'id': 'event_3'}, {'id': 'event_4'},
                                 {'id': 'event_5'}, {'id': 'event_6'}]}
        }
        mock_stealthwatch_instance.get_security_events_search_results.return_value = mock_response

        cisco_stealthwatch_list_security_events_results_command()

        expected_results = {
            "outputs_prefix": OUTPUT_PREFIX,
            "outputs_key_field": 'id',
            "raw_response": mock_response,
            "outputs": [{'id': 'event_1'}, {'id': 'event_2'}, {'id': 'event_3'}, {'id': 'event_4'}, {'id': 'event_5'}]
        }
        mock_orenctl_results.assert_called_with(expected_results)
        mock_stealthwatch_instance.get_security_events_search_results.assert_called_once_with('tenant_123',
                                                                                              'search_456')

    def test_utcfromtimestamp_valid_timestamp(self):
        timestamp = 1693180745
        result = utcfromtimestamp(timestamp)
        self.assertIsNotNone(result)

    def test_times_handler_with_time_range(self):
        time_range = "2023-08-01T00:00:00Z"
        end_time = "2023-08-02T00:00:00Z"
        start, end = times_handler(time_range=time_range, end_time=end_time)
        self.assertEqual(start, "2023-08-01T00:00:00Z")
        self.assertEqual(end, "2023-08-02T00:00:00Z")

    def test_non_dict_list_input(self):
        self.assertIsNotNone(remove_empty_elements('string'), 'string')
        self.assertIsNotNone(remove_empty_elements(123), 123)
        self.assertIsNotNone(remove_empty_elements(3.14), 3.14)
        self.assertIsNotNone(remove_empty_elements(True), True)

    def test_remove_empty_elements_with_non_empty_dict(self):
        data = {
            'key1': 'value1',
            'key2': None,
            'key3': {},
            'key4': [],
            'key5': {
                'subkey1': 'subvalue1',
                'subkey2': []
            }
        }
        result = remove_empty_elements(data)
        expected = {
            'key1': 'value1',
            'key5': {
                'subkey1': 'subvalue1'
            }
        }
        self.assertEqual(result, expected)

    @patch.object(Stealthwatch, 'prepare_request')
    def test_get_flow_search_results_success(self, mock_prepare_request):
        """Test the `get_flow_search_results` method for a successful API call."""
        mock_response = {'data': {'flows': ['flow1', 'flow2']}}
        mock_prepare_request.return_value = mock_response

        client = Stealthwatch()
        tenant_id = 'tenant123'
        search_id = 'search123'

        result = client.get_flow_search_results(tenant_id, search_id)

        self.assertEqual(result, mock_response)

    @patch.object(Stealthwatch, 'prepare_request')
    def test_check_flow_search_progress_success(self, mock_prepare_request):
        mock_response = {'data': {'status': 'completed'}}
        mock_prepare_request.return_value = mock_response

        client = Stealthwatch()
        tenant_id = 'tenant123'
        search_id = 'search123'

        # Call the method
        result = client.check_flow_search_progress(tenant_id, search_id)

        self.assertEqual(result, mock_response)

    @patch.object(Stealthwatch, 'prepare_request')
    def test_get_tag_success(self, mock_prepare_request):
        mock_response = {'data': {'tag': 'example_tag'}}
        mock_prepare_request.return_value = mock_response

        client = Stealthwatch()
        tenant_id = 'tenant123'
        tag_id = 'tag123'

        result = client.get_tag(tenant_id, tag_id)

        self.assertEqual(result, mock_response)

    @patch.object(Stealthwatch, 'prepare_request')
    def test_tag_hourly_traffic_success(self, mock_prepare_request):
        mock_response = {'data': {'hourlyTraffic': 'example_data'}}
        mock_prepare_request.return_value = mock_response

        client = Stealthwatch()
        tenant_id = 'tenant123'
        tag_id = 'tag123'

        result = client.tag_hourly_traffic(tenant_id, tag_id)

        self.assertEqual(result, mock_response)

    @patch.object(Stealthwatch, 'prepare_request')
    def test_get_top_alarms_success(self, mock_prepare_request):
        mock_response = {'data': {'topAlarms': 'example_data'}}
        mock_prepare_request.return_value = mock_response

        client = Stealthwatch()
        tenant_id = 'tenant123'

        result = client.get_top_alarms(tenant_id)

        self.assertEqual(result, mock_response)