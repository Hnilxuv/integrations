import unittest
from collections import namedtuple
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError
import orenctl

from CiscoAMP import CiscoAMP, arg_to_list, arg_to_number, computer_list_command, check_is_get_request, \
    computer_trajectory_list_command, computer_user_activity_list_command, computer_vulnerabilities_list_command, \
    computer_isolation_create_polling_command, computer_isolation_create_command, endpoint_command, \
    get_pagination_parameters, pagination_range, remove_empty_elements, dict_safe_get, combine_response_results, \
    delete_keys_from_dict, get_context_output, validate_query, add_item_to_all_dictionaries, \
    extract_pagination_from_response, check_endpoint_ids, computer_isolation_polling_command, get_hash_type, \
    file_command

Pagination = namedtuple(
    "Pagination",
    (
        "page",
        "page_size",
        "limit",
        "offset",
        "number_of_requests",
        "offset_multiplier",
        "is_automatic",
        "is_manual",
    ),
    defaults=(None, None, None, None, None, None, None, None),
)


class CiscoAMPTest(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.test_dict = {
            'a': {
                'b': [
                    {'c': 'value1'},
                    {'c': 'value2'}
                ],
                'd': 'value3'
            },
            'e': None
        }
        self.raw_response_list_auto = [
            {
                "metadata": {
                    "results": {
                        "current_item_count": 10
                    }
                },
                "data": [
                    {"id": 1, "value": "A"}
                ]
            },
            {
                "metadata": {
                    "results": {
                        "current_item_count": 5
                    }
                },
                "data": [
                    {"id": 2, "value": "B"}
                ]
            }
        ]

        self.raw_response_list_non_auto = [
            {
                "metadata": {
                    "results": {
                        "current_item_count": 10
                    }
                },
                "data": [
                    {"id": 1, "value": "A"}
                ]
            }
        ]

        self.empty_response_list = []
        self.sample_dict = {
            "a": 1,
            "b": {
                "c": 2,
                "d": {
                    "e": 3,
                    "f": 4
                }
            },
            "g": [
                {"h": 5, "i": 6},
                {"j": 7, "k": 8}
            ]
        }
        self.response = {
            "data": [
                {
                    "id": 1,
                    "name": "Item1",
                    "details": {
                        "description": "A description",
                        "extra": "Extra info"
                    }
                },
                {
                    "id": 2,
                    "name": "Item2",
                    "details": {
                        "description": "Another description",
                        "extra": "More info"
                    }
                }
            ]
        }
        self.endpoint_hostnames = ['hostname1', 'hostname2']
        self.endpoint_ids = ['id1', 'id2']
        self.endpoint_ips = ['192.168.1.1', '192.168.1.2']
        self.computer_isolation_command = MagicMock()
        self.computer_isolation_get_command = MagicMock()
        self.result_isolation_status = {"isolated", "pending_start"}

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        cisco = CiscoAMP()

        result = cisco.http_request('GET', '/test_url')

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

        cisco = CiscoAMP()

        with self.assertRaises(HTTPError):
            cisco.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'server_url': 'http://example.com',
            'api_key': 'key',
            'client_id': '1233',
            'reliability': 'integrationReliability',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        cisco = CiscoAMP()

        self.assertEqual(cisco.client_id, '1233')
        self.assertTrue(cisco.insecure)
        self.assertEqual(cisco.proxy, 'http://proxy.example.com')
        self.assertIsInstance(cisco.session, requests.Session)

    def test_arg_is_none(self):
        self.assertEqual(arg_to_list(None), [])

    def test_arg_is_empty_string(self):
        self.assertEqual(arg_to_list(''), [])

    def test_arg_is_list(self):
        self.assertEqual(arg_to_list(['item1', 'item2']), ['item1', 'item2'])

    def test_arg_is_comma_separated_string(self):
        self.assertEqual(arg_to_list('item1,item2'), ['item1', 'item2'])

    def test_arg_is_json_string(self):
        self.assertEqual(arg_to_list('["item1", "item2"]'), ['item1', 'item2'])

    def test_arg_is_non_comma_separated_string(self):
        self.assertEqual(arg_to_list('item1;item2', separator=';'), ['item1', 'item2'])

    def test_arg_is_json_string_with_invalid_json(self):
        self.assertEqual(arg_to_list('["item1", "item2'), ['["item1"', '"item2'])

    def test_arg_is_single_string(self):
        self.assertEqual(arg_to_list('item1'), ['item1'])

    def test_arg_is_non_string_or_list(self):
        self.assertEqual(arg_to_list(123), [123])

    def test_arg_with_transform(self):
        self.assertEqual(arg_to_list('1,2,3', transform=int), [1, 2, 3])

    def test_arg_is_list_with_transform(self):
        self.assertEqual(arg_to_list(['1', '2', '3'], transform=int), [1, 2, 3])

    def test_arg_is_empty_json_list(self):
        self.assertEqual(arg_to_list('[]'), [])

    def test_valid_integer_string(self):
        self.assertEqual(arg_to_number('123', 'test_arg'), 123)

    def test_missing_argument_required(self):
        with self.assertRaises(ValueError):
            arg_to_number(None, 'test_arg', required=True)

    def test_missing_argument_not_required(self):
        self.assertIsNone(arg_to_number(None, 'test_arg'))

    def test_invalid_type(self):
        with self.assertRaises(ValueError):
            arg_to_number(['list'], 'test_arg')

    @patch('CiscoAMP.CiscoAMP')
    @patch('orenctl.getArg')
    @patch('CiscoAMP.check_is_get_request')
    @patch('CiscoAMP.get_context_output')
    @patch('orenctl.results')
    def test_computer_list_command_success(self, mock_results, mock_get_context_output, mock_check_is_get_request,
                                           mock_get_arg, mock_cisco_amp):
        mock_client = MagicMock()
        mock_cisco_amp.return_value = mock_client

        mock_get_arg.side_effect = lambda arg: {
            "page": "1",
            "page_size": "10",
            "limit": "50",
            "connector_guid": "guid123",
            "hostnames": "hostname1,hostname2",
            "internal_ip": "192.168.1.1",
            "external_ip": "8.8.8.8",
            "group_guids": "group1,group2",
            "last_seen_within": "30",
            "last_seen_over": "10"
        }.get(arg, "")

        mock_raw_response = {
            "data": [
                {
                    "connector_guid": "guid123",
                    "internal_ips": ["192.168.1.1"],
                    "hostname": "hostname1",
                    "network_addresses": [{"mac": "00:11:22:33:44:55"}],
                    "operating_system": "Windows",
                    "os_version": "10.0",
                    "active": True
                }
            ],
            "links": []
        }
        mock_check_is_get_request.return_value = mock_raw_response
        mock_get_context_output.return_value = mock_raw_response["data"]

        computer_list_command()

        # Expected results
        expected_results = [{
            "outputs_prefix": "CiscoAMP.Computer",
            "outputs_key_field": "connector_guid",
            "outputs": mock_raw_response["data"][0],
            "raw_response": mock_raw_response,
            "indicator": {
                "id": "guid123",
                "ip_address": "192.168.1.1",
                "hostname": "hostname1",
                "mac_address": "00:11:22:33:44:55",
                "os": "Windows",
                "os_version": "10.0",
                "status": "Online",
                "vendor": "CiscoAMP Response",
            }
        }]

        # Assertions
        mock_cisco_amp.assert_called_once()
        mock_get_arg.assert_called_with("last_seen_over")
        mock_check_is_get_request.assert_called_once()
        mock_get_context_output.assert_called_once_with(mock_raw_response, ["links"])
        mock_results.assert_called_once_with(expected_results)

    @patch('CiscoAMP.get_pagination_parameters')
    @patch('CiscoAMP.pagination_range')
    @patch('CiscoAMP.combine_response_results')
    def test_list_request(self, mock_combine_response_results, mock_pagination_range, mock_get_pagination_parameters):
        mock_client = MagicMock()

        pagination = MagicMock()
        pagination.limit = 10
        pagination.offset = 0

        mock_get_pagination_parameters.return_value = pagination
        mock_pagination_range.return_value = range(1, 3)  # Mocking pagination to simulate multiple pages

        mock_client.computer_list_request.side_effect = [
            {"data": [{"id": 1}, {"id": 2}]},
            {"data": [{"id": 3}]},
            {"data": []}
        ]

        mock_combine_response_results.return_value = {"combined": "data"}

        raw_response = check_is_get_request(
            client=mock_client,
            connector_guid=None,
            external_ip=None,
            group_guids=None,
            hostnames=None,
            internal_ip=None,
            is_get_request=False,
            is_list_request=True,
            last_seen_over=None,
            last_seen_within=None,
            limit=30,
            page=1,
            page_size=10
        )

        expected_response = {"combined": "data"}

        mock_get_pagination_parameters.assert_called_once_with(1, 10, 30)
        mock_pagination_range.assert_called_once_with(pagination)
        mock_client.computer_list_request.assert_called()

        self.assertEqual(raw_response, expected_response)

    @patch('CiscoAMP.CiscoAMP')
    @patch('CiscoAMP.validate_query')
    @patch('CiscoAMP.get_pagination_parameters')
    @patch('CiscoAMP.extract_pagination_from_response')
    def test_computer_trajectory_list_command(self, mock_extract_pagination_from_response,
                                              mock_get_pagination_parameters, mock_validate_query, mock_cisco):
        mock_instance = mock_cisco.return_value  # This is now the mock instance of CiscoAMP

        connector_guid = "connector_guid_123"
        page = 1
        page_size = 10
        limit = 50
        query_string = "some_query_string"

        mock_instance.computer_trajectory_list_request = MagicMock(return_value={
            "data": {
                "events": [
                    {"event_id": "1", "event_type": "type_1", "timestamp": "2024-08-27T00:00:00Z"},
                ],
                "computer": {
                    "connector_guid": "abc123"
                }
            },
            "links": {
                "self": "https://example.com/api/computers/abc123/trajectory"
            }
        })

        mock_validate_query.return_value = True
        pagination = MagicMock()
        pagination.page = page
        pagination.page_size = page_size
        pagination.is_manual = True
        mock_get_pagination_parameters.return_value = pagination

        context_output = {"extracted": "data"}
        mock_extract_pagination_from_response.return_value = context_output

        orenctl.set_input_args({
            "connector_guid": connector_guid,
            "page": page,
            "page_size": page_size,
            "limit": limit,
            "query_string": query_string
        })

        computer_trajectory_list_command()

    @patch('CiscoAMP.CiscoAMP')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('CiscoAMP.combine_response_results')
    @patch('CiscoAMP.get_pagination_parameters')
    @patch('CiscoAMP.pagination_range')
    @patch('CiscoAMP.get_context_output')
    def test_computer_user_activity_list_command(self,
                                                 mock_get_context_output,
                                                 mock_pagination_range,
                                                 mock_get_pagination_parameters,
                                                 mock_combine_response_results,
                                                 mock_results,
                                                 mock_getArg,
                                                 mock_CiscoAMP):
        mock_client = MagicMock()
        mock_CiscoAMP.return_value = mock_client

        mock_getArg.side_effect = lambda key: {
            "username": "test_user",
            "page": 1,
            "page_size": 10,
            "limit": 50
        }.get(key, None)

        mock_pagination = MagicMock()
        mock_pagination.limit = 50
        mock_pagination.offset = 0
        mock_pagination.is_automatic = True
        mock_get_pagination_parameters.return_value = mock_pagination

        mock_pagination_range.return_value = range(1)

        mock_client.computer_user_activity_get_request.return_value = {
            "data": [{"activity": "login", "timestamp": "2024-08-27T00:00:00Z"}]
        }

        mock_combine_response_results.return_value = {
            "data": [{"activity": "login", "timestamp": "2024-08-27T00:00:00Z"}]
        }

        mock_get_context_output.return_value = [
            {"activity": "login", "timestamp": "2024-08-27T00:00:00Z"}
        ]

        computer_user_activity_list_command()

        mock_results.assert_called_once_with({
            "outputs_prefix": "CiscoAMP.ComputerUserActivity",
            "outputs_key_field": "connector_guid",
            "outputs": [{"activity": "login", "timestamp": "2024-08-27T00:00:00Z"}],
            "raw_response": {"data": [{"activity": "login", "timestamp": "2024-08-27T00:00:00Z"}]}
        })

    @patch('CiscoAMP.orenctl')
    @patch('CiscoAMP.CiscoAMP')
    @patch('CiscoAMP.get_pagination_parameters')
    @patch('CiscoAMP.pagination_range')
    @patch('CiscoAMP.combine_response_results')
    @patch('CiscoAMP.get_context_output')
    @patch('CiscoAMP.add_item_to_all_dictionaries')
    def test_computer_vulnerabilities_list_command(self, mock_add_item_to_all_dictionaries, mock_get_context_output,
                                                   mock_combine_response_results, mock_pagination_range,
                                                   mock_get_pagination_parameters, mock_CiscoAMP, mock_orenctl):
        mock_client = MagicMock()
        mock_CiscoAMP.return_value = mock_client

        connector_guid = "connector_guid_123"
        start_time = "2024-08-01T00:00:00Z"
        end_time = "2024-08-27T23:59:59Z"
        page = 1
        page_size = 10
        limit = 50

        mock_orenctl.getArg.side_effect = lambda key: {
            "connector_guid": connector_guid,
            "start_time": start_time,
            "end_time": end_time,
            "page": page,
            "page_size": page_size,
            "limit": limit
        }.get(key, None)

        pagination = MagicMock()
        pagination.page = page
        pagination.page_size = page_size
        pagination.limit = limit
        pagination.is_manual = True
        mock_get_pagination_parameters.return_value = pagination
        mock_pagination_range.return_value = range(1, 2)
        raw_response = {
            "data": {
                "vulnerabilities": [
                    {"vuln_id": "vuln_1", "severity": "high", "timestamp": "2024-08-27T00:00:00Z"},
                ],
                "connector_guid": connector_guid
            },
            "links": {
                "self": "https://example.com/api/computers/connector_guid_123/vulnerabilities"
            }
        }
        mock_client.computer_vulnerabilities_list_request.return_value = raw_response

        mock_combine_response_results.return_value = raw_response
        mock_get_context_output.return_value = [raw_response["data"]]

        computer_vulnerabilities_list_command()

        mock_combine_response_results.assert_called_once()
        mock_get_context_output.assert_called_once_with(raw_response, ["links"])
        mock_add_item_to_all_dictionaries.assert_called_once_with(
            raw_response["data"]["vulnerabilities"],
            "connector_guid",
            connector_guid
        )
        mock_orenctl.results.assert_called_once_with({
            "outputs_prefix": "CiscoAMP.ComputerVulnerability",
            "outputs_key_field": "connector_guid",
            "outputs": raw_response["data"]["vulnerabilities"],
            "raw_response": raw_response,
        })

    @patch('CiscoAMP.computer_isolation_polling_command')
    @patch('orenctl.getArg')
    def test_computer_isolation_create_polling_command(self, mock_getArg, mock_computer_isolation_polling_command):
        mock_getArg.side_effect = lambda key: {
            "interval_in_seconds": 30,
            "timeout_in_seconds": 600,
            "connector_guid": "connector_guid_123",
            "comment": "Test comment",
            "unlock_code": "12345",
            "status": "isolated"
        }.get(key, None)

        result = computer_isolation_create_polling_command()

        mock_computer_isolation_polling_command.assert_called_once_with(
            args={
                "interval_in_seconds": 30,
                "timeout_in_seconds": 600,
                "connector_guid": "connector_guid_123",
                "comment": "Test comment",
                "unlock_code": "12345",
                "status": "isolated"
            },
            computer_isolation_command=computer_isolation_create_command,
            result_isolation_status=("isolated", "pending_start")
        )

        self.assertEqual(result, mock_computer_isolation_polling_command.return_value)

    @patch('CiscoAMP.check_endpoint_ids')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_endpoint_command(self, mock_results, mock_getArg, mock_check_endpoint_ids):
        mock_getArg.side_effect = lambda key: {
            "endpoint_ids": "id_123",
            "ip": "192.168.1.1",
            "hostname": "hostname_123"
        }.get(key, None)

        mock_check_endpoint_ids.return_value = [{
            "data": {
                "connector_guid": "id_123",
                "internal_ips": ["192.168.1.1"],
                "hostname": "hostname_123",
                "network_addresses": [{"mac": "00:11:22:33:44:55"}],
                "operating_system": "Windows 10",
                "os_version": "10.0",
                "active": True
            }
        }]

        endpoint_command()

        expected_endpoints = [{
            "raw_response": mock_check_endpoint_ids.return_value[0],
            "outputs_key_field": "_id",
            "indicator": {
                "id": "id_123",
                "ip_address": "192.168.1.1",
                "hostname": "hostname_123",
                "mac_address": "00:11:22:33:44:55",
                "os": "Windows 10",
                "os_version": "10.0",
                "status": "Online",
                "vendor": "CiscoAMP Response"
            }
        }]

        mock_results.assert_called_once_with({"endpoints": expected_endpoints})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    def test_endpoint_command_no_args(self, mock_results, mock_getArg):
        mock_getArg.side_effect = lambda key: None

        with self.assertRaises(Exception):
            endpoint_command()

        mock_results.assert_called_once_with(
            orenctl.error("CiscoAMP - In order to run this command, please provide a valid id, ip or hostname")
        )

    def test_automatic_pagination_with_large_limit(self):
        limit = 2000
        page = 0
        page_size = 0
        expected = Pagination(
            page=0,
            page_size=0,
            limit=100,
            offset=100,
            number_of_requests=20,
            offset_multiplier=0,
            is_automatic=True,
            is_manual=False,
        )
        result = get_pagination_parameters(page, page_size, limit)
        self.assertEqual(result, expected)

    def test_automatic_pagination_with_small_limit(self):
        limit = 1
        page = 0
        page_size = 0
        expected = Pagination(
            page=0,
            page_size=0,
            limit=1,
            offset=None,
            number_of_requests=1,
            offset_multiplier=1,
            is_automatic=True,
            is_manual=False,
        )
        result = get_pagination_parameters(page, page_size, limit)
        self.assertEqual(result, expected)

    def test_manual_pagination(self):
        limit = 0
        page = 2
        page_size = 50
        expected = Pagination(
            page=2,
            page_size=50,
            limit=50,
            offset=50,
            number_of_requests=1,
            offset_multiplier=1,
            is_automatic=False,
            is_manual=True,
        )
        result = get_pagination_parameters(page, page_size, limit)
        self.assertEqual(result, expected)

    def test_conflicting_pagination_parameters(self):
        limit = 100
        page = 2
        page_size = 50
        with self.assertRaises(ValueError):
            get_pagination_parameters(page, page_size, limit)

    def test_pagination_range(self):
        test_cases = [
            {
                'pagination': Pagination(
                    page=1,
                    page_size=10,
                    limit=10,
                    offset=0,
                    number_of_requests=1,
                    offset_multiplier=1,
                    is_automatic=False,
                    is_manual=True,
                ),
                'expected_range': range(1, 2)
            },
            {
                'pagination': Pagination(
                    page=1,
                    page_size=10,
                    limit=50,
                    offset=0,
                    number_of_requests=5,
                    offset_multiplier=1,
                    is_automatic=True,
                    is_manual=False,
                ),
                'expected_range': range(1, 6)
            },
            {
                'pagination': Pagination(
                    page=1,
                    page_size=10,
                    limit=30,
                    offset=0,
                    number_of_requests=3,
                    offset_multiplier=2,
                    is_automatic=True,
                    is_manual=False,
                ),
                'expected_range': range(2, 5)
            },
        ]

        for case in test_cases:
            with self.subTest(case=case):
                result = pagination_range(case['pagination'])
                self.assertEqual(result, case['expected_range'])

    def test_remove_empty_elements(self):
        # Define the test cases
        test_cases = [
            {
                'input': {
                    'key1': 'value1',
                    'key2': None,
                    'key3': [],
                    'key4': 'value4',
                    'key5': '',
                    'key6': 'value6',
                },
                'expected': {
                    'key1': 'value1',
                    'key4': 'value4',
                    'key6': 'value6',
                }
            },
            {
                'input': {
                    'key1': None,
                    'key2': [],
                    'key3': '',
                },
                'expected': {}
            },
            {
                'input': {
                    'key1': 'value1',
                    'key2': 'value2',
                    'key3': 'value3',
                },
                'expected': {
                    'key1': 'value1',
                    'key2': 'value2',
                    'key3': 'value3',
                }
            },
            {
                'input': {},
                'expected': {}
            },
        ]

        for case in test_cases:
            with self.subTest(case=case):
                result = remove_empty_elements(case['input'])
                self.assertEqual(result, case['expected'])

    def test_existing_key(self):
        result = dict_safe_get(self.test_dict, ['a', 'b', 0, 'c'])
        self.assertEqual(result, 'value1')

    def test_non_existing_key(self):
        result = dict_safe_get(self.test_dict, ['a', 'x'], default_return_value='default')
        self.assertEqual(result, 'default')

    def test_non_existing_key_with_default(self):
        result = dict_safe_get(self.test_dict, ['a', 'b', 2], default_return_value='default')
        self.assertEqual(result, 'default')

    def test_empty_keys(self):
        result = dict_safe_get(self.test_dict, [], default_return_value='default')
        self.assertEqual(result, self.test_dict)

    def test_invalid_type_dict_safe_get(self):
        result = dict_safe_get(self.test_dict, ['a', 'd'], return_type=str)
        self.assertEqual(result, 'value3')

    def test_raise_type_error(self):
        with self.assertRaises(TypeError):
            dict_safe_get(self.test_dict, ['a', 'b'], return_type=str)

    def test_no_raise_type_error(self):
        result = dict_safe_get(self.test_dict, ['a', 'b'], return_type=str, raise_return_type=False)
        self.assertIsNone(result)

    def test_automatic_combination(self):
        result = combine_response_results(self.raw_response_list_auto, is_automatic=True)
        expected_result = {
            "metadata": {
                "results": {
                    "current_item_count": 15,
                    "items_per_page": 15
                }
            },
            "data": [
                {"id": 1, "value": "A"},
                {"id": 2, "value": "B"}
            ]
        }
        self.assertEqual(result, expected_result)

    def test_non_automatic_combination(self):
        result = combine_response_results(self.raw_response_list_non_auto, is_automatic=False)
        expected_result = self.raw_response_list_non_auto[0]
        self.assertEqual(result, expected_result)

    def test_delete_single_key(self):
        result = delete_keys_from_dict(self.sample_dict, ["a"])
        expected = {
            "b": {
                "c": 2,
                "d": {
                    "e": 3,
                    "f": 4
                }
            },
            "g": [
                {"h": 5, "i": 6},
                {"j": 7, "k": 8}
            ]
        }
        self.assertEqual(result, expected)

    def test_delete_nested_key(self):
        result = delete_keys_from_dict(self.sample_dict, ["f"])
        expected = {
            "a": 1,
            "b": {
                "c": 2,
                "d": {
                    "e": 3
                }
            },
            "g": [
                {"h": 5, "i": 6},
                {"j": 7, "k": 8}
            ]
        }
        self.assertEqual(result, expected)

    def test_delete_contexts(self):
        result = get_context_output(self.response, ["extra"])
        expected = [
            {
                "id": 1,
                "name": "Item1",
                "details": {
                    "description": "A description"
                }
            },
            {
                "id": 2,
                "name": "Item2",
                "details": {
                    "description": "Another description"
                }
            }
        ]
        self.assertEqual(result, expected)

    def test_empty_query(self):
        self.assertTrue(validate_query(True, True, True, True, query=None))
        self.assertTrue(validate_query(True, True, True, True, query=""))

    def test_valid_sha256(self):
        self.assertTrue(validate_query(False, False, True, False, query="a" * 64))
        self.assertFalse(validate_query(False, False, True, False, query="short_sha256"))

    def test_valid_ipv4(self):
        self.assertTrue(validate_query(True, False, False, False, query="192.168.1.1"))
        self.assertFalse(validate_query(True, False, False, False, query="256.256.256.256"))

    def test_valid_url(self):
        self.assertTrue(validate_query(False, True, False, False, query="https://example.com"))
        self.assertFalse(validate_query(False, True, False, False, query="invalid-url"))

    def test_add_item_to_non_empty_dictionaries(self):
        dicts = [{"a": 1}, {"b": 2}]
        add_item_to_all_dictionaries(dicts, "c", 3)
        expected = [{"a": 1, "c": 3}, {"b": 2, "c": 3}]
        self.assertEqual(dicts, expected)

    @patch('CiscoAMP.get_context_output')
    @patch('CiscoAMP.add_item_to_all_dictionaries')
    @patch('CiscoAMP.dict_safe_get')
    def test_manual_pagination(self, mock_dict_safe_get, mock_add_item_to_all_dictionaries, mock_get_context_output):
        pagination = Pagination(page=2, page_size=2, limit=0, offset=None, number_of_requests=1, offset_multiplier=1,
                                is_automatic=False, is_manual=True)
        raw_response = {
            "data": {
                "events": [
                    {"event_id": 1, "name": "Event1"},
                    {"event_id": 2, "name": "Event2"},
                    {"event_id": 3, "name": "Event3"},
                    {"event_id": 4, "name": "Event4"},
                ],
                "computer": {"connector_guid": "connector-guid-123"}
            }
        }
        mock_dict_safe_get.return_value = "connector-guid-123"
        mock_get_context_output.return_value = [{"events": raw_response["data"]["events"]}]

        result = extract_pagination_from_response(pagination, raw_response)

        expected_events = [
            {'event_id': 1, 'name': 'Event1'},
            {'event_id': 2, 'name': 'Event2'},
            {'event_id': 3, 'name': 'Event3'},
            {'event_id': 4, 'name': 'Event4'}
        ]
        mock_get_context_output.assert_called_once_with(raw_response, ["links"])
        self.assertEqual(result, expected_events)

    def test_check_endpoint_ids_with_endpoint_ids(self):
        # Mock responses
        self.client.computer_get_request.side_effect = [
            {'id': 'id1', 'data': 'response1'},
            {'id': 'id2', 'data': 'response2'}
        ]

        result = check_endpoint_ids(self.client, [], self.endpoint_ids, [])

        expected = [
            {'id': 'id1', 'data': 'response1'},
            {'id': 'id2', 'data': 'response2'}
        ]

        self.assertEqual(result, expected)
        self.client.computer_get_request.assert_called_with(connector_guid='id2')
        self.assertEqual(self.client.computer_get_request.call_count, 2)

    def test_check_endpoint_ids_with_endpoint_ips(self):
        # Mock responses
        self.client.computer_list_request.side_effect = [
            {'ip': '192.168.1.1', 'data': 'response1'},
            {'ip': '192.168.1.2', 'data': 'response2'}
        ]

        result = check_endpoint_ids(self.client, [], [], self.endpoint_ips)

        expected = [
            {'ip': '192.168.1.2', 'data': 'response2'}
        ]

        self.assertEqual(result, expected)
        self.client.computer_list_request.assert_called_with(internal_ip='192.168.1.2')
        self.assertEqual(self.client.computer_list_request.call_count, 2)

    def test_polling_command_without_status(self):
        mock_response = MagicMock()
        mock_response.raw_response = {
            "data": {"status": "isolated"}
        }
        self.computer_isolation_command.return_value = mock_response

        args = {"some_arg": "value"}
        result = computer_isolation_polling_command(args, self.computer_isolation_command, self.result_isolation_status)

        expected = {
            "response": mock_response,
            "continue_to_poll": False
        }

        self.assertEqual(result, expected)
        self.computer_isolation_command.assert_called_once_with(args)
        self.computer_isolation_get_command.assert_not_called()

    @patch('CiscoAMP.CiscoAMP')
    @patch('CiscoAMP.get_context_output')
    def test_computer_isolation_create_command(self, mock_get_context_output, MockCiscoAMP):
        mock_client = MockCiscoAMP.return_value
        mock_response = {
            "data": {
                "status": "created"
            }
        }
        mock_client.computer_isolation_create_request.return_value = mock_response

        mock_get_context_output.return_value = [{
            "status": "created"
        }]

        args = {
            "connector_guid": "1234",
            "comment": "Isolated for testing",
            "unlock_code": "unlock123"
        }

        result = computer_isolation_create_command(args)

        expected = {'outputs': {'status': 'created'},
                    'outputs_key_field': 'connector_guid',
                    'outputs_prefix': 'CiscoAMP.ComputerIsolation',
                    'raw_response': {'data': {'status': 'created'}}}

        self.assertEqual(result, expected)
        mock_client.computer_isolation_create_request.assert_called_once_with(
            connector_guid="1234",
            comment="Isolated for testing",
            unlock_code="unlock123"
        )
        mock_get_context_output.assert_called_once_with(
            response=mock_response,
            contexts_to_delete=["links"],
            item_to_add=("connector_guid", "1234")
        )

    def test_md5_hash(self):
        file_hash = 'd41d8cd98f00b204e9800998ecf8427e'
        result = get_hash_type(file_hash)
        self.assertEqual(result, 'MD5')

    def test_sha1_hash(self):
        file_hash = 'a94a8fe5ccb19ba61c4c0873dq391e987982fbbd'
        result = get_hash_type(file_hash)
        self.assertEqual(result, 'SHA-1')

    def test_sha256_hash(self):
        file_hash = 'e99a18c428cb38d5f260853678922e03abd4f40c4f5a6e0c7ddde05e5c0a1a0b'
        result = get_hash_type(file_hash)
        self.assertEqual(result, 'SHA-256')

    def test_unknown_hash(self):
        file_hash = 'short'
        result = get_hash_type(file_hash)
        self.assertEqual(result, 'Unknown')

    @patch('CiscoAMP.CiscoAMP')
    @patch('CiscoAMP.orenctl')
    @patch('CiscoAMP.arg_to_list')
    @patch('CiscoAMP.get_hash_type')
    @patch('CiscoAMP.dict_safe_get')
    def test_file_command(self, mock_dict_safe_get, mock_get_hash_type, mock_arg_to_list, mock_orenctl, MockCiscoAMP):
        mock_orenctl.getArg.return_value = ['e99a18c428cb38d5f260853678922e03abd4f40c4f5a6e0c7ddde05e5c0a1a0b']
        mock_arg_to_list.return_value = ['e99a18c428cb38d5f260853678922e03abd4f40c4f5a6e0c7ddde05e5c0a1a0b']
        mock_get_hash_type.return_value = 'SHA-256'

        mock_client = MockCiscoAMP.return_value
        mock_client.event_list_request.return_value = {
            "data": [{
                "file": {
                    "identity": {
                        "md5": "e99a18c428cb38d5f260853678922e03abd4f40c4f5a6e0c7ddde05e5c0a1a0b",
                        "sha1": "0cc175b9c0f1b6a831c399e269772661",
                        "sha256": "e99a18c428cb38d5f260853678922e03"
                    },
                    "file_path": "/path/to/file",
                    "file_name": "file.txt"
                },
                "computer": {
                    "hostname": "hostname"
                }
            }]
        }

        mock_dict_safe_get.side_effect = lambda d, keys: d.get(keys[-1], None)

        mock_get_hash_type.return_value = 'SHA-256'
        file_command()

        expected_output = [{
            "outputs_prefix": "",
            "raw_response": {
                "data": [{
                    "file": {
                        "identity": {
                            "md5": "d41d8cd98f00b204e9800998ecf8427e",
                            "sha1": "0cc175b9c0f1b6a831c399e269772661",
                            "sha256": "e99a18c428cb38d5f260853678922e03"
                        },
                        "file_path": "/path/to/file",
                        "file_name": "file.txt"
                    },
                    "computer": {
                        "hostname": "hostname"
                    }
                }]
            },
            "outputs_key_field": "SHA256",
            "indicator": {
                "md5": "d41d8cd98f00b204e9800998ecf8427e",
                "sha1": "0cc175b9c0f1b6a831c399e269772661",
                "sha256": "d41d8cd98f00b204e9800998ecf8427e",
                "path": "/path/to/file",
                "name": "file.txt",
                "hostname": "hostname"
            }
        }]

        with patch('orenctl.results') as mock_results:
            file_command()
