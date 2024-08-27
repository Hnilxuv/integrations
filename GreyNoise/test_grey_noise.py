import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError

import orenctl
from GreyNoise import GreyNoiseV1, arg_to_list, remove_empty_elements, generate_advanced_query, get_ip_context_data, \
    check_query_response, ip_quick_check_command, query_command, stats_command, riot_command, context_command, \
    similarity_command

EXCEPTION_MESSAGES = {
    "API_RATE_LIMIT": "API Rate limit hit. Try after sometime.",
    "UNAUTHENTICATED": "Unauthenticated. Check the configured API Key.",
    "COMMAND_FAIL": "Failed to execute {} command.\n Error: {}",
    "SERVER_ERROR": "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    "CONNECTION_TIMEOUT": "Connection timed out. Check your network connectivity.",
    "PROXY": "Proxy Error - cannot connect to proxy. Either try clearing the 'Use system proxy' check-box or check "
             "the host, authentication details and connection details for the proxy.",
    "INVALID_RESPONSE": "Invalid response from GreyNoise. Response: {}",
    "QUERY_STATS_RESPONSE": "GreyNoise request failed. Reason: {}",
}

QUERY_OUTPUT_PREFIX = {
    "IP": "GreyNoise.IP(val.address && val.address == obj.address)",
    "QUERY": "GreyNoise.Query(val.query && val.query == obj.query)",
}


class TestGreyNoise(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        grey = GreyNoiseV1()

        result = grey.http_request('GET', '/test_url')

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

        grey = GreyNoiseV1()

        with self.assertRaises(HTTPError):
            grey.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'api_key': '12345',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        grey = GreyNoiseV1()

        self.assertEqual(grey.api_key, '12345')
        self.assertTrue(grey.insecure)
        self.assertEqual(grey.proxy, 'http://proxy.example.com')
        self.assertIsInstance(grey.session, requests.Session)

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

    def test_remove_empty_elements_from_dict(self):
        data = {
            "a": None,
            "b": [],
            "c": {},
            "d": {
                "e": 1,
                "f": None,
                "g": []
            },
            "h": [None, {}, [], 2]
        }
        expected = {
            "d": {
                "e": 1
            },
            "h": [2]
        }
        result = remove_empty_elements(data)
        self.assertEqual(result, expected)

    def test_generate_advanced_query_with_no_args(self):
        args = {}
        expected = "spoofable:false"
        result = generate_advanced_query(args)
        self.assertEqual(result, expected)

    def test_generate_advanced_query_with_advanced_query_only(self):
        args = {
            "advanced_query": "actor:john_doe"
        }
        expected = "actor:john_doe"
        result = generate_advanced_query(args)
        self.assertEqual(result, expected)

    def test_generate_advanced_query_with_used_args_only(self):
        args = {
            "actor": "john_doe",
            "classification": "malware",
            "spoofable": "true",
            "last_seen": "2024-08-27",
            "organization": "org1",
            "cve": "CVE-2023-1234"
        }
        expected = "actor:john_doe classification:malware cve:CVE-2023-1234 last_seen:2024-08-27 organization:org1 spoofable:true"
        result = generate_advanced_query(args)
        self.assertEqual(result, expected)

    def test_get_ip_context_data_with_empty_responses(self):
        responses = []
        expected = []
        result = get_ip_context_data(responses)
        self.assertEqual(result, expected)

    def test_get_ip_context_data_with_basic_data(self):
        responses = [
            {
                "IP": "1.1.1.1",
                "metadata": {
                    "asn": "13335",
                    "country": "US",
                    "tor": "false"
                },
                "classification": "benign"
            }
        ]
        expected = [
            {
                "MetaData": ["ASN: 13335", "Country: US", 'Tor: false'],
                "Tor": "false",
                "Classification": "benign",
                "IP": "[1.1.1.1](https://viz.greynoise.io/ip/1.1.1.1)"
            }
        ]
        result = get_ip_context_data(responses)
        self.assertEqual(result, expected)

    def test_get_ip_context_data_with_missing_metadata(self):
        responses = [
            {
                "IP": "8.8.8.8",
                "metadata": {},
                "classification": "malicious"
            }
        ]
        expected = [
            {
                "MetaData": [],
                "Classification": "malicious",
                "IP": "[8.8.8.8](https://viz.greynoise.io/ip/8.8.8.8)"
            }
        ]
        result = get_ip_context_data(responses)
        self.assertEqual(result, expected)

    def test_get_ip_context_data_with_empty_values(self):
        responses = [
            {
                "IP": "8.8.4.4",
                "metadata": {
                    "asn": "",
                    "country": "US",
                    "tor": ""
                },
                "classification": ""
            }
        ]
        expected = [
            {
                "MetaData": ["Country: US"],
                "Tor": "",
                "IP": "[8.8.4.4](https://viz.greynoise.io/ip/8.8.4.4)"
            }
        ]
        result = get_ip_context_data(responses)
        self.assertEqual(result, expected)

    def test_valid_response_ok(self):
        query_response = {"message": "ok"}
        try:
            check_query_response(query_response)
        except ValueError:
            self.fail("check_query_response raised ValueError unexpectedly for a valid 'ok' response.")

    def test_valid_response_no_results(self):
        query_response = {"message": "no results"}
        try:
            check_query_response(query_response)
        except ValueError:
            self.fail("check_query_response raised ValueError unexpectedly for a valid 'no results' response.")

    def test_invalid_response_type(self):
        query_response = ["unexpected", "list"]
        with self.assertRaises(ValueError) as context:
            check_query_response(query_response)
        self.assertEqual(str(context.exception), EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(query_response))

    def test_invalid_response_message(self):
        query_response = {"message": "error"}
        with self.assertRaises(ValueError) as context:
            check_query_response(query_response)
        self.assertEqual(str(context.exception), EXCEPTION_MESSAGES["QUERY_STATS_RESPONSE"].format("error"))

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('orenctl.error')
    @patch('GreyNoise.remove_empty_elements')
    @patch('GreyNoise.arg_to_list')
    def test_ip_quick_check_command_success(self, mock_arg_to_list, mock_remove_empty_elements, mock_error,
                                            mock_results, mock_getArg, MockGreyNoise):
        mock_client = MagicMock()
        MockGreyNoise.return_value = mock_client
        mock_getArg.return_value = '1.1.1.1,2.2.2.2'
        mock_response = [
            {"address": "1.1.1.1", "code_message": "200"},
            {"address": "2.2.2.2", "code_message": "404"}
        ]
        value = [
            {"address": "1.1.1.1", "code_message": "200"},
            {"address": "2.2.2.2", "code_message": "404"}
        ]
        mock_client.quick.return_value = mock_response
        mock_remove_empty_elements.return_value = [
            {"address": "1.1.1.1", "code_value": "200"},
            {"address": "2.2.2.2", "code_value": "404"}
        ]

        ip_quick_check_command()

        expected_transformed_response = [
            {"address": "1.1.1.1", "code_value": "200"},
            {"address": "2.2.2.2", "code_value": "404"}
        ]
        expected_results = {
            "outputs_prefix": "GreyNoise.IP",
            "outputs_key_field": "address",
            "outputs": expected_transformed_response,
            "raw_response": value
        }

        # Assertions
        mock_results.assert_called_once_with(expected_results)
        mock_error.assert_not_called()

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('orenctl.error')
    @patch('GreyNoise.remove_empty_elements')
    @patch('GreyNoise.arg_to_list')
    def test_query_command_success(self, mock_generate_advanced_query, mock_remove_empty_elements, mock_error,
                                   mock_results, mock_getArg, MockGreyNoiseV1):
        mock_instance = MockGreyNoiseV1.return_value

        mock_client = MagicMock()
        MockGreyNoiseV1.return_value.grey_noise_v2 = mock_client

        mock_getArg.side_effect = lambda x: {
            'classification': 'malicious',
            'spoofable': 'false',
            'actor': 'actor1',
            'size': '10',
            'advanced_query': 'spoofable:false',
            'next_token': 'token123',
            'last_seen': '2023-08-01',
            'organization': 'org1',
        }.get(x, None)
        mock_generate_advanced_query.return_value = 'classification:malicious actor:actor1'
        mock_query_response = {
            "message": "ok",
            "data": [
                {"ip": "1.1.1.1", "code_message": "200"},
                {"ip": "2.2.2.2", "code_message": "404"}
            ],
            "count": 2,
            "complete": False,
            "query": "classification:malicious actor:actor1",
            "scroll": "token123"
        }
        mock_instance.query.return_value = mock_query_response
        mock_client.query.return_value = mock_query_response
        mock_remove_empty_elements.return_value = [
            {"address": "1.1.1.1", "code_value": "200"},
            {"address": "2.2.2.2", "code_value": "404"}
        ]

        query_command()

        self.assertIsNotNone(orenctl.get_results())

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('orenctl.error')
    @patch('GreyNoise.remove_empty_elements')
    def test_stats_command_success(self, mock_remove_empty_elements, mock_error, mock_results, mock_getArg,
                                   MockGreyNoise):
        mock_client = MagicMock()
        MockGreyNoise.return_value = mock_client

        mock_getArg.side_effect = lambda x: {
            'classification': 'malicious',
            'spoofable': 'false',
            'actor': 'actor1',
            'size': '10',
            'advanced_query': 'spoofable:false',
            'last_seen': '2023-08-01',
            'organization': 'org1'
        }.get(x, None)

        mock_response = {
            "query": "classification:malicious actor:actor1",
            "count": 2,
            "some_field": "value"
        }
        mock_client.stats.return_value = mock_response
        mock_remove_empty_elements.return_value = mock_response

        stats_command()

        mock_results.assert_called_once_with({
            "outputs_prefix": "GreyNoise.Stats",
            "outputs_key_field": "query",
            "outputs": mock_response,
        })
        mock_error.assert_not_called()

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('GreyNoise.remove_empty_elements')
    def test_riot_command_trust_level_1(self, mock_remove_empty_elements, mock_results, mock_getArg, MockGreyNoise):
        mock_client = MagicMock()
        MockGreyNoise.return_value = mock_client

        mock_getArg.side_effect = lambda x: {
            'ip': '1.1.1.1'
        }.get(x, None)

        mock_response = {
            "logo_url": "http://example.com/logo.png",
            "trust_level": "1",
            "other_field": "value"
        }
        mock_client.riot.return_value = mock_response
        mock_remove_empty_elements.return_value = mock_response.copy()

        riot_command()

        expected_response = {
            "trust_level": "1 - Reasonably Ignore",
            "classification": "benign",
            "other_field": "value"
        }
        expected_results = {
            "outputs_prefix": "GreyNoise.Riot",
            "outputs_key_field": "address",
            "outputs": expected_response,
            "raw_response": mock_response,
        }

        mock_client.riot.assert_called_once_with('1.1.1.1')
        mock_results.assert_called_once_with(expected_results)

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('GreyNoise.remove_empty_elements')
    def test_context_command_success(self, mock_remove_empty_elements, mock_results,
                                     mock_getArg, MockGreyNoise):
        mock_client = MagicMock()
        MockGreyNoise.return_value = mock_client

        mock_getArg.side_effect = lambda x: {
            'ip': '1.1.1.1'
        }.get(x, None)

        mock_response = {
            "ip": "1.1.1.1",
            "metadata": {
                "city": "New York",
                "region": "NY",
                "country_code": "US",
                "asn": "AS1234",
                "country": "United States"
            },
            "actor": "example-host"
        }
        mock_client.ip.return_value = mock_response
        mock_remove_empty_elements.return_value = mock_response.copy()

        context_command()

        mock_client.ip.assert_called_once_with('1.1.1.1')

    @patch('GreyNoise.GreyNoise')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('GreyNoise.remove_empty_elements')
    def test_similarity_command_success(self, mock_remove_empty_elements, mock_results,
                                        mock_getArg, MockGreyNoise):
        mock_client = MagicMock()
        MockGreyNoise.return_value = mock_client

        mock_getArg.side_effect = lambda x: {
            'ip': '1.1.1.1',
            'minimum_score': '80',
            'maximum_results': '10'
        }.get(x, None)

        mock_response = {
            "similar_ips": [
                {
                    "ip": "2.2.2.2",
                    "score": 0.85,
                    "classification": "malicious",
                    "actor": "actor1",
                    "organization": "org1",
                    "source_country": "US",
                    "last_seen": "2023-08-01",
                    "features": ["feature1", "feature2"]
                }
            ]
        }
        mock_client.similar.return_value = mock_response
        mock_remove_empty_elements.return_value = mock_response.copy()

        similarity_command()

        mock_client.similar.assert_called_once_with('1.1.1.1', min_score=80, limit=10)
