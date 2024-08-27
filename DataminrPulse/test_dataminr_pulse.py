import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError

from DataminrPulse import DataminrPulse, transform_watchlists_data, dataminrpulse_watchlists_get_command, \
    dataminrpulse_alerts_get_command, dataminrpulse_related_alerts_get_command, arg_to_list, raise_value_error, \
    encode_string_results, convert_to_number, arg_to_number, arg_to_boolean, remove_nulls_from_dictionary

OUTPUT_PREFIX_WATCHLISTS = 'DataminrPulse.WatchLists'


def mock_getArg_side_effect(key):
    return {
        'watchlist_ids': [{'watchlists': {}}],
        'watchlist_names': [{'watchlists': {}}],
        'query': 'Google',
        '_from': '1',
        'to': None,
        'num': 40,
        'alert_id': "969633949-1679028615394-3",
        'include_root': False
    }.get(key)


class DataminrPulseTest(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        dp = DataminrPulse()

        result = dp.http_request('GET', '/test_url')

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

        dp = DataminrPulse()

        with self.assertRaises(HTTPError):
            dp.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'client_id': '12345',
            'client_secret': 'secret',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
            'watchlist_names': 'test_watchlist_names',
        }.get(param)

        dp = DataminrPulse()

        self.assertEqual(dp.url, 'http://example.com')
        self.assertTrue(dp.insecure)
        self.assertEqual(dp.proxy, 'http://proxy.example.com')
        self.assertIsInstance(dp.session, requests.Session)

    def test_transform_watchlists_data(self):
        watchlists_data = {
            'watchlists': {
                'type1': [{'id': 1, 'name': 'list1'}, {'id': 2, 'name': 'list2'}],
                'type2': [{'id': 3, 'name': 'list3'}, {'id': 4, 'name': 'list4'}]
            }
        }
        expected_output = [
            {'id': 1, 'name': 'list1'}, {'id': 2, 'name': 'list2'},
            {'id': 3, 'name': 'list3'}, {'id': 4, 'name': 'list4'}
        ]
        self.assertEqual(transform_watchlists_data(watchlists_data), expected_output)

        watchlists_data = {
            'watchlists': {}
        }
        expected_output = []
        self.assertEqual(transform_watchlists_data(watchlists_data), expected_output)

        watchlists_data = {
            'watchlists': {
                'type1': [{'id': 1, 'name': 'list1'}]
            }
        }
        expected_output = [{'id': 1, 'name': 'list1'}]
        self.assertEqual(transform_watchlists_data(watchlists_data), expected_output)

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('DataminrPulse.DataminrPulse')
    def test_dataminrpulse_watchlists_get_command_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.get_watchlists.return_value = {
            'watchlists': {}
        }

        dataminrpulse_watchlists_get_command()

        mock_results.assert_called_once_with({
            "outputs_prefix": OUTPUT_PREFIX_WATCHLISTS,
            "outputs_key_field": 'id',
            "outputs": [],
            "raw_response": {
                'watchlists': {}
            }
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('DataminrPulse.DataminrPulse')
    def test_dataminrpulse_alerts_get_command_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.get_alerts.return_value = {
            'data': {}
        }

        dataminrpulse_alerts_get_command()

        mock_results.assert_called_once_with([{'outputs_prefix': 'DataminrPulse.Alerts', 'outputs_key_field': 'alertId',
                                               'outputs': [], 'raw_response': []},
                                              {'outputs_prefix': 'DataminrPulse.Cursor',
                                               'outputs_key_field': ['from', 'to'], 'outputs': ['from', 'to'],
                                               'raw_response': {'from': '', 'to': ''}}])

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('DataminrPulse.DataminrPulse')
    def test_dataminrpulse_related_alerts_get_command_success(self, mock_automox, mock_results, mock_getArg):
        mock_instance = mock_automox.return_value
        mock_instance.get_related_alerts.return_value = {
            'watchlists': {}
        }

        dataminrpulse_related_alerts_get_command()

        mock_results.assert_called_once_with(
            {'outputs_prefix': 'DataminrPulse.Alerts', 'outputs_key_field': 'alertId', 'outputs': ['watchlists'],
             'raw_response': {'watchlists': {}}})

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

    def test_raise_value_error_with_arg_name(self):
        with self.assertRaises(ValueError) as context:
            raise_value_error('test_arg', 'invalid_value', 'Invalid argument')
        self.assertEqual(str(context.exception), 'Invalid argument: "test_arg"="invalid_value"')

    def test_raise_value_error_without_arg_name(self):
        with self.assertRaises(ValueError) as context:
            raise_value_error(None, 'invalid_value', 'Invalid argument')
        self.assertEqual(str(context.exception), 'Invalid argument: "invalid_value"')

    def test_encode_string_results_with_normal_string(self):
        self.assertEqual(encode_string_results('hello'), 'hello')

    def test_encode_string_results_with_unicode_string(self):
        self.assertEqual(encode_string_results('café'), 'café')

    def test_encode_string_results_with_non_string(self):
        self.assertEqual(encode_string_results(1234), 1234)

    def test_convert_digit_string(self):
        self.assertEqual(convert_to_number('123', 'test_arg'), 123)

    def test_convert_non_numeric_string(self):
        with self.assertRaises(ValueError):
            convert_to_number('abc', 'test_arg')

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

    def test_boolean_true(self):
        self.assertTrue(arg_to_boolean(True))

    def test_boolean_false(self):
        self.assertFalse(arg_to_boolean(False))

    def test_string_false(self):
        self.assertFalse(arg_to_boolean('false'))

    def test_invalid_string(self):
        with self.assertRaises(ValueError):
            arg_to_boolean('maybe')

    def test_non_string_non_boolean(self):
        with self.assertRaises(ValueError):
            arg_to_boolean(123)

    def test_empty_string(self):
        with self.assertRaises(ValueError):
            arg_to_boolean('')

    def test_remove_nulls(self):
        input_data = {
            'key1': 'value1',
            'key2': None,
            'key3': '',
            'key4': [],
            'key5': {},
            'key6': (),
            'key7': 'value2'
        }
        expected_output = {
            'key1': 'value1',
            'key7': 'value2'
        }
        self.assertEqual(remove_nulls_from_dictionary(input_data), expected_output)

    def test_empty_dictionary(self):
        input_data = {}
        expected_output = {}
        self.assertEqual(remove_nulls_from_dictionary(input_data), expected_output)

    def test_no_nulls(self):
        input_data = {
            'key1': 'value1',
            'key2': 'value2'
        }
        expected_output = {
            'key1': 'value1',
            'key2': 'value2'
        }
        self.assertEqual(remove_nulls_from_dictionary(input_data), expected_output)

    def test_all_nulls(self):
        input_data = {
            'key1': None,
            'key2': '',
            'key3': [],
            'key4': {},
            'key5': ()
        }
        expected_output = {}
        self.assertEqual(remove_nulls_from_dictionary(input_data), expected_output)

    def test_mixed_values(self):
        input_data = {
            'key1': 'value1',
            'key2': None,
            'key3': 'value3',
            'key4': '',
            'key5': 'value5'
        }
        expected_output = {
            'key1': 'value1',
            'key3': 'value3',
            'key5': 'value5'
        }
        self.assertEqual(remove_nulls_from_dictionary(input_data), expected_output)
