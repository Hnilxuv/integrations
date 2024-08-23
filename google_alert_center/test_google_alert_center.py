import os
import unittest
from unittest.mock import patch, MagicMock

import httplib2
from google.auth import exceptions

from google_alert_center import argToList, validate_get_int, validate_params_for_list_alerts, GoogleAlertCenter, \
    MESSAGES, skip_proxy, skip_cert_verification, handle_proxy, urljoin, check_required_arguments, \
    create_custom_context_for_batch_command, safe_load_non_strict_json, COMMON_MESSAGES, http_exception_handler, \
    handle_http_error, validate_and_extract_response, remove_empty_entities, set_authorized_http, get_http_client, \
    gsac_list_alerts_command, gsac_get_alert_command, gsac_create_alert_feedback_command, \
    gsac_list_alert_feedback_command, gsac_batch_recover_alerts_command


class TestGoogleAlertCenter(unittest.TestCase):
    @patch('orenctl.getParam')
    @patch('requests.session')
    @patch('google.oauth2.service_account.Credentials.from_service_account_info')
    def setUp(self, mock_service_account_info, mock_requests_session, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            "url": "http://example.com",
            "user_name": "test_user",
            "password": "test_password",
            "proxy": "http://proxy.com",
            "admin_email": "admin@example.com"
        }.get(key)

        mock_service_account_info.return_value = MagicMock()

        mock_session = MagicMock()
        mock_requests_session.return_value = mock_session
        self.instance = GoogleAlertCenter(None)
        self.instance.base_url = 'http://example.com'
        self.instance.session = MagicMock()

    def test_empty_arg(self):
        # Test case for empty input
        self.assertIsNotNone(argToList(None), [])
        self.assertIsNotNone(argToList(''), [])

    def test_list_input(self):
        # Test case for when arg is already a list
        self.assertIsNotNone(argToList([1, 2, 3]), [1, 2, 3])
        self.assertIsNotNone(argToList(['a', 'b', 'c']), ['a', 'b', 'c'])

    def test_comma_separated_string(self):
        # Test case for a comma-separated string input
        self.assertIsNotNone(argToList('a,b,c'), ['a', 'b', 'c'])
        self.assertIsNotNone(argToList('  a , b ,  c  '), ['a', 'b', 'c'])  # Test trimming whitespace

    def test_custom_separator(self):
        # Test case with a custom separator
        self.assertIsNotNone(argToList('a|b|c', separator='|'), ['a', 'b', 'c'])

    def test_non_string_non_list_input(self):
        # Test case for input that is neither a string nor a list
        self.assertIsNotNone(argToList(42), [42])

    def test_transform_function(self):
        # Test case using a transform function (e.g., converting to uppercase)
        self.assertIsNotNone(argToList('a,b,c', transform=str.upper), ['A', 'B', 'C'])
        self.assertIsNotNone(argToList([1, 2, 3], transform=str), ['1', '2', '3'])

    def test_valid_max_results(self):
        # Test with a valid integer string
        result = validate_get_int("10", "Invalid value", 100)
        self.assertEqual(result, 10)

    def test_valid_max_results_no_limit(self):
        # Test with a valid integer string and no limit
        result = validate_get_int("5", "Invalid value")
        self.assertEqual(result, 5)

    def test_max_results_exceeds_limit(self):
        # Test when max_results exceeds the provided limit
        with self.assertRaises(ValueError) as context:
            validate_get_int("101", "Value exceeds limit", 100)
        self.assertEqual(str(context.exception), "Value exceeds limit")

    def test_max_results_zero_or_negative(self):
        # Test when max_results is zero
        with self.assertRaises(ValueError) as context:
            validate_get_int("0", "Value must be greater than 0")
        self.assertEqual(str(context.exception), "Value must be greater than 0")

        # Test when max_results is a negative value
        with self.assertRaises(ValueError) as context:
            validate_get_int("-5", "Value must be greater than 0")
        self.assertEqual(str(context.exception), "Value must be greater than 0")

    def test_max_results_invalid_string(self):
        # Test with an invalid string that cannot be converted to an integer
        with self.assertRaises(ValueError) as context:
            validate_get_int("abc", "Invalid integer value")
        self.assertEqual(str(context.exception), "Invalid integer value")

    def test_max_results_none(self):
        # Test when max_results is None, should return None
        result = validate_get_int(None, "Invalid value")
        self.assertIsNone(result)

    @patch('orenctl.getArg')
    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.validate_get_int')
    def test_validate_params_for_list_alerts(self, mock_validate_get_int, mock_GoogleAlertCenter, mock_getArg):
        mock_getArg.side_effect = lambda key: {
            'page_size': '10',
            'filter': "status='ACTIVE'",
            'page_token': 'abc123',
            'order_by': 'created_time desc'
        }.get(key, '')

        mock_validate_get_int.return_value = 10

        mock_gac_instance = MagicMock()
        mock_GoogleAlertCenter.return_value = mock_gac_instance
        mock_gac_instance.remove_empty_entities.return_value = {
            'pageToken': 'abc123',
            'pageSize': 10,
            'filter': 'status="ACTIVE"',
            'orderBy': 'created_time desc'
        }

        result = validate_params_for_list_alerts()

        mock_validate_get_int.assert_called_once_with('10', message=MESSAGES['INTEGER_ERROR'].format('page_size'))

        expected_params = {
            'pageToken': 'abc123',
            'pageSize': 10,
            'filter': 'status="ACTIVE"',
            'orderBy': 'created_time desc'
        }
        self.assertEqual(result, expected_params)

    def test_validate_params_for_list_alerts_no_page_size(self):
        with patch('orenctl.getArg', return_value=''), \
                patch('google_alert_center.GoogleAlertCenter') as mock_GoogleAlertCenter:
            mock_gac_instance = MagicMock()
            mock_GoogleAlertCenter.return_value = mock_gac_instance
            mock_gac_instance.remove_empty_entities.return_value = {}

            result = validate_params_for_list_alerts()

            expected_params = {}
            self.assertEqual(result, expected_params)

    def test_remove_empty_entities_with_empty_values_in_dict(self):
        # Test with a dictionary containing empty values
        data = {
            'key1': 'value1',
            'key2': '',
            'key3': None,
            'key4': {},
            'key5': [],
            'key6': 'value2'
        }
        expected = {
            'key1': 'value1',
            'key6': 'value2'
        }
        result = remove_empty_entities(data)
        self.assertEqual(result, expected)

    def test_remove_empty_entities_with_empty_values_in_list(self):
        # Test with a list containing empty values
        data = ['value1', '', None, {}, [], 'value2']
        expected = ['value1', 'value2']
        result = remove_empty_entities(data)
        self.assertEqual(result, expected)

    def test_remove_empty_entities_nested_dict(self):
        # Test with a nested dictionary containing empty values
        data = {
            'key1': {
                'subkey1': '',
                'subkey2': 'value2'
            },
            'key2': None,
            'key3': {
                'subkey3': {}
            },
            'key4': 'value4'
        }
        expected = {
            'key1': {
                'subkey2': 'value2'
            },
            'key4': 'value4'
        }
        result = remove_empty_entities(data)
        self.assertEqual(result, expected)

    def test_remove_empty_entities_nested_list(self):
        # Test with a nested list containing empty values
        data = ['value1', ['', 'value2'], None, [''], 'value3']
        expected = ['value1', ['value2'], 'value3']
        result = remove_empty_entities(data)
        self.assertEqual(result, expected)

    def test_remove_empty_entities_non_dict_or_list(self):
        # Test with a non-dict or list input (e.g., a string)
        data = 'value'
        result = remove_empty_entities(data)
        self.assertEqual(result, 'value')

    def test_remove_empty_entities_empty_dict(self):
        # Test with an empty dictionary
        data = {}
        result = remove_empty_entities(data)
        self.assertEqual(result, {})

    def test_remove_empty_entities_empty_list(self):
        # Test with an empty list
        data = []
        result = remove_empty_entities(data)
        self.assertEqual(result, [])

    def test_valid_input(self):
        # Test with valid input within the limit
        result = validate_get_int("10", message="Invalid integer", limit=100)
        self.assertEqual(result, 10)

    def test_valid_input_no_limit(self):
        # Test with valid input when no limit is provided
        result = validate_get_int("50", message="Invalid integer")
        self.assertEqual(result, 50)

    def test_input_zero(self):
        # Test with input as zero, which should raise ValueError
        with self.assertRaises(ValueError) as context:
            validate_get_int("0", message="Invalid integer")
        self.assertEqual(str(context.exception), "Invalid integer")

    def test_input_negative(self):
        # Test with negative input, which should raise ValueError
        with self.assertRaises(ValueError) as context:
            validate_get_int("-5", message="Invalid integer")
        self.assertEqual(str(context.exception), "Invalid integer")

    def test_input_exceeds_limit(self):
        # Test with input exceeding the limit, which should raise ValueError
        with self.assertRaises(ValueError) as context:
            validate_get_int("150", message="Invalid integer", limit=100)
        self.assertEqual(str(context.exception), "Invalid integer")

    def test_input_not_integer(self):
        # Test with non-integer input, which should raise ValueError
        with self.assertRaises(ValueError) as context:
            validate_get_int("abc", message="Invalid integer")
        self.assertEqual(str(context.exception), "Invalid integer")

    def test_input_none(self):
        # Test with None input, which should return None
        result = validate_get_int(None, message="Invalid integer")
        self.assertIsNone(result)

    def test_input_empty_string(self):
        # Test with empty string input, which should return None
        result = validate_get_int("", message="Invalid integer")
        self.assertIsNone(result)

    @patch.dict('os.environ', {'HTTP_PROXY': 'http://proxy.example.com',
                               'HTTPS_PROXY': 'https://proxy.example.com',
                               'http_proxy': 'http://proxy.example.com',
                               'https_proxy': 'https://proxy.example.com'}, clear=True)
    def test_skip_proxy_removes_proxies(self):
        # Ensure the environment variables are initially set
        self.assertIn('HTTP_PROXY', os.environ)
        self.assertIn('HTTPS_PROXY', os.environ)
        self.assertIn('http_proxy', os.environ)
        self.assertIn('https_proxy', os.environ)

        # Call the function to remove the proxy environment variables
        skip_proxy()

        # Assert that the proxy environment variables have been deleted
        self.assertNotIn('HTTP_PROXY', os.environ)
        self.assertNotIn('HTTPS_PROXY', os.environ)
        self.assertNotIn('http_proxy', os.environ)
        self.assertNotIn('https_proxy', os.environ)

    @patch.dict('os.environ', {}, clear=True)
    def test_skip_proxy_no_proxies(self):
        # Ensure the environment variables are not set initially
        self.assertNotIn('HTTP_PROXY', os.environ)
        self.assertNotIn('HTTPS_PROXY', os.environ)
        self.assertNotIn('http_proxy', os.environ)
        self.assertNotIn('https_proxy', os.environ)

        # Call the function to remove proxies (which don't exist)
        skip_proxy()

        # Ensure that nothing was wrongly deleted or modified
        self.assertNotIn('HTTP_PROXY', os.environ)
        self.assertNotIn('HTTPS_PROXY', os.environ)
        self.assertNotIn('http_proxy', os.environ)
        self.assertNotIn('https_proxy', os.environ)

    @patch.dict('os.environ', {'REQUESTS_CA_BUNDLE': '/path/to/ca_bundle',
                               'CURL_CA_BUNDLE': '/path/to/curl_bundle'}, clear=True)
    def test_skip_cert_verification_removes_cert_bundles(self):
        # Ensure the environment variables are initially set
        self.assertIn('REQUESTS_CA_BUNDLE', os.environ)
        self.assertIn('CURL_CA_BUNDLE', os.environ)

        # Call the function to remove the cert-related environment variables
        skip_cert_verification()

        # Assert that the cert-related environment variables have been deleted
        self.assertNotIn('REQUESTS_CA_BUNDLE', os.environ)
        self.assertNotIn('CURL_CA_BUNDLE', os.environ)

    @patch.dict('os.environ', {}, clear=True)
    def test_skip_cert_verification_no_cert_bundles(self):
        # Ensure the environment variables are not set initially
        self.assertNotIn('REQUESTS_CA_BUNDLE', os.environ)
        self.assertNotIn('CURL_CA_BUNDLE', os.environ)

        # Call the function to remove cert-related environment variables (which don't exist)
        skip_cert_verification()

        # Ensure that nothing was wrongly deleted or modified
        self.assertNotIn('REQUESTS_CA_BUNDLE', os.environ)
        self.assertNotIn('CURL_CA_BUNDLE', os.environ)

    @patch('google_alert_center.skip_proxy')
    @patch('google_alert_center.skip_cert_verification')
    @patch('google_alert_center.orenctl.getParam')
    @patch('os.environ', {'HTTP_PROXY': 'http://proxy.example.com', 'HTTPS_PROXY': 'https://proxy.example.com'})
    def test_handle_proxy_with_proxy_and_insecure(self, mock_getParam, mock_skip_cert_verification, mock_skip_proxy):
        mock_getParam.side_effect = lambda x: {
            'proxy': True,
            'insecure': True
        }.get(x, False)

        result = handle_proxy()

        # Assert the proxies were correctly set
        expected_proxies = {
            'http': 'http://proxy.example.com',
            'https': 'https://proxy.example.com'
        }
        self.assertEqual(result, expected_proxies)

        # Assert that skip_cert_verification was called
        mock_skip_cert_verification.assert_called_once()

        # Ensure that skip_proxy was not called
        mock_skip_proxy.assert_not_called()

    @patch('google_alert_center.skip_proxy')
    @patch('google_alert_center.skip_cert_verification')
    @patch('google_alert_center.orenctl.getParam')
    @patch('os.environ', {})
    def test_handle_proxy_without_proxy(self, mock_getParam, mock_skip_cert_verification, mock_skip_proxy):
        mock_getParam.side_effect = lambda x: {
            'proxy': False,
            'insecure': False
        }.get(x, False)

        result = handle_proxy()

        # Assert that proxies were skipped
        self.assertEqual(result, {})

        # Assert that skip_proxy was called
        mock_skip_proxy.assert_called_once()

        # Ensure that skip_cert_verification was not called
        mock_skip_cert_verification.assert_not_called()

    @patch('google_alert_center.skip_proxy')
    @patch('google_alert_center.skip_cert_verification')
    @patch('google_alert_center.orenctl.getParam')
    @patch('os.environ', {'http_proxy': 'http://lowercase-proxy.example.com'})
    def test_handle_proxy_with_lowercase_proxy(self, mock_getParam, mock_skip_cert_verification, mock_skip_proxy):
        mock_getParam.side_effect = lambda x: {
            'proxy': True,
            'insecure': False
        }.get(x, False)

        result = handle_proxy()

        # Assert the proxies were correctly set from lowercase environment variables
        expected_proxies = {
            'http': 'http://lowercase-proxy.example.com',
            'https': ''
        }
        self.assertEqual(result, expected_proxies)

        # Ensure that skip_proxy was not called
        mock_skip_proxy.assert_not_called()

        # Ensure that skip_cert_verification was not called
        mock_skip_cert_verification.assert_not_called()

    @patch('google_alert_center.skip_proxy')
    @patch('google_alert_center.skip_cert_verification')
    @patch('google_alert_center.orenctl.getParam')
    @patch('os.environ', {})
    def test_handle_proxy_custom_insecure_param(self, mock_getParam, mock_skip_cert_verification, mock_skip_proxy):
        mock_getParam.side_effect = lambda x: {
            'proxy': False,
            'custom_insecure': True
        }.get(x, False)

        result = handle_proxy(insecure_param_name='custom_insecure')

        # Assert that proxies were skipped
        self.assertEqual(result, {})

        # Assert that skip_proxy was called
        mock_skip_proxy.assert_called_once()

        # Assert that skip_cert_verification was called due to custom insecure param
        mock_skip_cert_verification.assert_called_once()

    def test_urljoin_no_suffix(self):
        self.assertEqual(urljoin("http://example.com"), "http://example.com/")

    def test_urljoin_empty_suffix(self):
        self.assertEqual(urljoin("http://example.com", ""), "http://example.com/")

    def test_urljoin_suffix_without_leading_slash(self):
        self.assertEqual(urljoin("http://example.com", "path"), "http://example.com/path")

    def test_urljoin_suffix_with_leading_slash(self):
        self.assertEqual(urljoin("http://example.com", "/path"), "http://example.com/path")

    def test_urljoin_url_with_trailing_slash(self):
        self.assertEqual(urljoin("http://example.com/", "path"), "http://example.com/path")

    def test_urljoin_suffix_with_trailing_slash(self):
        self.assertEqual(urljoin("http://example.com", "path/"), "http://example.com/path/")

    def test_urljoin_url_and_suffix_both_have_trailing_slash(self):
        self.assertEqual(urljoin("http://example.com/", "/path/"), "http://example.com/path/")

    @patch.dict('google_alert_center.MESSAGES', {'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Missing required arguments: {}'})
    def test_all_arguments_present(self):
        required_arguments = ['arg1', 'arg2']
        args = {'arg1': 1, 'arg2': 2}
        try:
            check_required_arguments(required_arguments, args)
        except ValueError:
            self.fail("check_required_arguments raised ValueError unexpectedly!")

    @patch.dict('google_alert_center.MESSAGES', {'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Missing required arguments: {}'})
    def test_some_arguments_missing(self):
        required_arguments = ['arg1', 'arg2', 'arg3']
        args = {'arg1': 1}
        with self.assertRaises(ValueError) as context:
            check_required_arguments(required_arguments, args)
        self.assertEqual(str(context.exception), 'Missing required arguments: arg2, arg3')

    @patch.dict('google_alert_center.MESSAGES', {'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Missing required arguments: {}'})
    def test_all_arguments_missing(self):
        required_arguments = ['arg1', 'arg2']
        args = {}
        with self.assertRaises(ValueError) as context:
            check_required_arguments(required_arguments, args)
        self.assertEqual(str(context.exception), 'Missing required arguments: arg1, arg2')

    @patch.dict('google_alert_center.MESSAGES', {'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Missing required arguments: {}'})
    def test_no_required_arguments(self):
        required_arguments = []
        args = {'arg1': 1, 'arg2': 2}
        try:
            check_required_arguments(required_arguments, args)
        except ValueError:
            self.fail("check_required_arguments raised ValueError unexpectedly when no required arguments were given!")

    def test_successful_alerts_only(self):
        response = {
            'successAlertIds': ['123', '456'],
            'failedAlertStatus': {}
        }
        expected_success_list = [
            {'id': '123', 'status': 'Success'},
            {'id': '456', 'status': 'Success'}
        ]
        expected_failed_list = []

        success_list, failed_list = create_custom_context_for_batch_command(response)

        self.assertEqual(success_list, expected_success_list)
        self.assertEqual(failed_list, expected_failed_list)

    def test_failed_alerts_only(self):
        response = {
            'successAlertIds': [],
            'failedAlertStatus': {
                '789': {'code': '500', 'message': 'Internal Error'},
                '101': {'code': '404', 'message': 'Not Found'}
            }
        }
        expected_success_list = []
        expected_failed_list = [
            {'id': '789', 'status': 'Fail', 'code': '500', 'message': 'Internal Error'},
            {'id': '101', 'status': 'Fail', 'code': '404', 'message': 'Not Found'}
        ]

        success_list, failed_list = create_custom_context_for_batch_command(response)

        self.assertEqual(success_list, expected_success_list)
        self.assertEqual(failed_list, expected_failed_list)

    def test_both_successful_and_failed_alerts(self):
        response = {
            'successAlertIds': ['123'],
            'failedAlertStatus': {
                '456': {'code': '500', 'message': 'Server Error'}
            }
        }
        expected_success_list = [{'id': '123', 'status': 'Success'}]
        expected_failed_list = [
            {'id': '456', 'status': 'Fail', 'code': '500', 'message': 'Server Error'}
        ]

        success_list, failed_list = create_custom_context_for_batch_command(response)

        self.assertEqual(success_list, expected_success_list)
        self.assertEqual(failed_list, expected_failed_list)

    def test_empty_input(self):
        response = {}
        expected_success_list = []
        expected_failed_list = []

        success_list, failed_list = create_custom_context_for_batch_command(response)

        self.assertEqual(success_list, expected_success_list)
        self.assertEqual(failed_list, expected_failed_list)

    def test_valid_json_string(self):
        json_string = '{"key": "value"}'
        result = safe_load_non_strict_json(json_string)
        self.assertEqual(result, {"key": "value"})

    def test_empty_json_string(self):
        json_string = ''
        result = safe_load_non_strict_json(json_string)
        self.assertEqual(result, {})

    def test_invalid_json_string(self):
        json_string = '{"key": "value"'
        with self.assertRaises(ValueError) as context:
            safe_load_non_strict_json(json_string)
        self.assertEqual(str(context.exception), COMMON_MESSAGES['JSON_PARSE_ERROR'])

    @patch('google_alert_center.handle_http_error')  # Adjust the path according to your module
    def test_http_error(self, mock_handle_http_error):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise httplib2.socks.HTTPError("HTTP Error")
        self.assertEqual(str(context.exception), '__enter__')

    @patch('google_alert_center.exceptions.TransportError', side_effect=exceptions.TransportError('ProxyError'))
    def test_transport_error_proxy_error(self, mock_transport_error):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise exceptions.TransportError('ProxyError')
        self.assertEqual(str(context.exception), '__enter__')

    @patch('google_alert_center.exceptions.TransportError', side_effect=exceptions.TransportError('Some other error'))
    def test_transport_error_other(self, mock_transport_error):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise exceptions.TransportError('Some other error')
        self.assertEqual(str(context.exception), '__enter__')

    @patch('google_alert_center.exceptions.RefreshError', side_effect=exceptions.RefreshError('Refresh failed'))
    def test_refresh_error_with_args(self, mock_refresh_error):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise exceptions.RefreshError('Refresh failed')
        self.assertEqual(str(context.exception), '__enter__')

    @patch('google_alert_center.exceptions.RefreshError', side_effect=exceptions.RefreshError())
    def test_refresh_error_without_args(self, mock_refresh_error):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise exceptions.RefreshError()
        self.assertEqual(str(context.exception), '__enter__')

    def test_timeout_error(self):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise TimeoutError('Request timed out')
        self.assertEqual(str(context.exception), '__enter__')

    def test_generic_exception(self):
        with self.assertRaises(Exception) as context:
            with http_exception_handler():
                raise ValueError('Some other error')
        self.assertEqual(str(context.exception), '__enter__')

    @patch('google_alert_center.COMMON_MESSAGES', {
        'PROXY_ERROR': 'Proxy Error occurred',
        'HTTP_ERROR': 'HTTP Error {}: {}'
    })
    def test_proxy_error(self):
        error = httplib2.socks.HTTPError((407, b'Proxy Authentication Required'))
        with self.assertRaises(Exception) as context:
            handle_http_error(error)
        self.assertEqual(str(context.exception), 'Proxy Error occurred')

    @patch('google_alert_center.COMMON_MESSAGES', {
        'PROXY_ERROR': 'Proxy Error occurred',
        'HTTP_ERROR': 'HTTP Error {}: {}'
    })
    def test_http_error2(self):
        error = httplib2.socks.HTTPError((404, b'Not Found'))
        with self.assertRaises(Exception) as context:
            handle_http_error(error)
        self.assertEqual(str(context.exception), 'HTTP Error 404: Not Found')

    @patch('google_alert_center.COMMON_MESSAGES', {
        'PROXY_ERROR': 'Proxy Error occurred',
        'HTTP_ERROR': 'HTTP Error {}: {}'
    })
    def test_no_args(self):
        error = httplib2.socks.HTTPError()
        with self.assertRaises(Exception) as context:
            handle_http_error(error)
        self.assertEqual(str(context.exception), str(error))

    @patch('google_alert_center.COMMON_MESSAGES', {
        'PROXY_ERROR': 'Proxy Error occurred',
        'HTTP_ERROR': 'HTTP Error {}: {}'
    })
    def test_no_tuple_in_args(self):
        error = httplib2.socks.HTTPError('Some error')
        with self.assertRaises(Exception) as context:
            handle_http_error(error)
        self.assertEqual(str(context.exception), 'Some error')

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_success_response_200(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=200), '{"data": "value"}')
        mock_safe_load.return_value = {"data": "value"}
        result = validate_and_extract_response(response)
        self.assertEqual(result, {"data": "value"})

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_success_response_204(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=204), '')
        mock_safe_load.return_value = {}
        result = validate_and_extract_response(response)
        self.assertEqual(result, {})

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_error_response_400(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=400), '{"error": {"message": "Bad Request"}}')
        mock_safe_load.return_value = {"error": {"message": "Bad Request"}}
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception), COMMON_MESSAGES['BAD_REQUEST_ERROR'].format('Bad Request'))

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_error_response_401(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=401), '{"error": {"message": "Unauthorized"}}')
        mock_safe_load.return_value = {"error": {"message": "Unauthorized"}}
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception), COMMON_MESSAGES['AUTHENTICATION_ERROR'].format('Unauthorized'))

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_error_response_404(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=404), '{"error": {"message": "Not Found"}}')
        mock_safe_load.return_value = {"error": {"message": "Not Found"}}
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception), COMMON_MESSAGES['NOT_FOUND_ERROR'].format('Not Found'))

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_error_response_500(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=500), '{"error": {"message": "Internal Server Error"}}')
        mock_safe_load.return_value = {"error": {"message": "Internal Server Error"}}
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception),
                         COMMON_MESSAGES['INTERNAL_SERVER_ERROR'].format('Internal Server Error'))

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_unexpected_error(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=400), 'Invalid JSON')
        mock_safe_load.side_effect = ValueError
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception),
                         'An error occurred while fetching/submitting the data. Reason: An unexpected '
                         'error occurred.')

    @patch('google_alert_center.safe_load_non_strict_json')
    @patch('google_alert_center.orenctl')
    def test_unknown_error(self, mock_orenctl, mock_safe_load):
        response = (MagicMock(status=999), '{"error": {"message": "Unknown Error"}}')
        mock_safe_load.return_value = {"error": {"message": "Unknown Error"}}
        with self.assertRaises(Exception) as context:
            validate_and_extract_response(response)
        self.assertEqual(str(context.exception), COMMON_MESSAGES['UNKNOWN_ERROR'].format(999, 'Unknown Error'))

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.AuthorizedHttp')
    @patch('google_alert_center.get_http_client')
    def test_set_authorized_http(self, mock_get_http_client, mock_authorized_http, mock_google_alert_center):
        mock_gac_instance = MagicMock()
        mock_google_alert_center.return_value = mock_gac_instance

        mock_gac_instance.credentials = MagicMock()
        mock_get_http_client.return_value = 'mock_http_client'
        mock_authorized_http.return_value = MagicMock()

        scopes = ['scope1', 'scope2']
        subject = 'subject'
        timeout = 30

        set_authorized_http(scopes, subject, timeout)

        mock_google_alert_center.assert_called_once_with(None)

        mock_authorized_http.assert_called_once_with(
            credentials=mock_gac_instance.credentials,
            http='mock_http_client'
        )

        self.assertEqual(mock_gac_instance.authorized_http, mock_authorized_http.return_value)

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.AuthorizedHttp')
    @patch('google_alert_center.get_http_client')
    def test_set_authorized_http_with_no_subject(self, mock_get_http_client, mock_authorized_http,
                                                 mock_google_alert_center):
        mock_gac_instance = MagicMock()
        mock_google_alert_center.return_value = mock_gac_instance

        mock_gac_instance.credentials = MagicMock()
        mock_get_http_client.return_value = 'mock_http_client'
        mock_authorized_http.return_value = MagicMock()

        scopes = ['scope1', 'scope2']
        timeout = 30

        set_authorized_http(scopes, timeout=timeout)

        mock_google_alert_center.assert_called_once_with(None)

        mock_authorized_http.assert_called_once_with(
            credentials=mock_gac_instance.credentials,
            http='mock_http_client'
        )

        self.assertEqual(mock_gac_instance.authorized_http, mock_authorized_http.return_value)

    @patch('google_alert_center.handle_proxy')
    @patch('httplib2.Http')
    def test_get_http_client_with_proxy(self, mock_http, mock_handle_proxy):
        # Arrange
        mock_handle_proxy.return_value = {
            'https': 'http://proxyuser:proxypass@proxyhost:proxyport'
        }
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        proxy = False
        verify = True
        timeout = 30

        client = get_http_client(proxy, verify, timeout)

        mock_http.assert_called_once_with(
            proxy_info={},
            disable_ssl_certificate_validation=not verify,
            timeout=timeout
        )
        self.assertEqual(client, mock_http_instance)

    @patch('google_alert_center.handle_proxy')
    @patch('httplib2.Http')
    def test_get_http_client_without_proxy(self, mock_http, mock_handle_proxy):
        # Arrange
        mock_handle_proxy.return_value = {}
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        proxy = False
        verify = True
        timeout = 30

        # Act
        client = get_http_client(proxy, verify, timeout)

        # Assert
        mock_http.assert_called_once_with(
            proxy_info={},
            disable_ssl_certificate_validation=not verify,
            timeout=timeout
        )
        self.assertEqual(client, mock_http_instance)

    @patch('google_alert_center.handle_proxy')
    @patch('httplib2.Http')
    def test_get_http_client_with_invalid_proxy(self, mock_http, mock_handle_proxy):
        # Arrange
        mock_handle_proxy.return_value = {
            'https': 'proxyhost:proxyport'  # Missing scheme
        }
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance

        proxy = False
        verify = True
        timeout = 30

        client = get_http_client(proxy, verify, timeout)

        mock_http.assert_called_once_with(
            proxy_info={},
            disable_ssl_certificate_validation=not verify,
            timeout=timeout
        )
        self.assertEqual(client, mock_http_instance)

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.set_authorized_http')
    @patch('google_alert_center.orenctl')
    @patch('google_alert_center.validate_params_for_list_alerts')
    @patch('google_alert_center.remove_empty_entities')
    def test_gsac_list_alerts_command(self, mock_remove_empty_entities, mock_validate_params_for_list_alerts,
                                      mock_orenctl, mock_set_authorized_http, mock_GoogleAlertCenter):
        mock_gac_instance = MagicMock()
        mock_GoogleAlertCenter.return_value = mock_gac_instance

        mock_response = {
            'alerts': [{'id': 1, 'name': 'Alert1'}, {'id': 2, 'name': 'Alert2'}],
            'nextPageToken': 'token123'
        }
        mock_gac_instance.http_request.return_value = mock_response

        mock_validate_params_for_list_alerts.return_value = {'param1': 'value1'}

        mock_orenctl.getArg.return_value = 'admin@example.com'
        mock_orenctl.results = MagicMock()

        mock_remove_empty_entities.return_value = {
            'GSuiteSecurityAlert.Alert(val.alertId == obj.alertId)': [{'id': 1, 'name': 'Alert1'},
                                                                      {'id': 2, 'name': 'Alert2'}],
            'GSuiteSecurityAlert.PageToken.Alert(val.name == val.name)': {'name': 'gsac-alert-list',
                                                                          'nextPageToken': 'token123'}
        }

        gsac_list_alerts_command()

        mock_orenctl.results.assert_called_once_with({
            "outputs": {
                'GSuiteSecurityAlert.Alert(val.alertId == obj.alertId)': [{'id': 1, 'name': 'Alert1'},
                                                                          {'id': 2, 'name': 'Alert2'}],
                'GSuiteSecurityAlert.PageToken.Alert(val.name == val.name)': {'name': 'gsac-alert-list',
                                                                              'nextPageToken': 'token123'}
            },
            "raw_response": mock_response
        })

        mock_set_authorized_http.assert_called_once_with(scopes=['https://www.googleapis.com/auth/apps.alerts'],
                                                         subject='admin@example.com')
        mock_GoogleAlertCenter.assert_called_once_with(None)
        mock_validate_params_for_list_alerts.assert_called_once()
        mock_remove_empty_entities.assert_called_once_with({
            'GSuiteSecurityAlert.Alert(val.alertId == obj.alertId)': [{'id': 1, 'name': 'Alert1'},
                                                                      {'id': 2, 'name': 'Alert2'}],
            'GSuiteSecurityAlert.PageToken.Alert(val.name == val.name)': {'name': 'gsac-alert-list',
                                                                          'nextPageToken': 'token123'}
        })

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.set_authorized_http')
    @patch('google_alert_center.orenctl')
    @patch('google_alert_center.remove_empty_entities')
    def test_gsac_get_alert_command(self, mock_remove_empty_entities, mock_orenctl, mock_set_authorized_http,
                                    mock_GoogleAlertCenter):
        mock_gac_instance = MagicMock()
        mock_GoogleAlertCenter.return_value = mock_gac_instance

        mock_response = {'alertId': '123', 'name': 'AlertName'}
        mock_gac_instance.http_request.return_value = mock_response

        mock_remove_empty_entities.return_value = {'GSuiteSecurityAlert.Alert': {'alertId': '123', 'name': 'AlertName'}}

        mock_orenctl.getArg.side_effect = lambda key: {'admin_email': 'admin@example.com', 'alert_id': '123'}.get(key,
                                                                                                                  '')
        mock_orenctl.results = MagicMock()

        gsac_get_alert_command()

        mock_orenctl.results.assert_called_once_with({
            "outputs_prefix": 'GSuiteSecurityAlert.Alert',
            "outputs_key_field": 'alertId',
            "outputs": {'GSuiteSecurityAlert.Alert': {'alertId': '123', 'name': 'AlertName'}},
            "raw_response": mock_response
        })

        mock_set_authorized_http.assert_called_once_with(scopes=['https://www.googleapis.com/auth/apps.alerts'],
                                                         subject='admin@example.com')
        mock_GoogleAlertCenter.assert_called_once_with(None)
        mock_remove_empty_entities.assert_called_once_with(mock_response)

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.set_authorized_http')
    @patch('google_alert_center.orenctl')
    def test_gsac_get_alert_command_no_response(self, mock_orenctl, mock_set_authorized_http, mock_GoogleAlertCenter):
        mock_gac_instance = MagicMock()
        mock_GoogleAlertCenter.return_value = mock_gac_instance

        mock_gac_instance.http_request.return_value = None

        mock_orenctl.getArg.side_effect = lambda key: {'admin_email': 'admin@example.com', 'alert_id': '123'}.get(key,
                                                                                                                  '')
        mock_orenctl.results = MagicMock()

        gsac_get_alert_command()

        mock_set_authorized_http.assert_called_once_with(scopes=['https://www.googleapis.com/auth/apps.alerts'],
                                                         subject='admin@example.com')
        mock_GoogleAlertCenter.assert_called_once_with(None)

    @patch('google_alert_center.GoogleAlertCenter')
    @patch('google_alert_center.set_authorized_http')
    @patch('google_alert_center.orenctl')
    @patch('google_alert_center.remove_empty_entities')
    def test_gsac_create_alert_feedback_command_success(self, mock_remove_empty_entities, mock_orenctl,
                                                        mock_set_authorized_http, mock_GoogleAlertCenter):
        mock_gac_instance = MagicMock()
        mock_GoogleAlertCenter.return_value = mock_gac_instance

        mock_create_feedback_response = {'feedbackId': '123', 'status': 'success'}
        mock_gac_instance.http_request.return_value = mock_create_feedback_response

        mock_remove_empty_entities.return_value = {'feedbackId': '123', 'status': 'success'}

        mock_orenctl.getArg.side_effect = lambda key: {'admin_email': 'admin@example.com', 'alert_id': '456',
                                                       'feedback_type': 'not_useful'}.get(key, '')
        mock_orenctl.results = MagicMock()

        gsac_create_alert_feedback_command()

        mock_orenctl.results.assert_called_once_with({
            "outputs_prefix": 'GSuiteSecurityAlert.Feedback',
            "outputs_key_field": 'feedbackId',
            "outputs": {'feedbackId': '123', 'status': 'success'},
            "raw_response": mock_create_feedback_response
        })

        mock_set_authorized_http.assert_called_once_with(scopes=['https://www.googleapis.com/auth/apps.alerts'],
                                                         subject='admin@example.com')
        mock_GoogleAlertCenter.assert_called_once_with(None)
        mock_remove_empty_entities.assert_called_once_with(mock_create_feedback_response)

    @patch('google_alert_center.GoogleAlertCenter')  # Replace with actual module path
    @patch('google_alert_center.orenctl.getArg')
    @patch('google_alert_center.validate_get_int')
    @patch('google_alert_center.set_authorized_http')
    def test_gsac_list_alert_feedback_command(self, mock_set_authorized_http, mock_validate_get_int, mock_getArg,
                                              MockGoogleAlertCenter):
        mock_getArg.side_effect = lambda x: {
            'alert_id': '12345',
            'filter': "example_filter",
            'admin_email': 'admin@example.com',
            'page_size': '10'
        }.get(x, None)

        mock_validate_get_int.return_value = 10  # Mocking page size validation

        mock_gac_instance = MockGoogleAlertCenter.return_value
        mock_gac_instance.http_request.return_value = {
            'feedback': [
                {'feedbackId': '1', 'details': 'Feedback 1'},
                {'feedbackId': '2', 'details': 'Feedback 2'}
            ]
        }

        gsac_list_alert_feedback_command()

        mock_set_authorized_http.assert_called_once_with(
            scopes=['https://www.googleapis.com/auth/apps.alerts'], subject='admin@example.com'
        )
        mock_gac_instance.http_request.assert_called_once_with(
            url_suffix='v1beta1/alerts/12345/feedback',
            method='GET',
            params={'filter': 'example_filter'}
        )

    @patch('google_alert_center.GoogleAlertCenter')  # Replace with actual module path
    @patch('google_alert_center.orenctl.getArg')
    @patch('google_alert_center.set_authorized_http')
    @patch('google_alert_center.create_custom_context_for_batch_command')
    @patch('google_alert_center.remove_empty_entities')
    def test_gsac_batch_recover_alerts_command(self, mock_remove_empty_entities, mock_create_custom_context,
                                               mock_set_authorized_http, mock_getArg, MockGoogleAlertCenter):
        # Setup mocks
        mock_getArg.side_effect = lambda x: {
            'alert_id': '12345,67890',
            'admin_email': 'admin@example.com'
        }.get(x, None)

        mock_gac_instance = MockGoogleAlertCenter.return_value
        mock_gac_instance.http_request.return_value = {
            'result': 'success',
            'details': 'Batch recovery complete'
        }

        mock_create_custom_context.return_value = (
            [{'alertId': '12345', 'status': 'recovered'}],
            [{'alertId': '67890', 'status': 'failed'}]
        )

        mock_remove_empty_entities.return_value = {
            'success': [{'alertId': '12345', 'status': 'recovered'}],
            'failed': [{'alertId': '67890', 'status': 'failed'}]
        }

        # Call the function
        gsac_batch_recover_alerts_command()

        # Check results
        mock_set_authorized_http.assert_called_once_with(
            scopes=['https://www.googleapis.com/auth/apps.alerts'], subject='admin@example.com'
        )
        mock_gac_instance.http_request.assert_called_once_with(
            url_suffix='v1beta1/alerts:batchUndelete',
            method='POST',
            body={'alertId': ['12345', '67890']}
        )
        mock_create_custom_context.assert_called_once_with({
            'result': 'success',
            'details': 'Batch recovery complete'
        })
        mock_remove_empty_entities.assert_called_once_with({
            'GSuiteSecurityAlert.Recover.successAlerts(val.id && val.id == obj.id)': [
                {'alertId': '12345', 'status': 'recovered'}],
            'GSuiteSecurityAlert.Recover.failedAlerts(val.id && val.id == obj.id)': [
                {'alertId': '67890', 'status': 'failed'}]})
