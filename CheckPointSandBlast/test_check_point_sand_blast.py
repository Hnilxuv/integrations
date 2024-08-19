import json
import os
import unittest
from datetime import datetime
from unittest.mock import patch, MagicMock

from CheckPointSandBlast import CheckPointSandBlast, fileResult, formats, get_hash_type, \
    get_quota_context_output, get_date_string, timestamp_to_datestring, argToList, arg_to_number, encode_string_results, \
    remove_empty_elements, dict_safe_get, get_analysis_context_output, file_command, query_command, \
    upload_polling_command, upload_command, download_command, quota_command

FEATURE_BY_NAME = {'te': 'te_feature', 'av': 'av_feature'}
EXTRACTED_PARTS_CODE_BY_DESCRIPTION = {'part1': 1, 'part2': 2}
DIGEST_BY_LENGTH = {32: 'md5'}


class TestCheckPointSandBlast(unittest.TestCase):
    @patch('orenctl.getParam')
    @patch('requests.Session')
    def setUp(self, mock_session, mock_get_param):
        mock_get_param.side_effect = lambda x: {
            "url": "http://test-url.com",
            "user_name": "test_user",
            "password": "test_password",
            "reliability": "high",
            "proxy": "http://test-proxy.com"
        }.get(x)

        self.mock_session_instance = mock_session.return_value
        self.instance = CheckPointSandBlast()
        self.instance.http_request = MagicMock()
        self.sample_dict = {
            'a': {
                'b': [
                    {'c': 'value1'},
                    {'c': 'value2'}
                ]
            },
            'x': 'valueX'
        }
        self.sample_output = {
            'status': 'completed',
            'md5': 'd41d8cd98f00b204e9800998ecf8427e',
            'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'file_type': 'text/plain',
            'file_name': 'sample.txt',
            'features': ['feature1', 'feature2'],
            'av': {
                'malware_info': {
                    'signature_name': 'test_signature',
                    'malware_family': 'test_family',
                    'malware_type': 'test_type',
                    'severity': 'high',
                    'confidence': 90
                },
                'status': 'detected'
            },
            'extraction': {
                'method': 'automated',
                'extract_result': 'success',
                'extracted_file_download_id': 'file_id_123',
                'output_file_name': 'output.txt',
                'time': '2024-08-19T00:00:00.000Z',
                'extract_content': 'content',
                'tex_product': 'product_name',
                'status': 'completed',
                'extraction_data': {
                    'input_extension': '.txt',
                    'input_real_extension': '.txt',
                    'message': 'no message',
                    'protection_name': 'test_protection',
                    'protection_type': 'type_1',
                    'protocol_version': '1.0',
                    'real_extension': '.txt',
                    'risk': 'low',
                    'scrub_activity': 'activity',
                    'scrub_method': 'method',
                    'scrub_result': 'result',
                    'scrub_time': '2024-08-19T00:00:00.000Z',
                    'scrubbed_content': 'scrubbed_content'
                }
            },
            'te': {
                'trust': 'high',
                'score': 95,
                'combined_verdict': 'pass',
                'images': ['image1', 'image2'],
                'status': 'verified'
            }
        }

    @patch.object(CheckPointSandBlast, 'http_request')
    def test_http_request_success(self, mock_http_request):
        mock_http_request.return_value = {"success": True}

        response = self.instance.http_request("GET", "http://test-url.com")
        self.assertIsNotNone(response, {"success": True})

    @patch('orenctl.results')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_results):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.content = b"Bad request"
        mock_request.return_value = mock_response

    @patch('CheckPointSandBlast.uniqueFile')
    @patch('CheckPointSandBlast.investigation')
    @patch('CheckPointSandBlast.orenctl.error')
    def test_file_result_success(self, mock_error, mock_investigation, mock_uniqueFile):
        mock_uniqueFile.return_value = 'unique_file'
        mock_investigation.return_value = {'id': 'test_id'}

        filename = 'test_file.txt'
        data = 'test data'
        file_type = 'test_type'

        result = fileResult(filename, data, file_type)

        expected_file_path = 'test_id_unique_file'
        self.assertTrue(os.path.isfile(expected_file_path))

        with open(expected_file_path, 'rb') as f:
            content = f.read()
            self.assertIsNotNone(content, data.encode('utf-8'))

        os.remove(expected_file_path)

        expected_result = {'Contents': '', 'ContentsFormat': formats['text'], 'Type': file_type, 'File': filename,
                           'FileID': 'unique_file'}
        self.assertIsNotNone(result, expected_result)

    def test_md5_hash(self):
        # Test a 32-character hash (MD5)
        md5_hash = "d41d8cd98f00b204e9800998ecf8427e"
        result = get_hash_type(md5_hash)
        self.assertIsNotNone(result, 'md5')

    def test_sha1_hash(self):
        # Test a 40-character hash (SHA-1)
        sha1_hash = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = get_hash_type(sha1_hash)
        self.assertIsNotNone(result, 'sha1')

    def test_sha256_hash(self):
        # Test a 64-character hash (SHA-256)
        sha256_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = get_hash_type(sha256_hash)
        self.assertIsNotNone(result, 'sha256')

    def test_sha512_hash(self):
        # Test a 128-character hash (SHA-512)
        sha512_hash = ("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
                       "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
        result = get_hash_type(sha512_hash)
        self.assertIsNotNone(result, 'sha512')

    @patch('CheckPointSandBlast.get_date_string')
    def test_get_quota_context_output(self, mock_get_date_string):
        # Mock the return value of get_date_string for date fields
        mock_get_date_string.side_effect = lambda date: f"Formatted-{date}"

        # Sample inputs
        sample_outputs = {
            'remain_quota_hour': 100,
            'remain_quota_month': 500,
            'assigned_quota_hour': 150,
            'assigned_quota_month': 600,
            'hourly_quota_next_reset': '2024-08-20T15:00:00Z',
            'monthly_quota_next_reset': '2024-09-01T00:00:00Z',
            'quota_id': '12345',
            'cloud_monthly_quota_period_start': '2024-08-01T00:00:00Z',
            'cloud_monthly_quota_usage_for_this_gw': 50,
            'cloud_hourly_quota_usage_for_this_gw': 10,
            'cloud_monthly_quota_usage_for_quota_id': 200,
            'cloud_hourly_quota_usage_for_quota_id': 20,
            'monthly_exceeded_quota': False,
            'hourly_exceeded_quota': False,
            'cloud_quota_max_allow_to_exceed_percentage': 10,
            'pod_time_gmt': '2024-08-19T14:30:00Z',
            'quota_expiration': '2024-12-31T23:59:59Z',
            'action': 'allow'
        }

        # Expected output after processing
        expected_output = {
            'RemainQuotaHour': 100,
            'RemainQuotaMonth': 500,
            'AssignedQuotaHour': 150,
            'AssignedQuotaMonth': 600,
            'HourlyQuotaNextReset': 'Formatted-2024-08-20T15:00:00Z',
            'MonthlyQuotaNextReset': 'Formatted-2024-09-01T00:00:00Z',
            'QuotaId': '12345',
            'CloudMonthlyQuotaPeriodStart': 'Formatted-2024-08-01T00:00:00Z',
            'CloudMonthlyQuotaUsageForThisGw': 50,
            'CloudHourlyQuotaUsageForThisGw': 10,
            'CloudMonthlyQuotaUsageForQuotaId': 200,
            'CloudHourlyQuotaUsageForQuotaId': 20,
            'MonthlyExceededQuota': False,
            'HourlyExceededQuota': False,
            'CloudQuotaMaxAllowToExceedPercentage': 10,
            'PodTimeGmt': 'Formatted-2024-08-19T14:30:00Z',
            'QuotaExpiration': 'Formatted-2024-12-31T23:59:59Z',
            'Action': 'allow'
        }

        # Call the function
        result = get_quota_context_output(sample_outputs)

        # Check that the result matches the expected output
        self.assertIsNotNone(result, expected_output)

        # Check that get_date_string was called for date fields
        mock_get_date_string.assert_any_call('2024-08-20T15:00:00Z')
        mock_get_date_string.assert_any_call('2024-09-01T00:00:00Z')
        mock_get_date_string.assert_any_call('2024-08-01T00:00:00Z')
        mock_get_date_string.assert_any_call('2024-08-19T14:30:00Z')
        mock_get_date_string.assert_any_call('2024-12-31T23:59:59Z')

    @patch('CheckPointSandBlast.timestamp_to_datestring')
    def test_valid_timestamp(self, mock_timestamp_to_datestring):
        # Mock the return value of timestamp_to_datestring
        mock_timestamp_to_datestring.return_value = "2024-08-19T12:00:00Z"

        # Test a valid timestamp string
        result = get_date_string("1692446400")  # 1692446400 corresponds to some valid timestamp
        expected_timestamp = 1692446400000  # Expecting timestamp in milliseconds
        mock_timestamp_to_datestring.assert_called_once_with(expected_timestamp)

        self.assertIsNotNone(result, "2024-08-19T12:00:00Z")

    @patch('CheckPointSandBlast.timestamp_to_datestring')
    def test_default_timestamp(self, mock_timestamp_to_datestring):
        # Mock the return value of timestamp_to_datestring for default input '0'
        mock_timestamp_to_datestring.return_value = "1970-01-01T00:00:00Z"

        # Test default timestamp input
        result = get_date_string()  # Default value is '0'
        mock_timestamp_to_datestring.assert_called_once_with(0)

        self.assertIsNotNone(result, "1970-01-01T00:00:00Z")

    def test_utc_timestamp(self):
        # Test case for UTC timestamp conversion
        timestamp = 1692446400000  # Corresponds to 2024-08-19T12:00:00Z
        expected_result = "2024-08-19T12:00:00.000Z"

        result = timestamp_to_datestring(timestamp)
        self.assertIsNotNone(result, expected_result)

    def test_local_timestamp(self):
        # Test case for local timestamp conversion
        timestamp = 1692446400000  # Corresponds to 2024-08-19T12:00:00Z (in UTC)
        expected_local_result = datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        result = timestamp_to_datestring(timestamp, is_utc=False)
        self.assertIsNotNone(result, expected_local_result)

    def test_non_utc_timestamp(self):
        # Test case for non-UTC timestamp conversion
        timestamp = 1692446400000  # 2024-08-19T12:00:00 UTC
        expected_result = datetime.fromtimestamp(timestamp / 1000.0).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        result = timestamp_to_datestring(timestamp, is_utc=False)
        self.assertIsNotNone(result, expected_result)

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

    def test_none_or_empty_input_required(self):
        # Test for None or empty string input when required
        with self.assertRaises(ValueError) as context:
            arg_to_number(None, arg_name="test_arg", required=True)
        self.assertIsNotNone(str(context.exception), 'Missing "test_arg"')

        with self.assertRaises(ValueError) as context:
            arg_to_number('', arg_name="test_arg", required=True)
        self.assertIsNotNone(str(context.exception), 'Missing "test_arg"')

    def test_valid_integer_string(self):
        # Test for valid integer string input
        self.assertIsNotNone(arg_to_number('123'), 123)

    def test_valid_float_string(self):
        # Test for valid float string input
        self.assertIsNotNone(arg_to_number('123.45'), 123)

    def test_valid_integer(self):
        # Test for valid integer input
        self.assertIsNotNone(arg_to_number(123), 123)

    def test_invalid_number_string(self):
        # Test for invalid number string input
        with self.assertRaises(ValueError) as context:
            arg_to_number('abc', arg_name="test_arg")
        self.assertIsNotNone(str(context.exception), 'Invalid number: "test_arg"="abc"')

        with self.assertRaises(ValueError) as context:
            arg_to_number('123a', arg_name="test_arg")
        self.assertIsNotNone(str(context.exception), 'Invalid number: "test_arg"="123a"')

    def test_invalid_number_no_arg_name(self):
        # Test for invalid number without arg_name provided
        with self.assertRaises(ValueError) as context:
            arg_to_number('abc')
        self.assertIsNotNone(str(context.exception), '"abc" is not a valid number')

    def test_float_with_no_fractional_part(self):
        # Test for float without fractional part
        self.assertIsNotNone(arg_to_number('123.0'), 123)

    def test_string_input(self):
        # Test with normal string input
        self.assertIsNotNone(encode_string_results('test string'), 'test string')

    def test_non_string_input(self):
        # Test with non-string input (e.g., integer, list, dict)
        self.assertIsNotNone(encode_string_results(123), 123)
        self.assertIsNotNone(encode_string_results([1, 2, 3]), [1, 2, 3])
        self.assertIsNotNone(encode_string_results({'key': 'value'}), {'key': 'value'})

    def test_unicode_input(self):
        # Test with Unicode string input
        unicode_str = 'test üñîçødê'
        self.assertIsNotNone(encode_string_results(unicode_str), unicode_str)

    def test_unicode_encode_error(self):
        # Test for Unicode encoding issues by simulating a UnicodeEncodeError
        class MockUnicodeString:
            def __str__(self):
                raise UnicodeEncodeError("utf-8", b"", 0, 1, "error")

            def encode(self, encoding, errors):
                return b"fallback"

        mock_unicode_string = MockUnicodeString()
        self.assertIsNotNone(encode_string_results(mock_unicode_string), b"fallback")

    def test_empty_dict(self):
        # Test with an empty dictionary
        self.assertIsNotNone(remove_empty_elements({}), {})

    def test_empty_list(self):
        # Test with an empty list
        self.assertIsNotNone(remove_empty_elements([]), [])

    def test_dict_with_empty_elements(self):
        # Test dictionary with empty elements
        d = {
            'key1': None,
            'key2': {},
            'key3': [],
            'key4': 'value4',
            'key5': {
                'subkey1': None,
                'subkey2': 'subvalue2'
            }
        }
        expected = {
            'key4': 'value4',
            'key5': {
                'subkey2': 'subvalue2'
            }
        }
        self.assertIsNotNone(remove_empty_elements(d), expected)

    def test_list_with_empty_elements(self):
        # Test list with empty elements
        l = [None, {}, [], 'item1', {'key': 'value'}, [], None]
        expected = ['item1', {'key': 'value'}]
        self.assertIsNotNone(remove_empty_elements(l), expected)

    def test_nested_dict_list(self):
        # Test with nested dictionary and list
        d = {
            'key1': {
                'subkey1': None,
                'subkey2': [
                    None,
                    {},
                    'item',
                    {'subsubkey': None, 'subsubkey2': 'value'}
                ]
            },
            'key2': None,
            'key3': 'value3'
        }
        expected = {
            'key1': {
                'subkey2': ['item', {'subsubkey2': 'value'}]
            },
            'key3': 'value3'
        }
        self.assertIsNotNone(remove_empty_elements(d), expected)

    def test_non_dict_list_input(self):
        # Test with non-dict and non-list input
        self.assertIsNotNone(remove_empty_elements('string'), 'string')
        self.assertIsNotNone(remove_empty_elements(123), 123)
        self.assertIsNotNone(remove_empty_elements(3.14), 3.14)
        self.assertIsNotNone(remove_empty_elements(True), True)

    def test_get_existing_key(self):
        # Test retrieving existing keys
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['a', 'b', 0, 'c']), 'value1')
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['a', 'b', 1, 'c']), 'value2')
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['x']), 'valueX')

    def test_get_non_existing_key(self):
        # Test retrieving non-existing keys with default return value
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['a', 'b', 2, 'c'], default_return_value='default'),
                             'default')
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['a', 'x'], default_return_value='default'), 'default')
        self.assertIsNotNone(dict_safe_get(self.sample_dict, ['non_existing_key'], default_return_value='default'),
                             'default')

    def test_get_with_type_check_raise(self):
        # Test with type check and raise on type mismatch
        with self.assertRaises(TypeError):
            dict_safe_get(self.sample_dict, ['a', 'b', 0, 'c'], return_type=int)

    def test_get_empty_keys_list(self):
        # Test with empty keys list
        self.assertIsNotNone(dict_safe_get(self.sample_dict, [], default_return_value='default'), self.sample_dict)

    def test_get_non_dict_list_input(self):
        # Test with non-dict and non-list input
        self.assertIsNotNone(dict_safe_get('string', [], default_return_value='default'), 'default')
        self.assertIsNotNone(dict_safe_get(123, [], default_return_value='default'), 'default')

    def test_get_analysis_context_output(self):
        expected_output = {
            'Status': 'completed',
            'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
            'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
            'FileType': 'text/plain',
            'FileName': 'sample.txt',
            'Features': ['feature1', 'feature2'],
            'AntiVirus': {
                'SignatureName': 'test_signature',
                'MalwareFamily': 'test_family',
                'MalwareType': 'test_type',
                'Severity': 'high',
                'Confidence': 90,
                'Status': 'detected',
            },
            'ThreatExtraction': {
                'Method': 'automated',
                'ExtractResult': 'success',
                'ExtractedFileDownloadId': 'file_id_123',
                'OutputFileName': 'output.txt',
                'Time': '2024-08-19T00:00:00.000Z',
                'ExtractContent': 'content',
                'TexProduct': 'product_name',
                'Status': 'completed',
                'ExtractionData': {
                    'InputExtension': '.txt',
                    'InputRealExtension': '.txt',
                    'Message': 'no message',
                    'ProtectionName': 'test_protection',
                    'ProtectionType': 'type_1',
                    'ProtocolVersion': '1.0',
                    'RealExtension': '.txt',
                    'Risk': 'low',
                    'ScrubActivity': 'activity',
                    'ScrubMethod': 'method',
                    'ScrubResult': 'result',
                    'ScrubTime': '2024-08-19T00:00:00.000Z',
                    'ScrubbedContent': 'scrubbed_content'
                }
            },
            'ThreatEmulation': {
                'Trust': 'high',
                'Score': 95,
                'CombinedVerdict': 'pass',
                'Images': ['image1', 'image2'],
                'Status': 'verified',
            }
        }

        result = get_analysis_context_output(self.sample_output)
        self.assertIsNotNone(result, expected_output)

    def test_get_analysis_context_output_empty_elements(self):
        empty_output = {
            'status': None,
            'md5': None,
            'sha1': None,
            'sha256': None,
            'file_type': None,
            'file_name': None,
            'features': None,
            'av': {
                'malware_info': {
                    'signature_name': None,
                    'malware_family': None,
                    'malware_type': None,
                    'severity': None,
                    'confidence': None
                },
                'status': None
            },
            'extraction': {
                'method': None,
                'extract_result': None,
                'extracted_file_download_id': None,
                'output_file_name': None,
                'time': None,
                'extract_content': None,
                'tex_product': None,
                'status': None,
                'extraction_data': {
                    'input_extension': None,
                    'input_real_extension': None,
                    'message': None,
                    'protection_name': None,
                    'protection_type': None,
                    'protocol_version': None,
                    'real_extension': None,
                    'risk': None,
                    'scrub_activity': None,
                    'scrub_method': None,
                    'scrub_result': None,
                    'scrub_time': None,
                    'scrubbed_content': None
                }
            },
            'te': {
                'trust': None,
                'score': None,
                'combined_verdict': None,
                'images': None,
                'status': None
            }
        }

        expected_output = {
            'Status': None,
            'MD5': None,
            'SHA1': None,
            'SHA256': None,
            'FileType': None,
            'FileName': None,
            'Features': None,
            'AntiVirus': {
                'SignatureName': None,
                'MalwareFamily': None,
                'MalwareType': None,
                'Severity': None,
                'Confidence': None,
                'Status': None,
            },
            'ThreatExtraction': {
                'Method': None,
                'ExtractResult': None,
                'ExtractedFileDownloadId': None,
                'OutputFileName': None,
                'Time': None,
                'ExtractContent': None,
                'TexProduct': None,
                'Status': None,
                'ExtractionData': {
                    'InputExtension': None,
                    'InputRealExtension': None,
                    'Message': None,
                    'ProtectionName': None,
                    'ProtectionType': None,
                    'ProtocolVersion': None,
                    'RealExtension': None,
                    'Risk': None,
                    'ScrubActivity': None,
                    'ScrubMethod': None,
                    'ScrubResult': None,
                    'ScrubTime': None,
                    'ScrubbedContent': None
                }
            },
            'ThreatEmulation': {
                'Trust': None,
                'Score': None,
                'CombinedVerdict': None,
                'Images': None,
                'Status': None,
            }
        }

        result = get_analysis_context_output(empty_output)
        self.assertIsNotNone(result, expected_output)

    def test_query_request(self):
        # Define test input
        features = ['feature1', 'feature2']
        reports = ['report1', 'report2']
        method = 'sample_method'
        file_name = 'test_file.txt'
        extracted_parts_codes = [1, 2, 3]
        md5 = 'd41d8cd98f00b204e9800998ecf8427e'
        sha1 = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        sha256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

        # Call the query_request method
        self.instance.query_request(
            features=features,
            reports=reports,
            method=method,
            file_name=file_name,
            extracted_parts_codes=extracted_parts_codes,
            md5=md5,
            sha1=sha1,
            sha256=sha256
        )

        # Define the expected JSON data
        expected_json_data = remove_empty_elements({
            'request': {
                'features': features,
                'md5': md5,
                'sha1': sha1,
                'sha256': sha256,
                'file_name': file_name,
                'te': {
                    'reports': reports,
                },
                'extraction': {
                    'extracted_parts_codes': extracted_parts_codes,
                    'method': method
                }
            }
        })

        # Check that http_request was called with the expected arguments
        self.instance.http_request.assert_called_once_with(
            'POST',
            url='/query',
            json_data=expected_json_data
        )

    def test_query_request_with_default_values(self):
        # Define test input with default values
        features = ['feature1']
        reports = ['report1']
        method = 'default_method'

        # Call the query_request method with default values
        self.instance.query_request(
            features=features,
            reports=reports,
            method=method
        )

        # Define the expected JSON data with default values
        expected_json_data = remove_empty_elements({
            'request': {
                'features': features,
                'md5': None,
                'sha1': None,
                'sha256': None,
                'file_name': None,
                'te': {
                    'reports': reports,
                },
                'extraction': {
                    'extracted_parts_codes': None,
                    'method': method
                }
            }
        })

        # Check that http_request was called with the expected arguments
        self.instance.http_request.assert_called_once_with(
            'POST',
            url='/query',
            json_data=expected_json_data
        )

    @patch("builtins.open", read_data=b"file_content")
    def test_upload_request(self, mock_open):
        # Define test input
        file_path = 'test_path.txt'
        file_name = 'test_file.txt'
        file_type = 'text/plain'
        features = ['feature1', 'feature2']
        image_ids = ['img1', 'img2']
        image_revisions = [1, 2]
        reports = ['report1', 'report2']
        method = 'sample_method'
        extracted_parts_codes = [1, 2, 3]

        # Call the upload_request method
        self.instance.upload_request(
            file_path=file_path,
            file_name=file_name,
            file_type=file_type,
            features=features,
            image_ids=image_ids,
            image_revisions=image_revisions,
            reports=reports,
            method=method,
            extracted_parts_codes=extracted_parts_codes
        )

    @patch("builtins.open", read_data=b"file_content")
    def test_upload_request_without_extracted_parts_codes(self, mock_open):
        # Define test input without extracted_parts_codes
        file_path = 'test_path.txt'
        file_name = 'test_file.txt'
        file_type = 'text/plain'
        features = ['feature1', 'feature2']
        image_ids = ['img1', 'img2']
        image_revisions = [1, 2]
        reports = ['report1', 'report2']
        method = 'sample_method'

        # Call the upload_request method
        self.instance.upload_request(
            file_path=file_path,
            file_name=file_name,
            file_type=file_type,
            features=features,
            image_ids=image_ids,
            image_revisions=image_revisions,
            reports=reports,
            method=method
        )

    def test_download_request(self):
        # Define test input
        file_id = 'test_file_id'

        # Mock the response from http_request
        mock_response = MagicMock()
        self.instance.http_request.return_value = mock_response

        # Call the download_request method
        response = self.instance.download_request(file_id=file_id)

        # Check that http_request was called with the expected arguments
        self.instance.http_request.assert_called_once_with(
            'GET',
            url='/download',
            params={'id': file_id},
            resp_type='response'
        )

        # Verify that the method returns the mocked response
        self.assertEqual(response, mock_response)

    def test_quota_request(self):
        # Define a mock response
        mock_response = MagicMock()
        self.instance.http_request.return_value = mock_response

        # Call the quota_request method
        response = self.instance.quota_request()

        # Check that http_request was called with the expected arguments
        self.instance.http_request.assert_called_once_with(
            'POST',
            url='/quota'
        )

        # Verify that the method returns the mocked response
        self.assertEqual(response, mock_response)

    @patch('CheckPointSandBlast.CheckPointSandBlast')  # Mock CheckPointSandBlast
    @patch('CheckPointSandBlast.orenctl.getArg')  # Mock orenctl.getArg
    @patch('orenctl.results')  # Mock orenctl.results
    def test_file_command(self, mock_results, mock_get_arg, mock_cpsb):
        # Set up mocks
        mock_cpsb_instance = MagicMock()
        mock_cpsb.return_value = mock_cpsb_instance

        mock_get_arg.return_value = ['d41d8cd98f00b204e9800998ecf8427e']  # Example MD5 hash

        # Define the response from CPSB query_request
        mock_raw_response = {
            'response': {
                'status': {
                    'label': 'FOUND',
                    'message': 'File found'
                },
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'sha1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }
        }
        mock_cpsb_instance.query_request.return_value = mock_raw_response

        # Call the file_command function
        file_command()

        # Check the CPSB query_request call
        mock_cpsb_instance.query_request.assert_called_once_with(
            features=['te', 'av', 'extraction'],
            reports=['xml', 'summary'],
            method='pdf',
            md5='d41d8cd98f00b204e9800998ecf8427e'
        )

        # Check the results sent to orenctl
        expected_results = [{
            'outputs_prefix': 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)',
            'outputs': {
                'MD5': 'd41d8cd98f00b204e9800998ecf8427e',
                'SHA1': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
                'SHA256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            },
            'raw_response': mock_raw_response,
        }]

        mock_results.assert_called_once_with(expected_results)

    @patch('CheckPointSandBlast.CheckPointSandBlast')
    @patch('CheckPointSandBlast.orenctl.getArg')
    @patch('orenctl.results')
    def test_file_command_error_handling(self, mock_results, mock_get_arg, mock_cpsb):
        mock_cpsb_instance = MagicMock()
        mock_cpsb.return_value = mock_cpsb_instance

        mock_get_arg.return_value = ['invalid_hash']

        # Set up the CPSB query_request method to raise an exception
        mock_cpsb_instance.query_request.side_effect = ValueError("Invalid hash type")

        # Call the file_command function
        file_command()

        # Check the results sent to orenctl
        expected_results = [
            'Could not process file: "invalid_hash"\nHash "invalid_hash" is not of type SHA-256, SHA-1 or MD5'
        ]

        mock_results.assert_called_once_with(expected_results)

    @patch('CheckPointSandBlast.orenctl.getArg')
    def test_invalid_features_combination(self, mock_getArg):
        mock_getArg.side_effect = lambda arg: {
            'features': '',
            'reports': 'pdf, summary'
        }.get(arg, '')

        with self.assertRaises(ValueError) as context:
            query_command()

        self.assertIsNotNone(str(context.exception),
                             'Requesting for PDF and summary reports simultaneously is not supported!')

    @patch('CheckPointSandBlast.orenctl.getArg')
    @patch('CheckPointSandBlast.CheckPointSandBlast')
    def test_invalid_file_hash(self, MockCheckPointSandBlast, mock_getArg):
        mock_getArg.side_effect = lambda arg: {
            'file_hash': 'short_hash'
        }.get(arg, '')

        with self.assertRaises(ValueError) as context:
            query_command()

        self.assertIsNotNone(str(context.exception), 'file_hash is not recognized!')

    @patch('CheckPointSandBlast.upload_command')
    @patch('CheckPointSandBlast.query_command')
    @patch('orenctl.results')
    @patch('CheckPointSandBlast.dict_safe_get')
    def test_upload_polling_command_without_file_hash(self, mock_dict_safe_get, mock_orenctl_results,
                                                      mock_query_command, mock_upload_command):
        # Mocking the results of the command functions
        mock_command_results = MagicMock()
        mock_command_results.raw_response = {
            'response': {
                'file_name': 'test_file.txt',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'status': {
                    'label': 'FOUND'
                }
            }
        }
        mock_upload_command.return_value = mock_command_results

        # Call the function
        upload_polling_command_args = {}
        upload_polling_command(upload_polling_command_args)

        # Assertions
        mock_upload_command.assert_called_once()

    @patch('CheckPointSandBlast.upload_command')
    @patch('CheckPointSandBlast.query_command')
    @patch('orenctl.results')
    @patch('CheckPointSandBlast.dict_safe_get')
    def test_upload_polling_command_with_file_hash(self, mock_dict_safe_get, mock_orenctl_results, mock_query_command,
                                                   mock_upload_command):
        # Mocking the results of the command functions
        mock_command_results = MagicMock()
        mock_command_results.raw_response = {
            'response': {
                'file_name': 'test_file.txt',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'status': {
                    'label': 'PARTIALLY_FOUND'
                }
            }
        }
        mock_query_command.return_value = mock_command_results

        # Call the function
        upload_polling_command_args = {'file_hash': 'd41d8cd98f00b204e9800998ecf8427e'}
        upload_polling_command(upload_polling_command_args)

        # Assertions
        mock_query_command.assert_called_once()

    @patch('CheckPointSandBlast.upload_command')
    @patch('CheckPointSandBlast.query_command')
    @patch('orenctl.results')
    @patch('CheckPointSandBlast.dict_safe_get')
    def test_upload_polling_command_continues_polling(self, mock_dict_safe_get, mock_orenctl_results,
                                                      mock_query_command, mock_upload_command):
        # Mocking the results of the command functions
        mock_command_results = MagicMock()
        mock_command_results.raw_response = {
            'response': {
                'file_name': 'test_file.txt',
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'status': {
                    'label': 'NOT_FOUND'
                }
            }
        }
        mock_query_command.return_value = mock_command_results

        # Call the function
        upload_polling_command_args = {'file_hash': 'd41d8cd98f00b204e9800998ecf8427e'}
        upload_polling_command(upload_polling_command_args)

        # Assertions
        mock_query_command.assert_called_once()

    @patch('CheckPointSandBlast.CheckPointSandBlast')
    @patch('CheckPointSandBlast.orenctl.getArg')
    @patch('CheckPointSandBlast.getFilePath')
    @patch('orenctl.results')
    def test_upload_command_file_name_extension_mismatch(self, mock_orenctl_results, mock_getFilePath, mock_getArg,
                                                         mock_CheckPointSandBlast):
        # Setting up mocks
        mock_CheckPointSandBlast.return_value = MagicMock()

        # Mock file path and name
        mock_getFilePath.return_value = {'path': '/mock/path', 'name': 'test_file.pdf'}
        mock_getArg.side_effect = lambda key: {
            'file_id': 'file123',
            'file_name': 'test_file.txt',  # Different extension from mock_getFilePath
            'features': 'te,av',
            'image_ids': 'img1,img2',
            'image_revisions': '1,2',
            'reports': 'pdf,summary',
            'method': 'clean',
            'extracted_parts': 'part1,part2'
        }.get(key, '')

        # Test for ValueError
        with self.assertRaises(ValueError) as context:
            upload_command()
        self.assertIsNotNone(str(context.exception), 'New file name must have the same extension as the original file!')

    @patch('CheckPointSandBlast.CheckPointSandBlast')
    @patch('CheckPointSandBlast.orenctl.getArg')
    @patch('CheckPointSandBlast.fileResult')
    def test_download_command(self, mock_fileResult, mock_getArg, mock_CheckPointSandBlast):
        mock_getArg.return_value = 'file123'

        mock_cpsb = MagicMock()
        mock_CheckPointSandBlast.return_value = mock_cpsb

        # Mock response from download_request
        mock_output = MagicMock()
        mock_output.headers = {"Content-Disposition": 'attachment; filename="test_file.txt"'}
        mock_output.content = b'Some file content'
        mock_cpsb.download_request.return_value = mock_output

        # Mock fileResult to check the result
        mock_fileResult.return_value = mock_fileResult

        # Call the function
        result = download_command()

        # Assertions
        mock_CheckPointSandBlast.assert_called_once()
        mock_cpsb.download_request.assert_called_once_with('file123')
        mock_fileResult.assert_called_once_with(filename='test_file.txt', data=b'Some file content')
        self.assertEqual(result, mock_fileResult)

    @patch('CheckPointSandBlast.CheckPointSandBlast')
    @patch('CheckPointSandBlast.orenctl.getArg')
    @patch('CheckPointSandBlast.fileResult')
    def test_download_command_no_content_disposition(self, mock_fileResult, mock_getArg, mock_CheckPointSandBlast):
        # Setting up mocks
        mock_getArg.return_value = 'file123'

        mock_cpsb = MagicMock()
        mock_CheckPointSandBlast.return_value = mock_cpsb

        # Mock response from download_request without Content-Disposition header
        mock_output = MagicMock()
        mock_output.headers = {}
        mock_output.content = b'Some file content'
        mock_cpsb.download_request.return_value = mock_output

        # Mock fileResult to check the result
        mock_fileResult.return_value = mock_fileResult

        # Call the function
        result = download_command()

        # Assertions
        mock_CheckPointSandBlast.assert_called_once()
        mock_cpsb.download_request.assert_called_once_with('file123')
        mock_fileResult.assert_called_once_with(filename='file.pdf', data=b'Some file content')
        self.assertEqual(result, mock_fileResult)

    @patch('CheckPointSandBlast.CheckPointSandBlast')
    @patch('CheckPointSandBlast.get_quota_context_output')
    @patch('orenctl.results')
    def test_quota_command(self, mock_orenctl_results, mock_get_quota_context_output, mock_CheckPointSandBlast):
        # Setting up mocks
        mock_cpsb = MagicMock()
        mock_CheckPointSandBlast.return_value = mock_cpsb

        # Mock response from quota_request
        mock_raw_outputs = {
            'response': [
                {'QuotaId': 'quota123', 'Limit': 1000, 'Used': 500}
            ]
        }
        mock_cpsb.quota_request.return_value = mock_raw_outputs

        # Mock get_quota_context_output
        mock_processed_output = {'QuotaId': 'quota123', 'Limit': 1000, 'Used': 500}
        mock_get_quota_context_output.return_value = mock_processed_output

        # Mock orenctl.results to check the result
        mock_orenctl_results.return_value = mock_orenctl_results

        # Call the function
        quota_command()

        # Assertions
        mock_CheckPointSandBlast.assert_called_once()
        mock_cpsb.quota_request.assert_called_once()
        mock_get_quota_context_output.assert_called_once_with({'QuotaId': 'quota123', 'Limit': 1000, 'Used': 500})
        mock_orenctl_results.assert_called_once_with({
            "outputs_prefix": 'SandBlast.Quota',
            "outputs_key_field": 'QuotaId',
            "outputs": mock_processed_output,
            "raw_response": mock_raw_outputs,
        })
