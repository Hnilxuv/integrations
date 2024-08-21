import json
import unittest
from datetime import datetime
from unittest.mock import patch, Mock, MagicMock

from Autofocus import Autofocus, get_hash_type, argToList, validate_no_query_and_indicators, \
    validate_no_multiple_indicators_for_search, build_indicator_children_query, children_list_generator, \
    build_logic_query, build_sample_search_query, build_children_query, run_search, batch, search_samples, \
    createContext, validate_sort_and_order_and_artifact, search_sessions, build_session_search_query, \
    get_search_results, parse_hits_response, get_fields_from_hit_object, get_files_data_from_results, \
    filter_object_entries_by_dict_values, parse_sample_analysis_response, parse_coverage_sub_categories, \
    get_data_from_coverage_sub_category, parse_lines_from_os, validate_if_line_needed, get_data_from_line, \
    string_to_context_key, is_ipv6_valid, timestamp_to_datestring, parse_indicator_response, \
    get_tags_for_tags_and_malware_family_fields, convert_url_to_ascii_character, BASE_URL, HEADERS, \
    search_samples_command, search_sessions_command, samples_search_results_command, sessions_search_results_command, \
    get_session_details_command, sample_analysis_command

API_PARAM_DICT = {
    'search_arguments': {
        'file_hash': {
            'api_name': 'field1',
            'operator': 'eq'
        },
        'domain': {
            'api_name': 'field2',
            'operator': 'contains'
        }
    }
}


class TestAutofocus(unittest.TestCase):

    @patch('requests.Session')
    @patch('orenctl.getParam')
    def setUp(self, mock_getParam, mock_session):
        mock_getParam.side_effect = lambda key: {
            'url': 'https://example.com',
            'user_name': 'test_user',
            'password': 'test_pass',
            'proxy': 'http://proxy.com',
            'api_key': 'test_api_key',
            'insecure': False
        }.get(key)

        self.mock_session_instance = mock_session.return_value
        self.instance = Autofocus()
        self.instance.http_request = MagicMock()
        self.mock_sample_analysis_line_keys = MagicMock()
        self.parse_hits_response_patch = patch('Autofocus.parse_hits_response', autospec=True)
        self.mock_parse_hits_response = self.parse_hits_response_patch.start()
        self.parse_sample_analysis_response_patch = patch('Autofocus.parse_sample_analysis_response', autospec=True)
        self.mock_parse_sample_analysis_response = self.parse_sample_analysis_response_patch.start()

    def tearDown(self):
        self.parse_hits_response_patch.stop()
        self.parse_sample_analysis_response_patch.stop()

    @patch('requests.Session.request')  # Mock the request method of the requests library
    def test_http_request_success(self, mock_request):
        # Setup
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'key': 'value'}
        mock_request.return_value = mock_response

        obj = Autofocus()  # Replace with the actual instantiation of your class

        # Test
        result = obj.http_request('GET', '/test')

        # Assertions
        mock_request.assert_called_once_with(method='GET', url='/test', verify=obj.verify)
        self.assertEqual(result, {'key': 'value'})

    @patch('requests.Session.request')
    def test_http_request_non_2xx_status(self, mock_request):
        # Setup
        mock_response = Mock()
        mock_response.status_code = 404
        mock_response.content = 'Not Found'
        mock_request.return_value = mock_response

        obj = Autofocus()

        with self.assertRaises(ValueError) as context:
            obj.http_request('GET', '/test')

        self.assertEqual(str(context.exception), 'Http request error: 404 Not Found')

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

    def test_query_with_no_args(self):
        # Trường hợp chỉ có query, không có arg_list
        try:
            validate_no_query_and_indicators("custom_query", [])
        except Exception:
            self.fail("validate_no_query_and_indicators raised Exception unexpectedly!")

    def test_no_query_with_args(self):
        # Trường hợp không có query, nhưng có arg_list
        try:
            validate_no_query_and_indicators(None, ["arg1", "arg2"])
        except Exception:
            self.fail("validate_no_query_and_indicators raised Exception unexpectedly!")

    def test_no_query_no_args(self):
        # Trường hợp không có query và không có arg_list
        try:
            validate_no_query_and_indicators(None, [])
        except Exception:
            self.fail("validate_no_query_and_indicators raised Exception unexpectedly!")

    def test_query_with_args(self):
        # Trường hợp có cả query và arg_list, nên Exception phải được raise
        with self.assertRaises(Exception) as context:
            validate_no_query_and_indicators("custom_query", ["arg1", "arg2"])

        self.assertEqual(str(context.exception),
                         'The search command can either run a search using a custom query or use the builtin arguments, but not both')

    def test_single_indicator(self):
        # Trường hợp chỉ có một indicator hợp lệ
        arg_dict = {"indicator1": None, "indicator2": "value"}
        result = validate_no_multiple_indicators_for_search(arg_dict)
        self.assertEqual(result, "indicator2")

    def test_no_indicator(self):
        # Trường hợp không có indicator nào được cung cấp
        arg_dict = {"indicator1": None, "indicator2": None}
        with self.assertRaises(Exception) as context:
            validate_no_multiple_indicators_for_search(arg_dict)
        self.assertEqual(str(context.exception),
                         'In order to perform a samples/sessions search, a query or an indicator must be given.')

    def test_multiple_indicators(self):
        # Trường hợp có nhiều hơn một indicator hợp lệ
        arg_dict = {"indicator1": "value1", "indicator2": "value2"}
        with self.assertRaises(Exception) as context:
            validate_no_multiple_indicators_for_search(arg_dict)
        self.assertTrue(
            'The search command can receive one indicator type at a time, two were given' in str(context.exception))

    def test_empty_dict(self):
        # Trường hợp dictionary rỗng
        arg_dict = {}
        with self.assertRaises(Exception) as context:
            validate_no_multiple_indicators_for_search(arg_dict)
        self.assertEqual(str(context.exception),
                         'In order to perform a samples/sessions search, a query or an indicator must be given.')

    @patch('Autofocus.children_list_generator')
    def test_build_indicator_children_query_valid(self, mock_children_list_generator):
        mock_children_list_generator.return_value = ["child1", "child2"]

        used_indicator = "file_hash"
        indicators_values = ["value1", "value2"]
        result = build_indicator_children_query(used_indicator, indicators_values)

        mock_children_list_generator.assert_called_once_with("alias.hash_lookup", "is", indicators_values)

        self.assertIsNotNone(result, ["child1", "child2"])

    @patch('Autofocus.children_list_generator')
    def test_build_indicator_children_query_no_values(self, mock_children_list_generator):
        used_indicator = "indicator1"
        indicators_values = []

        result = build_indicator_children_query(used_indicator, indicators_values)

        mock_children_list_generator.assert_not_called()

        self.assertEqual(result, [])

    def test_children_list_generator_multiple_values(self):
        # Test với nhiều giá trị trong val_list
        field_name = 'field1'
        operator = 'eq'
        val_list = ['value1', 'value2', 'value3']

        expected_output = [
            {'field': field_name, 'operator': operator, 'value': 'value1'},
            {'field': field_name, 'operator': operator, 'value': 'value2'},
            {'field': field_name, 'operator': operator, 'value': 'value3'}
        ]

        result = children_list_generator(field_name, operator, val_list)
        self.assertEqual(result, expected_output)

    def test_children_list_generator_single_value(self):
        # Test với một giá trị trong val_list
        field_name = 'field1'
        operator = 'eq'
        val_list = ['value1']

        expected_output = [
            {'field': field_name, 'operator': operator, 'value': 'value1'}
        ]

        result = children_list_generator(field_name, operator, val_list)
        self.assertEqual(result, expected_output)

    def test_children_list_generator_empty_list(self):
        # Test với val_list rỗng
        field_name = 'field1'
        operator = 'eq'
        val_list = []

        expected_output = []

        result = children_list_generator(field_name, operator, val_list)
        self.assertEqual(result, expected_output)

    def test_build_logic_query_and_operator(self):
        # Test với logic_operator là 'AND'
        logic_operator = 'AND'
        condition_list = [{'field': 'field1', 'operator': 'eq', 'value': 'value1'}]

        expected_output = {
            'operator': 'all',
            'children': condition_list
        }

        result = build_logic_query(logic_operator, condition_list)
        self.assertEqual(result, expected_output)

    def test_build_logic_query_or_operator(self):
        # Test với logic_operator là 'OR'
        logic_operator = 'OR'
        condition_list = [{'field': 'field2', 'operator': 'eq', 'value': 'value2'}]

        expected_output = {
            'operator': 'any',
            'children': condition_list
        }

        result = build_logic_query(logic_operator, condition_list)
        self.assertEqual(result, expected_output)

    def test_build_logic_query_invalid_operator(self):
        # Test với logic_operator không phải là 'AND' hoặc 'OR'
        logic_operator = 'NOT'
        condition_list = [{'field': 'field3', 'operator': 'eq', 'value': 'value3'}]

        expected_output = {
            'operator': None,
            'children': condition_list
        }

        result = build_logic_query(logic_operator, condition_list)
        self.assertEqual(result, expected_output)

    def test_build_logic_query_empty_conditions(self):
        # Test với condition_list rỗng
        logic_operator = 'AND'
        condition_list = []

        expected_output = {
            'operator': 'all',
            'children': condition_list
        }

        result = build_logic_query(logic_operator, condition_list)
        self.assertEqual(result, expected_output)

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_sample_search_query(self, mock_build_children_query, mock_build_logic_query,
                                       mock_build_indicator_children_query):
        # Cấu hình các mock
        mock_build_indicator_children_query.return_value = [
            {'field': 'indicator1', 'operator': 'eq', 'value': 'value1'}]
        mock_build_logic_query.side_effect = lambda op, conds: {'operator': op, 'children': conds}
        mock_build_children_query.return_value = [{'field': 'first_seen', 'operator': 'eq', 'value': '2024-01-01'}]

        # Gọi hàm với dữ liệu đầu vào
        used_indicator = 'indicator1'
        indicators_values = ['value1']
        wildfire_verdict = 'VerdictA'
        first_seen = '2024-01-01'
        last_updated = '2024-01-02'

        expected_query = {
            'operator': 'all',
            'children': [
                {'field': 'first_seen', 'operator': 'eq', 'value': '2024-01-01'},
                {'field': 'last_updated', 'operator': 'eq', 'value': '2024-01-02'},
                {'operator': 'any', 'children': [{'field': 'indicator1', 'operator': 'eq', 'value': 'value1'}]}
            ]
        }

        expected_result = json.dumps(expected_query)
        result = build_sample_search_query(used_indicator, indicators_values, wildfire_verdict, first_seen,
                                           last_updated)

        # Kiểm tra kết quả
        self.assertIsNotNone(result, expected_result)

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_sample_search_query_no_wildfire_verdict(self, mock_build_children_query, mock_build_logic_query,
                                                           mock_build_indicator_children_query):
        # Cấu hình các mock
        mock_build_indicator_children_query.return_value = [
            {'field': 'indicator1', 'operator': 'eq', 'value': 'value1'}]
        mock_build_logic_query.side_effect = lambda op, conds: {'operator': op, 'children': conds}
        mock_build_children_query.return_value = [{'field': 'first_seen', 'operator': 'eq', 'value': '2024-01-01'}]

        # Gọi hàm không có wildfire_verdict
        used_indicator = 'indicator1'
        indicators_values = ['value1']
        wildfire_verdict = None
        first_seen = '2024-01-01'
        last_updated = '2024-01-02'

        expected_query = {
            'operator': 'all',
            'children': [
                {'field': 'first_seen', 'operator': 'eq', 'value': '2024-01-01'},
                {'field': 'last_updated', 'operator': 'eq', 'value': '2024-01-02'},
                {'operator': 'any', 'children': [{'field': 'indicator1', 'operator': 'eq', 'value': 'value1'}]}
            ]
        }

        expected_result = json.dumps(expected_query)
        result = build_sample_search_query(used_indicator, indicators_values, wildfire_verdict, first_seen,
                                           last_updated)

        # Kiểm tra kết quả
        self.assertIsNotNone(result, expected_result)

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_sample_search_query_no_conditions(self, mock_build_children_query, mock_build_logic_query,
                                                     mock_build_indicator_children_query):
        # Cấu hình các mock
        mock_build_indicator_children_query.return_value = []
        mock_build_logic_query.side_effect = lambda op, conds: {'operator': op, 'children': conds}
        mock_build_children_query.return_value = []

        # Gọi hàm không có điều kiện
        used_indicator = 'indicator1'
        indicators_values = []
        wildfire_verdict = None
        first_seen = None
        last_updated = None

        expected_query = {
            'operator': 'all',
            'children': [
                {'operator': 'any', 'children': []}
            ]
        }

        expected_result = json.dumps(expected_query)
        result = build_sample_search_query(used_indicator, indicators_values, wildfire_verdict, first_seen,
                                           last_updated)

        # Kiểm tra kết quả
        self.assertIsNotNone(result, expected_result)

    @patch('Autofocus.children_list_generator')
    def test_build_children_query_multiple_values(self, mock_children_list_generator):
        # Cấu hình mock để trả về kết quả mong muốn
        mock_children_list_generator.side_effect = lambda field_name, operator, val_list: [
            {'field': field_name, 'operator': operator, 'value': value} for value in val_list]

        # Gọi hàm với nhiều cặp khóa-giá trị
        args_for_query = {
            'file_hash': 'value1',
            'domain': 'value2'
        }

        expected_output = [
            {'field': 'api_field1', 'operator': 'eq', 'value': 'value1'},
            {'field': 'api_field2', 'operator': 'neq', 'value': 'value2'}
        ]

        result = build_children_query(args_for_query)
        self.assertIsNotNone(result, expected_output)

    @patch('Autofocus.children_list_generator')
    def test_build_children_query_single_value(self, mock_children_list_generator):
        # Cấu hình mock để trả về kết quả mong muốn
        mock_children_list_generator.side_effect = lambda field_name, operator, val_list: [
            {'field': field_name, 'operator': operator, 'value': value} for value in val_list]

        # Gọi hàm với một cặp khóa-giá trị
        args_for_query = {
            'file_hash': 'value1'
        }

        expected_output = [
            {'field': 'api_field1', 'operator': 'eq', 'value': 'value1'}
        ]

        result = build_children_query(args_for_query)
        self.assertIsNotNone(result, expected_output)

    def test_build_children_query_empty_query(self):
        # Gọi hàm với args_for_query rỗng
        args_for_query = {}

        expected_output = []

        result = build_children_query(args_for_query)
        self.assertEqual(result, expected_output)

    @patch('Autofocus.children_list_generator')
    def test_build_children_query_invalid_key(self, mock_children_list_generator):
        # Cấu hình mock để trả về giá trị mặc định
        mock_children_list_generator.side_effect = lambda field_name, operator, val_list: [
            {'field': field_name, 'operator': operator, 'value': value} for value in val_list]

        # Gọi hàm với khóa không tồn tại trong API_PARAM_DICT
        args_for_query = {
            'field_invalid': 'value_invalid'
        }

        with self.assertRaises(KeyError):
            build_children_query(args_for_query)

    @patch('Autofocus.Autofocus')
    def test_run_search_success(self, MockAutofocus):
        # Cấu hình mock để trả về kết quả mong muốn
        mock_autofocus_instance = MockAutofocus.return_value
        mock_autofocus_instance.do_search.return_value = {
            'af_in_progress': False,
            'af_cookie': 'test_cookie'
        }

        search_object = 'test_object'
        query = json.dumps({'key': 'value'})
        scope = 'test_scope'
        size = '10'
        sort = 'date'
        order = 'desc'
        artifact_source = 'source'

        expected_search_info = {
            'AFCookie': 'test_cookie',
            'Status': 'complete',
            'SessionStart': datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        }

        # Gọi hàm và kiểm tra kết quả
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 8, 21, 10, 0, 0)
            result = run_search(search_object, query, scope, size, sort, order, artifact_source)
            expected_search_info['SessionStart'] = mock_datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            self.assertIsNotNone(result, expected_search_info)

    @patch('Autofocus.Autofocus')
    def test_run_search_in_progress(self, MockAutofocus):
        # Cấu hình mock để trả về kết quả mong muốn
        mock_autofocus_instance = MockAutofocus.return_value
        mock_autofocus_instance.do_search.return_value = {
            'af_in_progress': True,
            'af_cookie': 'test_cookie'
        }

        search_object = 'test_object'
        query = json.dumps({'key': 'value'})
        scope = 'test_scope'
        size = '10'
        sort = 'date'
        order = 'desc'
        artifact_source = 'source'

        expected_search_info = {
            'AFCookie': 'test_cookie',
            'Status': 'in progress',
            'SessionStart': datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        }

        # Gọi hàm và kiểm tra kết quả
        with patch('datetime.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime(2024, 8, 21, 10, 0, 0)
            result = run_search(search_object, query, scope, size, sort, order, artifact_source)
            expected_search_info['SessionStart'] = mock_datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
            self.assertIsNotNone(result, expected_search_info)

    def test_batch_size_smaller_than_iterable(self):
        # Kích thước batch nhỏ hơn số lượng phần tử
        iterable = [1, 2, 3, 4, 5]
        batch_size = 2
        expected_output = [[1, 2], [3, 4], [5]]
        result = list(batch(iterable, batch_size))
        self.assertEqual(result, expected_output)

    def test_batch_size_equal_to_iterable(self):
        # Kích thước batch bằng số lượng phần tử
        iterable = [1, 2, 3, 4, 5]
        batch_size = 5
        expected_output = [[1, 2, 3, 4, 5]]
        result = list(batch(iterable, batch_size))
        self.assertEqual(result, expected_output)

    def test_batch_size_larger_than_iterable(self):
        # Kích thước batch lớn hơn số lượng phần tử
        iterable = [1, 2, 3, 4, 5]
        batch_size = 10
        expected_output = [[1, 2, 3, 4, 5]]
        result = list(batch(iterable, batch_size))
        self.assertEqual(result, expected_output)

    def test_empty_iterable(self):
        # Iterable rỗng
        iterable = []
        batch_size = 3
        expected_output = []
        result = list(batch(iterable, batch_size))
        self.assertEqual(result, expected_output)

    def test_batch_size_of_one(self):
        # Kích thước batch bằng 1
        iterable = [1, 2, 3, 4, 5]
        batch_size = 1
        expected_output = [[1], [2], [3], [4], [5]]
        result = list(batch(iterable, batch_size))
        self.assertEqual(result, expected_output)

    @patch('Autofocus.validate_no_query_and_indicators')
    @patch('Autofocus.validate_no_multiple_indicators_for_search')
    @patch('Autofocus.batch')
    @patch('Autofocus.build_sample_search_query')
    @patch('Autofocus.run_search')
    def test_search_with_query(self, mock_run_search, mock_build_sample_search_query, mock_batch,
                               mock_validate_no_multiple_indicators_for_search, mock_validate_no_query_and_indicators):
        # Trường hợp có query và không có các chỉ số (indicators)
        mock_validate_no_query_and_indicators.return_value = None
        mock_run_search.return_value = {'result': 'some_data'}

        query = '{"key": "value"}'
        search_result = search_samples(query=query)

        mock_validate_no_query_and_indicators.assert_called_once_with(query, [None, None, None, None, None, None, None])
        mock_run_search.assert_called_once_with('samples', query=query, scope=None, size=None, sort=None, order=None,
                                                artifact_source=None)
        self.assertIsNotNone(search_result, {'result': 'some_data'})

    @patch('Autofocus.validate_no_query_and_indicators')
    @patch('Autofocus.validate_no_multiple_indicators_for_search')
    @patch('Autofocus.batch')
    @patch('Autofocus.build_sample_search_query')
    @patch('Autofocus.run_search')
    def test_search_without_query_with_one_indicator(self, mock_run_search, mock_build_sample_search_query, mock_batch,
                                                     mock_validate_no_multiple_indicators_for_search,
                                                     mock_validate_no_query_and_indicators):
        # Trường hợp không có query nhưng có một chỉ số
        mock_validate_no_query_and_indicators.return_value = None
        mock_validate_no_multiple_indicators_for_search.return_value = 'file_hash'
        mock_batch.return_value = [['hash1', 'hash2']]
        mock_build_sample_search_query.return_value = '{"query": "some_query"}'
        mock_run_search.return_value = {'result': 'some_data'}

        search_result = search_samples(file_hash=['hash1', 'hash2'])

        mock_validate_no_query_and_indicators.assert_called_once_with(None,
                                                                      [['hash1', 'hash2'], None, None, None, None, None,
                                                                       None])
        mock_validate_no_multiple_indicators_for_search.assert_called_once_with({
            'file_hash': ['hash1', 'hash2'],
            'domain': None,
            'ip': None,
            'url': None
        })
        mock_batch.assert_called_once_with(['hash1', 'hash2'], batch_size=100)
        mock_build_sample_search_query.assert_called_once_with('file_hash', ['hash1', 'hash2'], None, None, None)
        mock_run_search.assert_called_once_with('samples', query='{"query": "some_query"}', scope=None, size=None,
                                                sort=None, order=None, artifact_source=None)
        self.assertIsNotNone(search_result, [{'result': 'some_data'}])

    @patch('Autofocus.validate_no_query_and_indicators')
    @patch('Autofocus.validate_no_multiple_indicators_for_search')
    @patch('Autofocus.batch')
    @patch('Autofocus.build_sample_search_query')
    @patch('Autofocus.run_search')
    def test_search_without_query_with_invalid_indicators(self, mock_run_search, mock_build_sample_search_query,
                                                          mock_batch, mock_validate_no_multiple_indicators_for_search,
                                                          mock_validate_no_query_and_indicators):
        # Trường hợp không có query và các chỉ số không hợp lệ
        mock_validate_no_query_and_indicators.return_value = None
        mock_validate_no_multiple_indicators_for_search.side_effect = Exception('Invalid indicators')

        with self.assertRaises(Exception):
            search_samples(file_hash=['hash1', 'hash2'], domain='example.com')

    @patch('Autofocus.createContextSingle')  # Mock createContextSingle
    def test_createContext_with_list(self, mock_createContextSingle):
        mock_createContextSingle.side_effect = lambda d, id, kt, rn: f"Processed: {d}"

        data = [{"name": "Alice"}, {"name": "Bob"}]

        result = createContext(data, id=1, keyTransform=str.upper, removeNull=True)

        self.assertEqual(mock_createContextSingle.call_count, 2)

        expected_result = ["Processed: {'name': 'Alice'}", "Processed: {'name': 'Bob'}"]
        self.assertIsNotNone(result, expected_result)

    @patch('Autofocus.createContextSingle')  # Mock createContextSingle
    def test_createContext_with_tuple(self, mock_createContextSingle):
        mock_createContextSingle.side_effect = lambda d, id, kt, rn: f"Processed: {d}"

        data = ({"name": "Charlie"}, {"name": "David"})

        result = createContext(data, id=2, keyTransform=str.lower, removeNull=False)

        self.assertEqual(mock_createContextSingle.call_count, 2)

        expected_result = ["Processed: {'name': 'Charlie'}", "Processed: {'name': 'David'}"]
        self.assertIsNotNone(result, expected_result)

    def test_no_sort_and_order(self):
        # Test trường hợp không có sort và order
        self.assertFalse(validate_sort_and_order_and_artifact(sort=None, order=None, artifact_source=None))

    def test_only_sort(self):
        # Test trường hợp chỉ có sort mà không có order
        with self.assertRaises(Exception) as context:
            validate_sort_and_order_and_artifact(sort='field', order=None, artifact_source=None)
        self.assertEqual(str(context.exception), 'Please specify the order of sorting (Ascending or Descending).')

    def test_only_order(self):
        # Test trường hợp chỉ có order mà không có sort
        with self.assertRaises(Exception) as context:
            validate_sort_and_order_and_artifact(sort=None, order='asc', artifact_source=None)
        self.assertEqual(str(context.exception), 'Please specify a field to sort by.')

    def test_sort_and_order(self):
        # Test trường hợp có cả sort và order
        self.assertTrue(validate_sort_and_order_and_artifact(sort='field', order='asc', artifact_source=None))

    def test_sort_with_artifact_source(self):
        # Test trường hợp có cả sort và artifact_source
        with self.assertRaises(Exception) as context:
            validate_sort_and_order_and_artifact(sort='field', order='asc', artifact_source='true')
        self.assertEqual(str(context.exception), 'Please remove or disable one of sort or artifact,'
                                                 ' As they are not supported in the api together.')

    def test_artifact_source_without_sort(self):
        # Test trường hợp có artifact_source mà không có sort
        self.assertFalse(validate_sort_and_order_and_artifact(sort=None, order=None, artifact_source='true'))

    @patch('Autofocus.validate_no_query_and_indicators')
    @patch('Autofocus.run_search')
    def test_search_with_query(self, mock_run_search, mock_validate_no_query_and_indicators):
        # Trường hợp có query và không có các chỉ số
        mock_validate_no_query_and_indicators.return_value = None
        mock_run_search.return_value = {'result': 'some_data'}

        search_result = search_sessions(query='some_query', size=10, sort='date', order='asc')

        mock_validate_no_query_and_indicators.assert_called_once_with('some_query',
                                                                      [None, None, None, None, None, None])
        mock_run_search.assert_called_once_with('sessions', query='some_query', size=10, sort='date', order='asc')
        self.assertEqual(search_result, {'result': 'some_data'})

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_session_search_query_with_all_times(self, mock_build_children_query, mock_build_logic_query,
                                                       mock_build_indicator_children_query):
        # Mock các hàm phụ thuộc
        mock_build_indicator_children_query.return_value = [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]
        mock_build_logic_query.return_value = {'operator': 'or', 'children': [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
        mock_build_children_query.return_value = [
            {'field': 'time_range', 'operator': 'range', 'value': ['2024-01-01', '2024-01-31']}]

        query = build_session_search_query('file_hash', ['hash1', 'hash2'], '2024-01-01', '2024-01-31')

        expected_query = json.dumps({
            'operator': 'and',
            'children': [
                {'field': 'time_range', 'operator': 'range', 'value': ['2024-01-01', '2024-01-31']},
                {'operator': 'or', 'children': [{'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
            ]
        })

        self.assertIsNotNone(query, expected_query)
        mock_build_indicator_children_query.assert_called_once_with('file_hash', ['hash1', 'hash2'])

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_session_search_query_with_only_from_time(self, mock_build_children_query, mock_build_logic_query,
                                                            mock_build_indicator_children_query):
        mock_build_indicator_children_query.return_value = [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]
        mock_build_logic_query.return_value = {'operator': 'or', 'children': [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
        mock_build_children_query.return_value = [{'field': 'time_after', 'operator': 'after', 'value': ['2024-01-01']}]

        query = build_session_search_query('file_hash', ['hash1', 'hash2'], '2024-01-01', None)

        expected_query = json.dumps({
            'operator': 'and',
            'children': [
                {'field': 'time_after', 'operator': 'after', 'value': ['2024-01-01']},
                {'operator': 'or', 'children': [{'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
            ]
        })

        self.assertIsNotNone(query, expected_query)

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_session_search_query_with_only_to_time(self, mock_build_children_query, mock_build_logic_query,
                                                          mock_build_indicator_children_query):
        mock_build_indicator_children_query.return_value = [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]
        mock_build_logic_query.return_value = {'operator': 'or', 'children': [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
        mock_build_children_query.return_value = [
            {'field': 'time_before', 'operator': 'before', 'value': ['2024-01-31']}]

        query = build_session_search_query('file_hash', ['hash1', 'hash2'], None, '2024-01-31')

        expected_query = json.dumps({
            'operator': 'and',
            'children': [
                {'field': 'time_before', 'operator': 'before', 'value': ['2024-01-31']},
                {'operator': 'or', 'children': [{'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
            ]
        })

        self.assertIsNotNone(query, expected_query)

    @patch('Autofocus.build_indicator_children_query')
    @patch('Autofocus.build_logic_query')
    @patch('Autofocus.build_children_query')
    def test_build_session_search_query_with_no_times(self, mock_build_children_query, mock_build_logic_query,
                                                      mock_build_indicator_children_query):
        mock_build_indicator_children_query.return_value = [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]
        mock_build_logic_query.return_value = {'operator': 'or', 'children': [
            {'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
        mock_build_children_query.return_value = []

        query = build_session_search_query('file_hash', ['hash1', 'hash2'], None, None)

        expected_query = json.dumps({
            'operator': 'and',
            'children': [
                {'operator': 'or', 'children': [{'field': 'field_name', 'operator': 'operator', 'value': 'value'}]}
            ]
        })

        self.assertIsNotNone(query, expected_query)

    @patch('Autofocus.Autofocus')
    @patch('Autofocus.parse_hits_response')
    def test_get_search_results_successful_initial(self, mock_parse_hits_response, mock_Autofocus):
        # Giả lập kết quả trả về thành công ngay lập tức
        mock_autofocus_instance = MagicMock()
        mock_Autofocus.return_value = mock_autofocus_instance
        mock_autofocus_instance.run_get_search_results.return_value = {
            'hits': ['result1', 'result2'],
            'af_complete_percentage': 100,
            'af_in_progress': False
        }
        mock_parse_hits_response.return_value = ['parsed_result1', 'parsed_result2']

        parsed_results, status = get_search_results('search_object', 'af_cookie')

        self.assertEqual(parsed_results, ['parsed_result1', 'parsed_result2'])
        self.assertEqual(status, 'complete')
        mock_autofocus_instance.run_get_search_results.assert_called_once_with('search_object', 'af_cookie')
        mock_parse_hits_response.assert_called_once_with(['result1', 'result2'], 'search_results')

    @patch('Autofocus.Autofocus')
    @patch('Autofocus.parse_hits_response')
    @patch('time.sleep', return_value=None)  # Patch time.sleep to avoid actual sleep
    def test_get_search_results_with_retries(self, mock_sleep, mock_parse_hits_response, mock_Autofocus):
        # Giả lập retry với kết quả thành công sau một vài lần thử
        mock_autofocus_instance = MagicMock()
        mock_Autofocus.return_value = mock_autofocus_instance

        # Simulate multiple retries
        mock_autofocus_instance.run_get_search_results.side_effect = [
            {'hits': None, 'af_complete_percentage': 50, 'af_in_progress': True},
            {'hits': None, 'af_complete_percentage': 75, 'af_in_progress': True},
            {'hits': ['result1'], 'af_complete_percentage': 100, 'af_in_progress': False}
        ]
        mock_parse_hits_response.return_value = ['parsed_result1']

        parsed_results, status = get_search_results('search_object', 'af_cookie')

        self.assertEqual(parsed_results, ['parsed_result1'])
        self.assertEqual(status, 'complete')
        self.assertEqual(mock_autofocus_instance.run_get_search_results.call_count, 3)
        mock_parse_hits_response.assert_called_once_with(['result1'], 'search_results')

    @patch('Autofocus.get_fields_from_hit_object')
    def test_parse_hits_response_empty_hits(self, mock_get_fields_from_hit_object):
        # Test trường hợp hits là danh sách rỗng
        hits = []
        response_dict_name = 'search_results'
        result = parse_hits_response(hits, response_dict_name)

        self.assertEqual(result, [])
        mock_get_fields_from_hit_object.assert_not_called()

    @patch('Autofocus.get_fields_from_hit_object')
    def test_parse_hits_response_with_hits(self, mock_get_fields_from_hit_object):
        # Test trường hợp hits chứa các đối tượng hợp lệ
        mock_get_fields_from_hit_object.return_value = {'parsed_field': 'value'}
        hits = [
            {'_source': {'field1': 'value1'}, '_id': 'id1'},
            {'_source': {'field2': 'value2'}, '_id': 'id2'}
        ]
        response_dict_name = 'search_results'
        result = parse_hits_response(hits, response_dict_name)

        expected_result = [
            {'parsed_field': 'value'},
            {'parsed_field': 'value'}
        ]
        self.assertEqual(result, expected_result)
        self.assertEqual(mock_get_fields_from_hit_object.call_count, 2)
        mock_get_fields_from_hit_object.assert_any_call({'field1': 'value1', '_id': 'id1'}, response_dict_name)
        mock_get_fields_from_hit_object.assert_any_call({'field2': 'value2', '_id': 'id2'}, response_dict_name)

    @patch('Autofocus.API_PARAM_DICT')
    def test_get_fields_from_hit_object_with_mapping(self, mock_api_param_dict):
        # Test trường hợp result_object có các trường có thể ánh xạ
        mock_api_param_dict.get.return_value = {
            'field1': 'mapped_field1',
            'field2': 'mapped_field2'
        }
        result_object = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }
        response_dict_name = 'search_results'
        expected_result = {
            'mapped_field1': 'value1',
            'mapped_field2': 'value2',
            'field3': 'value3'
        }

        result = get_fields_from_hit_object(result_object, response_dict_name)
        self.assertEqual(result, expected_result)

    @patch('Autofocus.API_PARAM_DICT')
    def test_get_fields_from_hit_object_without_mapping(self, mock_api_param_dict):
        # Test trường hợp result_object có các trường không có trong af_params_dict
        mock_api_param_dict.get.return_value = {}
        result_object = {
            'field1': 'value1',
            'field2': 'value2'
        }
        response_dict_name = 'search_results'
        expected_result = {
            'field1': 'value1',
            'field2': 'value2'
        }

        result = get_fields_from_hit_object(result_object, response_dict_name)
        self.assertEqual(result, expected_result)

    @patch('Autofocus.API_PARAM_DICT')
    def test_get_fields_from_hit_object_with_partial_mapping(self, mock_api_param_dict):
        # Test trường hợp af_params_dict chỉ chứa một số ánh xạ
        mock_api_param_dict.get.return_value = {
            'field1': 'mapped_field1'
        }
        result_object = {
            'field1': 'value1',
            'field2': 'value2'
        }
        response_dict_name = 'search_results'
        expected_result = {
            'mapped_field1': 'value1',
            'field2': 'value2'
        }

        result = get_fields_from_hit_object(result_object, response_dict_name)
        self.assertEqual(result, expected_result)

    @patch('Autofocus.get_fields_from_hit_object')
    @patch('Autofocus.filter_object_entries_by_dict_values')
    def test_get_files_data_from_results_empty(self, mock_filter_object_entries_by_dict_values,
                                               mock_get_fields_from_hit_object):
        # Test trường hợp results là danh sách rỗng
        results = []
        mock_get_fields_from_hit_object.return_value = {}
        mock_filter_object_entries_by_dict_values.return_value = {}

        files_data = get_files_data_from_results(results)

        self.assertEqual(files_data, [])
        mock_get_fields_from_hit_object.assert_not_called()
        mock_filter_object_entries_by_dict_values.assert_not_called()

    @patch('Autofocus.get_fields_from_hit_object')
    @patch('Autofocus.filter_object_entries_by_dict_values')
    def test_get_files_data_from_results_with_results(self, mock_filter_object_entries_by_dict_values,
                                                      mock_get_fields_from_hit_object):
        # Test trường hợp results chứa các kết quả
        results = [
            {'_id': '1', '_source': {'file_name': 'file1', 'file_size': '10MB'}},
            {'_id': '2', '_source': {'file_name': 'file2', 'file_size': '20MB'}}
        ]
        mock_get_fields_from_hit_object.side_effect = lambda result, _: result.get('_source')
        mock_filter_object_entries_by_dict_values.side_effect = lambda raw_file, _: raw_file

        expected_result = [
            {'file_name': 'file1', 'file_size': '10MB'},
            {'file_name': 'file2', 'file_size': '20MB'}
        ]

        files_data = get_files_data_from_results(results)

        self.assertEqual(files_data, expected_result)
        mock_get_fields_from_hit_object.assert_called()
        mock_filter_object_entries_by_dict_values.assert_called()

    @patch('Autofocus.get_fields_from_hit_object')
    @patch('Autofocus.filter_object_entries_by_dict_values')
    def test_get_files_data_from_results_no_changes(self, mock_filter_object_entries_by_dict_values,
                                                    mock_get_fields_from_hit_object):
        # Test trường hợp các hàm không thay đổi dữ liệu
        results = [
            {'_id': '1', '_source': {'file_name': 'file1', 'file_size': '10MB'}}
        ]
        mock_get_fields_from_hit_object.return_value = {'file_name': 'file1', 'file_size': '10MB'}
        mock_filter_object_entries_by_dict_values.return_value = {'file_name': 'file1', 'file_size': '10MB'}

        expected_result = [{'file_name': 'file1', 'file_size': '10MB'}]

        files_data = get_files_data_from_results(results)

        self.assertEqual(files_data, expected_result)
        mock_get_fields_from_hit_object.assert_called_once_with(
            {'_id': '1', '_source': {'file_name': 'file1', 'file_size': '10MB'}}, 'file_indicators')
        mock_filter_object_entries_by_dict_values.assert_called_once_with({'file_name': 'file1', 'file_size': '10MB'},
                                                                          'file_indicators')

    @patch('Autofocus.API_PARAM_DICT')
    def test_valid_filtering(self, mock_api_param_dict):
        # Test trường hợp `result_object` và `af_params_dict` là từ điển và có giá trị tương ứng
        mock_api_param_dict.get.return_value = {'file_name': 'name', 'file_size': 'size'}
        result_object = {'name': 'file1', 'size': '10MB', 'extra': 'value'}

        expected_filtered = {'name': 'file1', 'size': '10MB'}
        filtered_result = filter_object_entries_by_dict_values(result_object, 'file_indicators')

        self.assertEqual(filtered_result, expected_filtered)

    def test_result_object_not_dict(self):
        # Test trường hợp `result_object` không phải là từ điển
        result_object = ['name', 'size']
        expected_filtered = {}

        filtered_result = filter_object_entries_by_dict_values(result_object, 'file_indicators')

        self.assertEqual(filtered_result, expected_filtered)

    def test_af_params_dict_not_dict(self):
        # Test trường hợp `af_params_dict` không phải là từ điển
        with patch('Autofocus.API_PARAM_DICT', {'file_indicators': 'invalid_type'}):
            result_object = {'name': 'file1', 'size': '10MB'}
            expected_filtered = {}

            filtered_result = filter_object_entries_by_dict_values(result_object, 'file_indicators')

            self.assertEqual(filtered_result, expected_filtered)

    def test_no_matching_keys(self):
        # Test trường hợp `af_params_dict` không chứa các giá trị tương ứng với các khóa trong `result_object`
        with patch('Autofocus.API_PARAM_DICT', {'file_indicators': {'other_key': 'nonexistent'}}):
            result_object = {'name': 'file1', 'size': '10MB'}
            expected_filtered = {}

            filtered_result = filter_object_entries_by_dict_values(result_object, 'file_indicators')

            self.assertEqual(filtered_result, expected_filtered)

    @patch('Autofocus.parse_lines_from_os')
    @patch('Autofocus.parse_coverage_sub_categories')
    def test_parse_with_sample_analysis_keys(self, mock_parse_coverage_sub_categories, mock_parse_lines_from_os):
        # Test trường hợp resp chứa các mục trong SAMPLE_ANALYSIS_LINE_KEYS
        mock_parse_lines_from_os.return_value = 'sanitized_data'
        resp = {
            'category1': {
                'os1': 'data1',
                'os2': 'data2'
            },
            'category2': {
                'os3': 'data3'
            }
        }
        mock_sample_analysis_line_keys = {
            'category1': {'display_name': 'Display Cat 1'},
            'category2': {'display_name': 'Display Cat 2'}
        }
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', mock_sample_analysis_line_keys):
            result = parse_sample_analysis_response(resp, filter_data_flag=True)

            expected_result = {
                'Display Cat 1': {
                    'os1': 'sanitized_data',
                    'os2': 'sanitized_data'
                },
                'Display Cat 2': {
                    'os3': 'sanitized_data'
                }
            }
            self.assertEqual(result, expected_result)

    @patch('Autofocus.parse_lines_from_os')
    @patch('Autofocus.parse_coverage_sub_categories')
    def test_parse_with_coverage(self, mock_parse_coverage_sub_categories, mock_parse_lines_from_os):
        # Test trường hợp resp chứa mục 'coverage'
        mock_parse_coverage_sub_categories.return_value = {'coverage_data': 'value'}
        resp = {
            'coverage': 'coverage_data'
        }
        result = parse_sample_analysis_response(resp, filter_data_flag=False)

        expected_result = {'coverage_data': 'value'}
        self.assertEqual(result, expected_result)

    def test_parse_with_no_relevant_keys(self):
        # Test trường hợp resp không chứa mục nào trong SAMPLE_ANALYSIS_LINE_KEYS và không chứa 'coverage'
        resp = {
            'irrelevant_key': 'data'
        }
        result = parse_sample_analysis_response(resp, filter_data_flag=False)

        self.assertEqual(result, {})

    @patch('Autofocus.get_data_from_coverage_sub_category')
    def test_parse_with_valid_sub_categories(self, mock_get_data_from_coverage_sub_category):
        # Test trường hợp coverage_data chứa các mục trong SAMPLE_ANALYSIS_COVERAGE_KEYS
        mock_get_data_from_coverage_sub_category.return_value = 'sub_category_data'
        coverage_data = {
            'sub_cat_1': {'data': 'value1'},
            'sub_cat_2': {'data': 'value2'}
        }
        mock_sample_analysis_coverage_keys = {
            'sub_cat_1': {'display_name': 'Sub Category 1'},
            'sub_cat_2': {'display_name': 'Sub Category 2'}
        }
        with patch('Autofocus.SAMPLE_ANALYSIS_COVERAGE_KEYS', mock_sample_analysis_coverage_keys):
            result = parse_coverage_sub_categories(coverage_data)

            expected_result = {
                'coverage': {
                    'Sub Category 1': 'sub_category_data',
                    'Sub Category 2': 'sub_category_data'
                }
            }
            self.assertEqual(result, expected_result)

    def test_parse_with_no_relevant_sub_categories(self):
        # Test trường hợp coverage_data không chứa mục nào trong SAMPLE_ANALYSIS_COVERAGE_KEYS
        coverage_data = {
            'irrelevant_sub_cat': {'data': 'value'}
        }
        result = parse_coverage_sub_categories(coverage_data)

        expected_result = {'coverage': {}}
        self.assertEqual(result, expected_result)

    def test_parse_with_non_dict_data(self):
        coverage_data = 'invalid_data'
        result = parse_coverage_sub_categories(coverage_data)

        expected_result = {'coverage': {}}
        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_COVERAGE_KEYS')
    def test_get_data_from_valid_sub_category(self, mock_sample_analysis_coverage_keys):
        # Test trường hợp dữ liệu sub_category hợp lệ và fields tồn tại trong SAMPLE_ANALYSIS_COVERAGE_KEYS
        mock_sample_analysis_coverage_keys.get.return_value = {'fields': ['field1', 'field2']}
        sub_category_data = [
            {'field1': 'value1', 'field2': 'value2', 'field3': 'extra_value'},
            {'field1': 'value3', 'field2': 'value4', 'field3': 'extra_value'}
        ]

        result = get_data_from_coverage_sub_category('valid_sub_category', sub_category_data)

        expected_result = [
            {'field1': 'value1', 'field2': 'value2'},
            {'field1': 'value3', 'field2': 'value4'}
        ]
        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_COVERAGE_KEYS')
    def test_get_data_from_empty_sub_category_data(self, mock_sample_analysis_coverage_keys):
        # Test trường hợp sub_category_data rỗng
        mock_sample_analysis_coverage_keys.get.return_value = {'fields': ['field1']}
        sub_category_data = []

        result = get_data_from_coverage_sub_category('valid_sub_category', sub_category_data)

        expected_result = []
        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_COVERAGE_KEYS')
    def test_get_data_from_missing_fields(self, mock_sample_analysis_coverage_keys):
        # Test trường hợp SAMPLE_ANALYSIS_COVERAGE_KEYS không có 'fields'
        mock_sample_analysis_coverage_keys.get.return_value = {}
        sub_category_data = [
            {'field1': 'value1', 'field2': 'value2'}
        ]

        result = get_data_from_coverage_sub_category('valid_sub_category', sub_category_data)

        expected_result = [{}]  # Không có trường nào được lấy
        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_COVERAGE_KEYS')
    def test_get_data_from_non_existent_sub_category(self, mock_sample_analysis_coverage_keys):
        mock_sample_analysis_coverage_keys.get.return_value = None
        sub_category_data = [
            {'field1': 'value1'}
        ]

        result = get_data_from_coverage_sub_category('non_existent_sub_category', sub_category_data)

        expected_result = []
        self.assertIsNotNone(result, expected_result)

    @patch('Autofocus.validate_if_line_needed')
    @patch('Autofocus.get_data_from_line')
    def test_parse_lines_from_os_with_filter(self, mock_get_data_from_line, mock_validate_if_line_needed):
        # Setup mocks
        mock_validate_if_line_needed.return_value = True
        mock_get_data_from_line.return_value = {'parsed': 'data'}

        category_name = 'category1'
        data = [{'line': 'line1'}, {'line': 'line2'}]
        filter_data_flag = True

        expected_result = [{'parsed': 'data'}, {'parsed': 'data'}]

        result = parse_lines_from_os(category_name, data, filter_data_flag)

        mock_validate_if_line_needed.assert_called_with(category_name, {'line': 'line2'})
        mock_get_data_from_line.assert_called_with('line2', category_name)
        self.assertEqual(result, expected_result)

    @patch('Autofocus.validate_if_line_needed')
    @patch('Autofocus.get_data_from_line')
    def test_parse_lines_from_os_without_filter(self, mock_get_data_from_line, mock_validate_if_line_needed):
        # Setup mocks
        mock_get_data_from_line.return_value = {'parsed': 'data'}

        category_name = 'category1'
        data = [{'line': 'line1'}, {'line': 'line2'}]
        filter_data_flag = False

        expected_result = [{'parsed': 'data'}, {'parsed': 'data'}]

        result = parse_lines_from_os(category_name, data, filter_data_flag)

        mock_validate_if_line_needed.assert_not_called()
        mock_get_data_from_line.assert_called_with('line2', category_name)
        self.assertEqual(result, expected_result)

    def test_parse_lines_from_os_with_no_data(self):
        category_name = 'category1'
        data = []
        filter_data_flag = True

        expected_result = []

        result = parse_lines_from_os(category_name, data, filter_data_flag)

        self.assertEqual(result, expected_result)

    @patch('Autofocus.validate_if_line_needed')
    @patch('Autofocus.get_data_from_line')
    def test_parse_lines_from_os_with_filter_data_not_needed(self, mock_get_data_from_line,
                                                             mock_validate_if_line_needed):
        # Setup mocks
        mock_validate_if_line_needed.return_value = False
        mock_get_data_from_line.return_value = {'parsed': 'data'}

        category_name = 'category1'
        data = [{'line': 'line1'}, {'line': 'line2'}]
        filter_data_flag = True

        expected_result = []

        result = parse_lines_from_os(category_name, data, filter_data_flag)

        mock_validate_if_line_needed.assert_called_with(category_name, {'line': 'line2'})
        mock_get_data_from_line.assert_not_called()
        self.assertEqual(result, expected_result)

    def test_validate_if_line_needed_behavior_not_informational(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'risk': 2}}
        info_line = {'line': 'some,data,of,risk_value'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('behavior', info_line)
        self.assertTrue(result)

    def test_validate_if_line_needed_behavior_informational(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'risk': 2}}
        info_line = {'line': 'some,data,of,informational'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('behavior', info_line)
        self.assertTrue(result)

    def test_validate_if_line_needed_registry_valid_action(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,SetValueKey,data'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('registry', info_line)
        self.assertTrue(result)

    def test_validate_if_line_needed_registry_invalid_action(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,InvalidAction,data'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('registry', info_line)
        self.assertFalse(result)

    def test_validate_if_line_needed_file_malicious_greater_than_benign(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,CreateFileW,data', 'b': 1, 'm': 2}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('file', info_line)
        self.assertTrue(result)

    def test_validate_if_line_needed_file_benign_greater_than_malicious(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,CreateFileW,data', 'b': 3, 'm': 1}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('file', info_line)
        self.assertFalse(result)

    def test_validate_if_line_needed_process_valid_action(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,CreateProcessInternalW,data'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('process', info_line)
        self.assertTrue(result)

    def test_validate_if_line_needed_process_invalid_action(self):
        self.mock_sample_analysis_line_keys.get.return_value = {'indexes': {'action': 1}}
        info_line = {'line': 'some,InvalidAction,data'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('process', info_line)
        self.assertFalse(result)

    def test_validate_if_line_needed_default_case(self):
        self.mock_sample_analysis_line_keys.get.return_value = {}
        info_line = {'line': 'some,data,action'}
        with patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS', self.mock_sample_analysis_line_keys):
            result = validate_if_line_needed('other_category', info_line)
        self.assertTrue(result)

    @patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS')
    def test_get_data_from_line_with_indexes(self, mock_sample_analysis_line_keys):
        # Mock the category indexes
        mock_sample_analysis_line_keys.get.return_value = {
            'indexes': {'field1': 0, 'field2': 1}
        }
        line = 'value1,value2,value3'
        expected_result = {'field1': 'value1', 'field2': 'value2'}

        result = get_data_from_line(line, 'some_category')

        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS')
    def test_get_data_from_line_without_indexes(self, mock_sample_analysis_line_keys):
        # Mock no category indexes
        mock_sample_analysis_line_keys.get.return_value = {}
        line = 'value1,value2,value3'
        expected_result = {}

        result = get_data_from_line(line, 'some_category')

        self.assertEqual(result, expected_result)

    @patch('Autofocus.SAMPLE_ANALYSIS_LINE_KEYS')
    def test_get_data_from_line_with_missing_indexes(self, mock_sample_analysis_line_keys):
        # Mock the category indexes with missing fields
        mock_sample_analysis_line_keys.get.return_value = {
            'indexes': {'field1': 0}
        }
        line = 'value1,value2,value3'
        expected_result = {'field1': 'value1'}

        result = get_data_from_line(line, 'some_category')

        self.assertEqual(result, expected_result)

    def test_string_to_context_key_valid_string(self):
        result = string_to_context_key('example_key')
        self.assertEqual(result, 'ExampleKey')

    def test_string_to_context_key_invalid_type(self):
        with self.assertRaises(Exception) as context:
            string_to_context_key(123)
        self.assertEqual(str(context.exception), 'The key is not a string: 123')

    def test_string_to_context_key_empty_string(self):
        result = string_to_context_key('')
        self.assertEqual(result, '')

    def test_string_to_context_key_multiple_underscores(self):
        result = string_to_context_key('multiple__underscores')
        self.assertEqual(result, 'MultipleUnderscores')

    def test_valid_ipv6_address(self):
        valid_ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334'
        self.assertTrue(is_ipv6_valid(valid_ipv6))

    def test_valid_ipv6_address_with_compression(self):
        valid_ipv6 = '2001:db8:85a3::8a2e:370:7334'
        self.assertTrue(is_ipv6_valid(valid_ipv6))

    def test_invalid_ipv6_address(self):
        invalid_ipv6 = '2001:0db8:85a3:0000:0000:8a2e:0370:xyz'
        self.assertFalse(is_ipv6_valid(invalid_ipv6))

    def test_invalid_ipv4_address(self):
        invalid_ipv4 = '192.168.1.1'
        self.assertFalse(is_ipv6_valid(invalid_ipv4))

    def test_empty_address(self):
        self.assertFalse(is_ipv6_valid(''))

    def test_parse_with_complete_data(self):
        res = {
            'indicatorValue': 'example.com',
            'indicatorType': 'Domain',
            'latestPanVerdicts': 'Malicious',
            'wildfireRelatedSampleVerdictCounts': '5',
            'seenByDataSourceIds': '12345',
            'firstSeenTsGlobal': '1625078400',
            'lastSeenTsGlobal': '1625164800',
            'whoisAdminCountry': 'US',
            'whoisAdminEmail': 'admin@example.com',
            'whoisAdminName': 'Admin Name',
            'whoisDomainCreationDate': '2021-06-20',
            'whoisDomainExpireDate': '2022-06-20',
            'whoisDomainUpdateDate': '2021-07-01',
            'whoisRegistrar': 'Registrar Name',
            'whoisRegistrarUrl': 'http://registrar.com',
            'whoisRegistrant': 'Registrant Name'
        }
        raw_tags = [{
            'public_tag_name': 'Tag1',
            'tag_name': 'tag1',
            'customer_name': 'Customer1',
            'source': 'source1',
            'tag_definition_scope_id': 'scope1',
            'tag_definition_status_id': 'status1',
            'tag_class_id': 'class1',
            'count': '10',
            'lasthit': '1625164800',
            'description': 'Description1'
        }]
        expected_output = {
            'IndicatorValue': 'example.com',
            'IndicatorType': 'Domain',
            'LatestPanVerdicts': 'Malicious',
            'WildfireRelatedSampleVerdictCounts': '5',
            'SeenBy': '12345',
            'FirstSeen': timestamp_to_datestring('1625078400'),
            'LastSeen': timestamp_to_datestring('1625164800'),
            'Tags': [{
                'PublicTagName': 'Tag1',
                'TagName': 'tag1',
                'CustomerName': 'Customer1',
                'Source': 'source1',
                'TagDefinitionScopeID': 'scope1',
                'TagDefinitionStatusID': 'status1',
                'TagClassID': 'class1',
                'Count': '10',
                'Lasthit': '1625164800',
                'Description': 'Description1'
            }],
            'WhoisAdminCountry': 'US',
            'WhoisAdminEmail': 'admin@example.com',
            'WhoisAdminName': 'Admin Name',
            'WhoisDomainCreationDate': '2021-06-20',
            'WhoisDomainExpireDate': '2022-06-20',
            'WhoisDomainUpdateDate': '2021-07-01',
            'WhoisRegistrar': 'Registrar Name',
            'WhoisRegistrarUrl': 'http://registrar.com',
            'WhoisRegistrant': 'Registrant Name'
        }
        result = parse_indicator_response(res, raw_tags, 'Domain')
        self.assertEqual(result, expected_output)

    def test_parse_with_no_raw_tags(self):
        res = {
            'indicatorValue': 'example.com',
            'indicatorType': 'Domain',
            'latestPanVerdicts': 'Malicious',
            'wildfireRelatedSampleVerdictCounts': '5',
            'seenByDataSourceIds': '12345',
            'firstSeenTsGlobal': '1625078400',
            'lastSeenTsGlobal': '1625164800',
            'whoisAdminCountry': 'US'
        }
        expected_output = {
            'IndicatorValue': 'example.com',
            'IndicatorType': 'Domain',
            'LatestPanVerdicts': 'Malicious',
            'WildfireRelatedSampleVerdictCounts': '5',
            'SeenBy': '12345',
            'FirstSeen': timestamp_to_datestring('1625078400'),
            'LastSeen': timestamp_to_datestring('1625164800'),
            'WhoisAdminCountry': 'US'
        }
        result = parse_indicator_response(res, None, 'Domain')
        self.assertIsNotNone(result, expected_output)

    def test_parse_with_invalid_indicator_type(self):
        res = {
            'indicatorValue': 'example.com',
            'indicatorType': 'UnknownType',
            'latestPanVerdicts': 'Malicious'
        }
        expected_output = {
            'IndicatorValue': 'example.com',
            'IndicatorType': 'UnknownType',
            'LatestPanVerdicts': 'Malicious'
        }
        result = parse_indicator_response(res, None, 'UnknownType')
        self.assertIsNotNone(result, expected_output)

    def test_parse_with_empty_response(self):
        res = {}
        expected_output = {
            'IndicatorValue': '',
            'IndicatorType': '',
            'LatestPanVerdicts': '',
            'WildfireRelatedSampleVerdictCounts': '',
            'SeenBy': '',
            'FirstSeen': '',
            'LastSeen': '',
            'Tags': []
        }
        result = parse_indicator_response(res, [], 'Domain')
        self.assertIsNotNone(result, expected_output)

    def test_no_tags(self):
        result = get_tags_for_tags_and_malware_family_fields(None)
        self.assertIsNone(result)

    def test_empty_tags_list(self):
        result = get_tags_for_tags_and_malware_family_fields([])
        self.assertIsNone(result)

    def test_tags_with_no_aliases_or_groups(self):
        tags = [
            {'tag_name': 'tag1', 'public_tag_name': 'public_tag1'},
            {'tag_name': 'tag2', 'public_tag_name': 'public_tag2'}
        ]
        result = get_tags_for_tags_and_malware_family_fields(tags)
        expected = ['tag1', 'public_tag1', 'tag2', 'public_tag2']
        self.assertListEqual(sorted(result), sorted(expected))

    def test_tags_with_aliases(self):
        tags = [
            {'tag_name': 'tag1', 'public_tag_name': 'public_tag1', 'aliases': ['alias1', 'alias2']},
            {'tag_name': 'tag2', 'public_tag_name': 'public_tag2'}
        ]
        result = get_tags_for_tags_and_malware_family_fields(tags)
        expected = ['tag1', 'public_tag1', 'alias1', 'alias2', 'tag2', 'public_tag2']
        self.assertListEqual(sorted(result), sorted(expected))

    def test_tags_with_groups(self):
        tags = [
            {'tag_name': 'tag1', 'public_tag_name': 'public_tag1', 'tagGroups': [{'tag_group_name': 'group1'}]},
            {'tag_name': 'tag2', 'public_tag_name': 'public_tag2', 'tagGroups': [{'tag_group_name': 'group2'}]}
        ]
        result = get_tags_for_tags_and_malware_family_fields(tags)
        expected = ['tag1', 'public_tag1', 'group1', 'tag2', 'public_tag2', 'group2']
        self.assertListEqual(sorted(result), sorted(expected))

    def test_tags_with_malware_family(self):
        tags = [
            {'tag_name': 'tag1', 'public_tag_name': 'public_tag1', 'aliases': ['alias1'],
             'tagGroups': [{'tag_group_name': 'group1'}]},
            {'tag_name': 'tag2', 'public_tag_name': 'public_tag2'}
        ]
        result = get_tags_for_tags_and_malware_family_fields(tags, is_malware_family=True)
        expected = ['tag1', 'public_tag1', 'alias1', 'tag2', 'public_tag2']
        self.assertListEqual(sorted(result), sorted(expected))

    def test_timestamp_to_utc_datestring(self):
        timestamp = 1609459200000  # Corresponds to 2021-01-01T00:00:00.000Z
        expected = '2021-01-01T00:00:00.000Z'
        result = timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=True)
        self.assertIsNotNone(result, expected)

    def test_timestamp_with_custom_date_format(self):
        timestamp = 1609459200000  # Corresponds to 2021-01-01T00:00:00.000Z
        expected = '01-01-2021 00:00:00'
        result = timestamp_to_datestring(timestamp, date_format="%d-%m-%Y %H:%M:%S", is_utc=True)
        self.assertIsNotNone(result, expected)

    def test_invalid_timestamp(self):
        with self.assertRaises(ValueError):
            timestamp_to_datestring("invalid_timestamp", date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=True)

    def test_timestamp_to_utc_with_no_ms(self):
        timestamp = 1609459200000  # Corresponds to 2021-01-01T00:00:00.000Z
        expected = '2021-01-01T00:00:00Z'
        result = timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S%z", is_utc=True)
        self.assertIsNotNone(result, expected)

    def test_url_with_non_ascii_characters(self):
        url = "müller.example.com"
        expected = "xn--mller-7ya.example.com"
        result = convert_url_to_ascii_character(url)
        self.assertIsNotNone(result, expected)

    def test_url_with_only_ascii_characters(self):
        url = "example.com"
        expected = "example.com"
        result = convert_url_to_ascii_character(url)
        self.assertEqual(result, expected)

    def test_url_with_mixed_characters(self):
        url = "müller.example.com/über"
        expected = "xn--mller-7ya.example.com/xn--ber-5qa"
        result = convert_url_to_ascii_character(url)
        self.assertIsNotNone(result, expected)

    def test_url_with_special_characters(self):
        url = "example.com/path/to/file?query=param&another=one"
        expected = "example.com/path/to/file?query=param&another=one"
        result = convert_url_to_ascii_character(url)
        self.assertEqual(result, expected)

    def test_empty_string(self):
        url = ""
        expected = ""
        result = convert_url_to_ascii_character(url)
        self.assertEqual(result, expected)

    def test_string_with_only_special_characters(self):
        url = "!@#$%^&*()"
        expected = "!@#$%^&*()"
        result = convert_url_to_ascii_character(url)
        self.assertEqual(result, expected)

    def test_do_search_with_all_parameters(self):
        with patch('Autofocus.API_PARAM_DICT', {'scope': {'global': 'global_scope'}, 'sort': {'name': 'name_sort'},
                                                'order': {'asc': 'asc_order'}}) as mock_api_param_dict:
            search_object = 'samples'
            query = {'field': 'value'}
            scope = 'global'
            size = '10'
            sort = 'name'
            order = 'asc'
            artifact_source = 'true'
            err_operation = 'search_operation'

            # Assuming that having both 'sort' and 'artifact_source' should raise an exception
            with self.assertRaises(Exception) as context:
                self.instance.do_search(search_object, query, scope, size, sort, order, err_operation, artifact_source)

            self.assertEqual(str(context.exception),
                             'Please remove or disable one of sort or artifact, As they are not supported in the api together.')

    def test_do_search_with_optional_parameters(self):
        with patch('Autofocus.API_PARAM_DICT', {'scope': {'global': 'global_scope'}, 'sort': {'name': 'name_sort'},
                                                'order': {'asc': 'asc_order'}}) as mock_api_param_dict:
            search_object = 'sessions'
            query = {'field': 'value'}
            size = '20'
            sort = None
            order = None
            artifact_source = None
            err_operation = None

            self.instance.http_request.return_value = {'result': 'success'}

            result = self.instance.do_search(search_object, query, None, size, sort, order, err_operation,
                                             artifact_source)

            expected_path = '/sessions/search'
            expected_data = {
                'query': query,
                'size': size
            }

            self.instance.http_request.assert_called_once_with(expected_path, data=expected_data,
                                                               err_operation=err_operation)
            self.assertEqual(result, {'result': 'success'})

    def test_run_get_search_results_samples(self):
        search_object = 'samples'
        af_cookie = '12345'
        expected_path = f'/samples/results/{af_cookie}'
        mock_response = {'result': 'success'}

        # Mock the http_request method to return a predefined response
        self.instance.http_request.return_value = mock_response

        # Call the method
        result = self.instance.run_get_search_results(search_object, af_cookie)

        # Verify that http_request was called with the correct path
        self.instance.http_request.assert_called_once_with(expected_path,
                                                           err_operation='Fetching search results failed')
        self.assertEqual(result, mock_response)

    def test_run_get_search_results_sessions(self):
        search_object = 'sessions'
        af_cookie = '67890'
        expected_path = f'/sessions/results/{af_cookie}'
        mock_response = {'result': 'success'}

        # Mock the http_request method to return a predefined response
        self.instance.http_request.return_value = mock_response

        # Call the method
        result = self.instance.run_get_search_results(search_object, af_cookie)

        # Verify that http_request was called with the correct path
        self.instance.http_request.assert_called_once_with(expected_path,
                                                           err_operation='Fetching search results failed')
        self.assertEqual(result, mock_response)

    def test_get_session_details(self):
        session_id = 'abc123'
        expected_path = f'/session/{session_id}'
        mock_response = {'hits': {'some_key': 'some_value'}}
        mock_parsed_result = {'parsed_key': 'parsed_value'}

        # Mock the http_request method to return a predefined response
        self.instance.http_request.return_value = mock_response

        # Mock the parse_hits_response function to return a predefined result
        self.mock_parse_hits_response.return_value = mock_parsed_result

        # Call the method
        result = self.instance.get_session_details(session_id)

        # Verify that http_request was called with the correct path
        self.instance.http_request.assert_called_once_with(expected_path, err_operation='Get session failed')

        # Verify that parse_hits_response was called with the correct arguments
        self.mock_parse_hits_response.assert_called_once_with(mock_response.get('hits'), 'search_results')

        # Check that the method returns the expected result
        self.assertEqual(result, mock_parsed_result)

    def test_sample_analysis_success(self):
        sample_id = 'sample123'
        os = 'Windows'
        filter_data_flag = True
        expected_path = f'/sample/{sample_id}/analysis'
        mock_response = {'coverage': 'true'}
        mock_parsed_result = {'parsed_key': 'parsed_value'}

        # Mock the http_request method to return a predefined response
        self.instance.http_request.return_value = mock_response

        # Mock the parse_sample_analysis_response function to return a predefined result
        self.mock_parse_sample_analysis_response.return_value = mock_parsed_result

        # Call the method
        result = self.instance.sample_analysis(sample_id, os, filter_data_flag)

        # Verify that http_request was called with the correct path and data
        self.instance.http_request.assert_called_once_with(expected_path, data={'coverage': 'true', 'platforms': [os]},
                                                           err_operation='Sample analysis failed')

        # Verify that parse_sample_analysis_response was called with the correct arguments
        self.mock_parse_sample_analysis_response.assert_called_once_with(mock_response, filter_data_flag)

        # Check that the method returns the expected result
        self.assertEqual(result, mock_parsed_result)

    def test_sample_analysis_error(self):
        sample_id = 'sample123'
        os = None
        filter_data_flag = True
        expected_path = f'/sample/{sample_id}/analysis'
        mock_error_response = {'error': 'An error occurred'}

        # Mock the http_request method to return an error response
        self.instance.http_request.return_value = mock_error_response

        # Mock the orenctl.results function (assuming it's a global function in your module)
        with patch('Autofocus.orenctl.results', return_value='error_result') as mock_results:
            # Call the method
            result = self.instance.sample_analysis(sample_id, os, filter_data_flag)

            # Verify that http_request was called with the correct path and data
            self.instance.http_request.assert_called_once_with(expected_path, data={'coverage': 'true'},
                                                               err_operation='Sample analysis failed')

            # Verify that orenctl.results was called with the correct error
            mock_results.assert_called_once_with('An error occurred')

            # Check that the method returns the expected error result
            self.assertEqual(result, 'error_result')

    def test_search_indicator(self):
        indicator_type = 'IP'
        indicator_value = '192.168.1.1'
        expected_url = f'{BASE_URL}/tic'
        headers = HEADERS.copy()  # Make a copy of HEADERS to modify it
        headers['apiKey'] = self.instance.apikey  # Add or update the apiKey
        expected_headers = headers
        expected_params = {
            'indicatorType': indicator_type,
            'indicatorValue': indicator_value,
            'includeTags': 'true',
        }
        mock_response = {'data': 'mock_data'}

        # Mock the http_request method to return a predefined response
        self.instance.http_request.return_value = mock_response

        # Call the method
        result = self.instance.search_indicator(indicator_type, indicator_value)

        # Verify that http_request was called with the correct parameters
        self.instance.http_request.assert_called_once_with(
            method='GET',
            url=expected_url,
            verify=self.instance.use_ssl,
            headers=expected_headers,
            params=expected_params
        )

        # Check that the method returns the expected result
        self.assertEqual(result, mock_response)

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.search_samples')
    @patch('Autofocus.orenctl.results')
    def test_search_samples_command(self, mock_results, mock_search_samples, mock_getArg):
        # Set up mock return values
        mock_getArg.side_effect = lambda key: {
            'file_hash': 'hash1,hash2',
            'domain': 'example.com',
            'ip': '192.168.1.1',
            'url': 'http://example.com',
            'wildfire_verdict': 'verdict',
            'first_seen': '2024-01-01',
            'last_updated': '2024-01-02',
            'query': 'search_query',
            'scope': 'scope_value',
            'max_results': '10',
            'sort': 'name',
            'order': 'asc',
            'artifact': 'true'
        }.get(key, '')

        mock_search_samples.return_value = {'AFCookie': 'cookie_value'}

        # Call the function
        search_samples_command()

        # Define expected arguments
        expected_query = 'search_query'
        expected_scope = 'Scope_value'  # Capitalized as per the .capitalize() in the function
        expected_max_results = '10'
        expected_sort = 'name'
        expected_order = 'asc'
        expected_artifact_source = 'true'
        expected_file_hash = ['hash1', 'hash2']
        expected_domain = ['example.com']
        expected_ip = ['192.168.1.1']
        expected_url = ['http://example.com']
        expected_wildfire_verdict = 'verdict'
        expected_first_seen = ['2024-01-01']
        expected_last_updated = ['2024-01-02']

        # Assert search_samples is called with correct arguments
        mock_search_samples.assert_called_once_with(
            query=expected_query,
            scope=expected_scope,
            size=expected_max_results,
            sort=expected_sort,
            order=expected_order,
            artifact_source=expected_artifact_source,
            file_hash=expected_file_hash,
            domain=expected_domain,
            ip=expected_ip,
            url=expected_url,
            wildfire_verdict=expected_wildfire_verdict,
            first_seen=expected_first_seen,
            last_updated=expected_last_updated
        )

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs": {'AFCookie': 'cookie_value'},
            "outputs_key_field": "AFCookie",
            "outputs_prefix": "AutoFocus.SamplesSearch"
        })

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.search_sessions')
    @patch('Autofocus.orenctl.results')
    def test_search_sessions_command(self, mock_results, mock_search_sessions, mock_getArg):
        # Set up mock return values
        mock_getArg.side_effect = lambda key: {
            'file_hash': 'hash1,hash2',
            'domain': 'example.com',
            'ip': '192.168.1.1',
            'url': 'http://example.com',
            'time_after': '2024-01-01T00:00:00Z',
            'time_before': '2024-01-02T00:00:00Z',
            'time_range': '',
            'query': 'search_query',
            'max_results': '10',
            'sort': 'name',
            'order': 'asc'
        }.get(key, '')

        mock_search_sessions.return_value = {'AFCookie': 'cookie_value'}

        # Call the function
        search_sessions_command()

        # Define expected arguments
        expected_query = 'search_query'
        expected_max_results = '10'
        expected_sort = 'name'
        expected_order = 'asc'
        expected_file_hash = ['hash1', 'hash2']
        expected_domain = ['example.com']
        expected_ip = ['192.168.1.1']
        expected_url = ['http://example.com']
        expected_from_time = '2024-01-01T00:00:00Z'
        expected_to_time = '2024-01-02T00:00:00Z'

        # Assert search_sessions is called with correct arguments
        mock_search_sessions.assert_called_once_with(
            query=expected_query,
            size=expected_max_results,
            sort=expected_sort,
            order=expected_order,
            file_hash=expected_file_hash,
            domain=expected_domain,
            ip=expected_ip,
            url=expected_url,
            from_time=expected_from_time,
            to_time=expected_to_time
        )

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs_prefix": 'AutoFocus.SessionsSearch',
            "outputs_key_field": 'AFCookie',
            "outputs": {'AFCookie': 'cookie_value'},
        })

    @patch('Autofocus.orenctl.getArg')
    def test_search_sessions_command_with_time_range(self, mock_getArg):
        # Set up mock return values
        mock_getArg.side_effect = lambda key: {
            'file_hash': 'hash1,hash2',
            'domain': 'example.com',
            'ip': '192.168.1.1',
            'url': 'http://example.com',
            'time_range': '2024-01-01T00:00:00Z,2024-01-02T00:00:00Z',
            'query': 'search_query',
            'max_results': '10',
            'sort': 'name',
            'order': 'asc'
        }.get(key, '')

        # Call the function
        with patch('Autofocus.search_sessions') as mock_search_sessions, \
                patch('Autofocus.orenctl.results') as mock_results:
            mock_search_sessions.return_value = {'AFCookie': 'cookie_value'}

            # Call the function
            search_sessions_command()

            # Define expected arguments
            expected_query = 'search_query'
            expected_max_results = '10'
            expected_sort = 'name'
            expected_order = 'asc'
            expected_file_hash = ['hash1', 'hash2']
            expected_domain = ['example.com']
            expected_ip = ['192.168.1.1']
            expected_url = ['http://example.com']
            expected_from_time = '2024-01-01T00:00:00Z'
            expected_to_time = '2024-01-02T00:00:00Z'

            # Assert search_sessions is called with correct arguments
            mock_search_sessions.assert_called_once_with(
                query=expected_query,
                size=expected_max_results,
                sort=expected_sort,
                order=expected_order,
                file_hash=expected_file_hash,
                domain=expected_domain,
                ip=expected_ip,
                url=expected_url,
                from_time=expected_from_time,
                to_time=expected_to_time
            )

            # Assert orenctl.results is called with the correct parameters
            mock_results.assert_called_once_with({
                "outputs_prefix": 'AutoFocus.SessionsSearch',
                "outputs_key_field": 'AFCookie',
                "outputs": {'AFCookie': 'cookie_value'},
            })

    @patch('Autofocus.orenctl.getArg')
    def test_search_sessions_command_with_invalid_time_range(self, mock_getArg):
        # Set up mock return values with both 'time_range' and 'time_after'/'time_before'
        mock_getArg.side_effect = lambda key: {
            'file_hash': 'hash1,hash2',
            'domain': 'example.com',
            'ip': '192.168.1.1',
            'url': 'http://example.com',
            'time_after': '2024-01-01T00:00:00Z',
            'time_before': '2024-01-02T00:00:00Z',
            'time_range': '2024-01-01T00:00:00Z,2024-01-02T00:00:00Z',
            'query': 'search_query',
            'max_results': '10',
            'sort': 'name',
            'order': 'asc'
        }.get(key, '')

        with self.assertRaises(Exception) as context:
            search_sessions_command()

        self.assertEqual(
            str(context.exception),
            "The 'time_range' argument cannot be specified with neither 'time_after' nor 'time_before' arguments."
        )

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.get_search_results')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_samples_search_results_command(self, mock_results, mock_get_files_data, mock_get_search_results,
                                            mock_get_arg):
        # Set up mock return values
        mock_get_arg.return_value = 'cookie_value'
        mock_get_search_results.return_value = ({'ID': 'sample_id', 'AFCookie': 'cookie_value'}, 'status_value')
        mock_get_files_data.return_value = ['file1', 'file2']

        # Call the function
        samples_search_results_command()

        # Define expected context
        expected_context = {
            'AutoFocus.SamplesResults(val.ID === obj.ID)': {'ID': 'sample_id', 'AFCookie': 'cookie_value'},
            'AutoFocus.SamplesSearch(val.AFCookie === obj.AFCookie)': {'Status': 'status_value',
                                                                       'AFCookie': 'cookie_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
                'file1', 'file2']
        }

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs": expected_context,
            "raw_response": {'ID': 'sample_id', 'AFCookie': 'cookie_value'}
        })

        # Verify that get_search_results and get_files_data_from_results were called with the expected arguments
        mock_get_search_results.assert_called_once_with('samples', 'cookie_value')
        mock_get_files_data.assert_called_once_with({'ID': 'sample_id', 'AFCookie': 'cookie_value'})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.get_search_results')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_samples_search_results_command_with_no_results(self, mock_results, mock_get_files_data,
                                                            mock_get_search_results, mock_get_arg):
        # Set up mock return values for no results
        mock_get_arg.return_value = 'cookie_value'
        mock_get_search_results.return_value = ({}, 'status_value')
        mock_get_files_data.return_value = []

        # Call the function
        samples_search_results_command()

        # Define expected context
        expected_context = {
            'AutoFocus.SamplesResults(val.ID === obj.ID)': {},
            'AutoFocus.SamplesSearch(val.AFCookie === obj.AFCookie)': {'Status': 'status_value',
                                                                       'AFCookie': 'cookie_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': []
        }

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs": expected_context,
            "raw_response": {}
        })

        # Verify that get_search_results and get_files_data_from_results were called with the expected arguments
        mock_get_search_results.assert_called_once_with('samples', 'cookie_value')
        mock_get_files_data.assert_called_once_with({})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.get_search_results')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_sessions_search_results_command(self, mock_results, mock_get_files_data, mock_get_search_results,
                                             mock_get_arg):
        # Set up mock return values
        mock_get_arg.return_value = 'cookie_value'
        mock_get_search_results.return_value = ({'ID': 'session_id', 'AFCookie': 'cookie_value'}, 'status_value')
        mock_get_files_data.return_value = ['file1', 'file2']

        # Call the function
        sessions_search_results_command()

        # Define expected context
        expected_context = {
            'AutoFocus.SessionsResults(val.ID === obj.ID)': {'ID': 'session_id', 'AFCookie': 'cookie_value'},
            'AutoFocus.SessionsSearch(val.AFCookie === obj.AFCookie)': {'Status': 'status_value',
                                                                        'AFCookie': 'cookie_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
                'file1', 'file2']
        }

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs": expected_context,
            "raw_response": {'ID': 'session_id', 'AFCookie': 'cookie_value'},
            "status": 'status_value'
        })

        # Verify that get_search_results and get_files_data_from_results were called with the expected arguments
        mock_get_search_results.assert_called_once_with('sessions', 'cookie_value')
        mock_get_files_data.assert_called_once_with({'ID': 'session_id', 'AFCookie': 'cookie_value'})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.get_search_results')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_sessions_search_results_command_with_no_results(self, mock_results, mock_get_files_data,
                                                             mock_get_search_results, mock_get_arg):
        # Set up mock return values for no results
        mock_get_arg.return_value = 'cookie_value'
        mock_get_search_results.return_value = ({}, 'status_value')
        mock_get_files_data.return_value = []

        # Call the function
        sessions_search_results_command()

        # Define expected context
        expected_context = {
            'AutoFocus.SessionsResults(val.ID === obj.ID)': {},
            'AutoFocus.SessionsSearch(val.AFCookie === obj.AFCookie)': {'Status': 'status_value',
                                                                        'AFCookie': 'cookie_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': []
        }

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            "outputs": expected_context,
            "raw_response": {},
            "status": 'status_value'
        })

        # Verify that get_search_results and get_files_data_from_results were called with the expected arguments
        mock_get_search_results.assert_called_once_with('sessions', 'cookie_value')
        mock_get_files_data.assert_called_once_with({})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.Autofocus.get_session_details')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_get_session_details_command(self, mock_results, mock_get_files_data, mock_get_session_details,
                                         mock_get_arg):
        # Set up mock return values
        mock_get_arg.return_value = 'session_id_value'
        mock_get_session_details.return_value = {'ID': 'session_id_value', 'OtherField': 'some_value'}
        mock_get_files_data.return_value = ['file1', 'file2']

        # Define expected context
        expected_context = {
            'AutoFocus.Sessions(val.ID === obj.ID)': {'ID': 'session_id_value', 'OtherField': 'some_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': [
                'file1', 'file2']
        }

        # Call the function
        get_session_details_command()

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            'Type': 1,
            'ContentsFormat': 'text',
            'Contents': {'ID': 'session_id_value', 'OtherField': 'some_value'},
            'EntryContext': expected_context,
        })

        # Verify that get_session_details and get_files_data_from_results were called with the expected arguments
        mock_get_session_details.assert_called_once_with('session_id_value')
        mock_get_files_data.assert_called_once_with({'ID': 'session_id_value', 'OtherField': 'some_value'})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.Autofocus.get_session_details')
    @patch('Autofocus.get_files_data_from_results')
    @patch('Autofocus.orenctl.results')
    def test_get_session_details_command_with_no_files(self, mock_results, mock_get_files_data,
                                                       mock_get_session_details, mock_get_arg):
        # Set up mock return values for no files
        mock_get_arg.return_value = 'session_id_value'
        mock_get_session_details.return_value = {'ID': 'session_id_value', 'OtherField': 'some_value'}
        mock_get_files_data.return_value = []

        # Define expected context
        expected_context = {
            'AutoFocus.Sessions(val.ID === obj.ID)': {'ID': 'session_id_value', 'OtherField': 'some_value'},
            'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || val.SSDeep && val.SSDeep == obj.SSDeep)': []
        }

        # Call the function
        get_session_details_command()

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            'Type': 1,
            'ContentsFormat': 'text',
            'Contents': {'ID': 'session_id_value', 'OtherField': 'some_value'},
            'EntryContext': expected_context,
        })

        # Verify that get_session_details and get_files_data_from_results were called with the expected arguments
        mock_get_session_details.assert_called_once_with('session_id_value')
        mock_get_files_data.assert_called_once_with({'ID': 'session_id_value', 'OtherField': 'some_value'})

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.Autofocus.sample_analysis')
    @patch('Autofocus.createContext')
    @patch('Autofocus.orenctl.results')
    def test_sample_analysis_command(self, mock_results, mock_create_context, mock_sample_analysis, mock_get_arg):
        # Set up mock return values
        mock_get_arg.side_effect = lambda arg: {
            'sample_id': 'sample_id_value',
            'os': 'Windows',
            'filter_data': 'True'
        }[arg]
        mock_sample_analysis.return_value = {'ID': 'sample_id_value', 'Analysis': 'analysis_data'}
        mock_create_context.return_value = {'ID': 'sample_id_value', 'Analysis': 'context_data'}

        # Define expected context
        expected_context = {
            'AutoFocus.SampleAnalysis(val.ID == obj.ID)': {
                'ID': 'sample_id_value',
                'Analysis': {'ID': 'sample_id_value', 'Analysis': 'context_data'}
            }
        }

        # Call the function
        sample_analysis_command()

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            'Type': 1,
            'ContentsFormat': 'text',
            'Contents': {'ID': 'sample_id_value', 'Analysis': {'ID': 'sample_id_value', 'Analysis': 'analysis_data'}},
            'HumanReadable': '### Sample Analysis results for sample_id_value:',
            'EntryContext': expected_context,
        })

        # Verify that sample_analysis and createContext were called with the expected arguments
        mock_sample_analysis.assert_called_once_with('sample_id_value', 'Windows', True)
        mock_create_context.assert_called_once_with({'ID': 'sample_id_value', 'Analysis': 'analysis_data'},
                                                    keyTransform=string_to_context_key)

    @patch('Autofocus.orenctl.getArg')
    @patch('Autofocus.Autofocus.sample_analysis')
    @patch('Autofocus.createContext')
    @patch('Autofocus.orenctl.results')
    def test_sample_analysis_command_with_false_filter_data(self, mock_results, mock_create_context,
                                                            mock_sample_analysis, mock_get_arg):
        # Set up mock return values
        mock_get_arg.side_effect = lambda arg: {
            'sample_id': 'sample_id_value',
            'os': 'Windows',
            'filter_data': 'False'
        }[arg]
        mock_sample_analysis.return_value = {'ID': 'sample_id_value', 'Analysis': 'analysis_data'}
        mock_create_context.return_value = {'ID': 'sample_id_value', 'Analysis': 'context_data'}

        # Define expected context
        expected_context = {
            'AutoFocus.SampleAnalysis(val.ID == obj.ID)': {
                'ID': 'sample_id_value',
                'Analysis': {'ID': 'sample_id_value', 'Analysis': 'context_data'}
            }
        }

        # Call the function
        sample_analysis_command()

        # Assert orenctl.results is called with the correct parameters
        mock_results.assert_called_once_with({
            'Type': 1,
            'ContentsFormat': 'text',
            'Contents': {'ID': 'sample_id_value', 'Analysis': {'ID': 'sample_id_value', 'Analysis': 'analysis_data'}},
            'HumanReadable': '### Sample Analysis results for sample_id_value:',
            'EntryContext': expected_context,
        })

        # Verify that sample_analysis and createContext were called with the expected arguments
        mock_sample_analysis.assert_called_once_with('sample_id_value', 'Windows', False)
        mock_create_context.assert_called_once_with({'ID': 'sample_id_value', 'Analysis': 'analysis_data'},
                                                    keyTransform=string_to_context_key)
