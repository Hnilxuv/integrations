import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import requests
from requests import HTTPError

from BoxV2 import BoxV2, search_content_command, get_folder_command, list_folder_items_command, list_users_command, \
    upload_file_command, get_current_user_command, update_user_command, list_user_events_command, \
    list_enterprise_events_command, date_to_timestamp, parse_date_range, format_time_range, remove_empty_elements, \
    arg_to_int, arg_to_boolean, parse_key_value_arg, arg_to_datetime, handle_string_arg, QueryHandler

DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


class TestBoxv2(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.instance = BoxV2()
        self.box_v2 = BoxV2()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        box = BoxV2()

        result = box.http_request('GET', '/test_url')

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

        box = BoxV2()

        with self.assertRaises(HTTPError):
            box.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'first_fetch': 'first_fetch',
            'default_as_user': 'default_as_user',
            'search_user_id': 'search_user_id',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        box = BoxV2()

        self.assertEqual(box.first_fetch, 'first_fetch')
        self.assertTrue(box.insecure)
        self.assertEqual(box.proxy, 'http://proxy.example.com')
        self.assertIsInstance(box.session, requests.Session)

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    @patch('BoxV2.QueryHandler')
    def test_search_content_command(self, MockQueryHandler, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            "type": "file",
            "ancestor_folder_ids": ["12345"],
            "item_name": "example",
            "item_description": "description",
            "comments": "comments",
            "tag": "tag",
            "created_range": "2023-01-01 to 2023-12-31",
            "file_extensions": [".pdf", ".docx"],
            "limit": 10,
            "offset": 0,
            "owner_uids": ["owner1"],
            "trash_content": False,
            "updated_at_range": "2023-01-01 to 2023-12-31",
            "query": "search term"
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.search_content.return_value = {
            'entries': [
                {'id': '1', 'name': 'file1', 'description': 'desc1'},
                {'id': '2', 'name': 'file2', 'description': 'desc2'}
            ]
        }

        mock_query_handler = MockQueryHandler.return_value

        with patch('BoxV2.orenctl.results') as mock_results:
            search_content_command()
            expected_results = {
                'outputs_prefix': 'Box.Query',
                'outputs_key_field': 'id',
                'outputs': [
                    {'id': '1', 'name': 'file1', 'description': 'desc1'},
                    {'id': '2', 'name': 'file2', 'description': 'desc2'}
                ]
            }
            mock_results.assert_called_once_with(expected_results)

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    def test_get_folder_command(self, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'folder_id': '12345',
            'as_user': 'user123'
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.get_folder.return_value = {
            'id': '12345',
            'name': 'Test Folder',
            'item_collection': [
                {'id': 'file1', 'name': 'file1.txt'},
                {'id': 'file2', 'name': 'file2.txt'}
            ],
            'created_at': '2023-01-01T00:00:00Z'
        }

        with patch('orenctl.results') as mock_results:
            get_folder_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    @patch('BoxV2.arg_to_int')
    def test_list_folder_items_command(self, mock_arg_to_int, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'folder_id': '12345',
            'as_user': 'user123',
            'limit': '50',
            'offset': '10',
            'sort': 'name'
        }.get(key, None)

        mock_arg_to_int.side_effect = lambda arg_name, arg, default: int(arg) if arg else default

        mock_client = MockBoxV2.return_value
        mock_client.list_folder_items.return_value = {
            'id': '12345',
            'item_collection': [
                {'id': 'file1', 'name': 'file1.txt'},
                {'id': 'file2', 'name': 'file2.txt'}
            ],
            'created_at': '2023-01-01T00:00:00Z'
        }

        with patch('orenctl.results') as mock_results:
            list_folder_items_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    @patch('BoxV2.arg_to_int')
    def test_list_users_command(self, mock_arg_to_int, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'fields': 'id,name,email',
            'filter_term': 'test_user',
            'limit': '50',
            'offset': '10',
            'user_type': 'admin'
        }.get(key, None)

        mock_arg_to_int.side_effect = lambda arg_name, arg, default: int(arg) if arg else default

        mock_client = MockBoxV2.return_value
        mock_client.list_users.return_value = {
            'entries': [
                {'id': 'user1', 'name': 'User One', 'email': 'userone@example.com'},
                {'id': 'user2', 'name': 'User Two', 'email': 'usertwo@example.com'}
            ],
            'total_count': 2
        }

        with patch('orenctl.results') as mock_results:
            list_users_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    def test_upload_file_command(self, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'file_name': 'test_file.txt',
            'folder_id': '12345',
            'as_user': 'user123'
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.upload_file.return_value = {
            'entities': {'id': 'file123', 'name': 'test_file.txt'}
        }

        with patch('orenctl.results') as mock_results:
            upload_file_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    def test_get_current_user_command(self, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'as_user': 'user123'
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.get_current_user.return_value = {
            'id': 'user123',
            'name': 'Test User'
        }

        with patch('orenctl.results') as mock_results:
            get_current_user_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    def test_update_user_command(self, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'as_user': 'admin_user',
            'user_id': 'user123',
            'login': 'test_user',
            'name': 'Test User',
            'role': 'user',
            'language': 'en',
            'is_sync_enabled': 'true',
            'job_title': 'Developer',
            'phone': '1234567890',
            'address': '123 Test St',
            'space_amount': '1000',
            'tracking_codes': 'key1:value1,key2:value2',
            'can_see_managed_users': 'true',
            'timezone': 'UTC',
            'is_exempt_from_device_limits': 'false',
            'is_exempt_from_login_verification': 'true',
            'is_external_collab_restricted': 'false',
            'status': 'active'
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.create_update_user.return_value = {
            'id': 'user123',
            'login': 'test_user',
            'name': 'Test User'
        }

        with patch('orenctl.results') as mock_results:
            update_user_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    def test_list_user_events_command(self, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'as_user': 'admin_user',
            'stream_type': 'all',
            'limit': '5'
        }.get(key, None)

        mock_client = MockBoxV2.return_value
        mock_client.list_events.return_value = {
            'entries': [
                {'event_id': 'event1', 'type': 'upload', 'timestamp': '2024-08-27T12:00:00Z'},
                {'event_id': 'event2', 'type': 'delete', 'timestamp': '2024-08-27T12:05:00Z'}
            ]
        }

        with patch('orenctl.results') as mock_results:
            list_user_events_command()

    @patch('BoxV2.BoxV2')
    @patch('BoxV2.orenctl')
    @patch('BoxV2.arg_to_datetime')
    def test_list_enterprise_events_command(self, mock_arg_to_datetime, mock_orenctl, MockBoxV2):
        mock_orenctl.getArg.side_effect = lambda key: {
            'as_user': 'admin_user',
            'limit': '5',
            'created_after': '2024-08-01T00:00:00Z'
        }.get(key, None)

        mock_arg_to_datetime.return_value = datetime.strptime('2024-08-01T00:00:00Z', '%Y-%m-%dT%H:%M:%SZ')

        mock_client = MockBoxV2.return_value
        mock_client.list_events.return_value = {
            'entries': [
                {'event_id': 'event1', 'type': 'upload', 'timestamp': '2024-08-27T12:00:00Z'},
                {'event_id': 'event2', 'type': 'delete', 'timestamp': '2024-08-27T12:05:00Z'}
            ]
        }

        with patch('orenctl.results') as mock_results:
            list_enterprise_events_command()

    def test_date_str_to_timestamp(self):
        date_str = '2024-08-27T12:00:00'
        expected_timestamp = int(time.mktime(time.strptime(date_str, '%Y-%m-%dT%H:%M:%S')) * 1000)

        result = date_to_timestamp(date_str)
        self.assertEqual(result, expected_timestamp)

    def test_datetime_to_timestamp(self):
        date_dt = datetime(2024, 8, 27, 12, 0, 0)
        expected_timestamp = int(time.mktime(date_dt.timetuple()) * 1000)

        result = date_to_timestamp(date_dt)
        self.assertEqual(result, expected_timestamp)

    def test_date_range_with_format(self):
        date_range = '1 day'
        date_format = '%Y-%m-%d %H:%M:%S'
        start, end = parse_date_range(date_range, date_format=date_format, to_timestamp=False, timezone_offset=0,
                                      utc=True)
        expected_start = (datetime.now(timezone.utc) - timedelta(days=1)).strftime(date_format)
        expected_end = datetime.now(timezone.utc).strftime(date_format)

        self.assertEqual(start, expected_start)
        self.assertEqual(end, expected_end)

    def test_invalid_date_range(self):
        with self.assertRaises(ValueError):
            parse_date_range('invalid range', to_timestamp=False, timezone_offset=0, utc=True)

    def test_invalid_unit(self):
        with self.assertRaises(ValueError):
            parse_date_range('2 invalidunit', to_timestamp=False, timezone_offset=0, utc=True)

    def test_invalid_timezone(self):
        with self.assertRaises(ValueError):
            parse_date_range('2 hours', to_timestamp=False, timezone_offset='invalid', utc=True)

    def test_valid_date_range(self):
        date_range = '2 hours'
        start, end = parse_date_range(date_range, to_timestamp=False, timezone_offset=0, utc=True)
        expected_start = datetime.now(timezone.utc) - timedelta(hours=2)
        expected_end = datetime.now(timezone.utc)

        self.assertAlmostEqual(start, expected_start, delta=timedelta(seconds=1))
        self.assertAlmostEqual(end, expected_end, delta=timedelta(seconds=1))

    def test_format_time_range_valid_date_range(self):
        range_arg = '2 hours'
        result = format_time_range(range_arg)
        self.assertIsNotNone(result)

    def test_none_date_range(self):
        result = format_time_range(None)
        self.assertIsNone(result)

    def test_empty_dict(self):
        self.assertIsNotNone(remove_empty_elements({}), {})

    def test_empty_list(self):
        self.assertIsNotNone(remove_empty_elements([]), [])

    def test_dict_with_nested_empty_values(self):
        # Kiểm tra dictionary với các giá trị rỗng lồng nhau
        self.assertEqual(
            remove_empty_elements({
                'key1': {'subkey1': 'value1', 'subkey2': None},
                'key2': {'subkey1': [], 'subkey2': 'value2'},
            }),
            {
                'key1': {'subkey1': 'value1'},
                'key2': {'subkey2': 'value2'}
            }
        )

    def test_valid_string(self):
        self.assertEqual(arg_to_int('123', 'test_arg'), 123)

    def test_valid_integer(self):
        self.assertEqual(arg_to_int(456, 'test_arg'), 456)

    def test_none_with_default(self):
        self.assertEqual(arg_to_int(None, 'test_arg', default=789), 789)

    def test_none_without_default(self):
        self.assertIsNone(arg_to_int(None, 'test_arg'))

    def test_invalid_string(self):
        with self.assertRaises(ValueError) as context:
            arg_to_int('abc', 'test_arg')
        self.assertEqual(str(context.exception), 'Invalid number: "test_arg"="abc"')

    def test_invalid_type(self):
        with self.assertRaises(ValueError) as context:
            arg_to_int([], 'test_arg')
        self.assertEqual(str(context.exception), 'Invalid number: "test_arg"')

    def test_boolean_true(self):
        self.assertTrue(arg_to_boolean(True))

    def test_boolean_false(self):
        self.assertFalse(arg_to_boolean(False))

    def test_string_false(self):
        self.assertFalse(arg_to_boolean('false'))

    def test_non_string_non_boolean(self):
        with self.assertRaises(ValueError):
            arg_to_boolean(123)

    def test_empty_string(self):
        with self.assertRaises(ValueError):
            arg_to_boolean('')

    def test_valid_key_value_pairs(self):
        result = parse_key_value_arg('key1:value1,key2:value2')
        expected = [{'key1': 'value1'}, {'key2': 'value2'}]
        self.assertEqual(result, expected)

    def test_missing_value(self):
        with self.assertRaises(ValueError):
            parse_key_value_arg('key1:')

    def test_empty_input(self):
        self.assertIsNone(parse_key_value_arg(''))

    def test_missing_colon(self):
        with self.assertRaises(ValueError):
            parse_key_value_arg('key1value1')

    def test_none_arg(self):
        with self.assertRaises(ValueError):
            arg_to_datetime(None, arg_name="test_arg", required=True)

    def test_numeric_arg(self):
        # Test with numeric timestamp
        timestamp = datetime(2023, 1, 1, tzinfo=timezone.utc).timestamp()
        dt = arg_to_datetime(timestamp)
        self.assertEqual(dt, datetime(2023, 1, 1, tzinfo=timezone.utc))

    def test_non_numeric_and_non_string(self):
        # Test with unsupported type
        with self.assertRaises(ValueError):
            arg_to_datetime([2023, 1, 1])

    @patch('BoxV2.check_value_error')  # Adjust the import path accordingly
    def test_valid_date(self, mock_check_value_error):
        date_str = '2023-01-01 12:00:00'
        expected_date = datetime(2023, 1, 1, 12, 0, 0)
        result = handle_string_arg(date_str, settings={'TIMEZONE': 'UTC'}, arg_name='date')
        self.assertEqual(result, expected_date)
        mock_check_value_error.assert_not_called()

    @patch('BoxV2.orenctl')  # Adjust the import path accordingly
    @patch('BoxV2.format_time_range')
    def setUp(self, mock_format_time_range, mock_orenctl):
        mock_orenctl.getParam = MagicMock()
        mock_orenctl.getParam.side_effect = [
            'type_value',  # type
            'ancestor_folder_ids_value',  # ancestor_folder_ids
            'item_name_value',  # item_name
            'item_description_value',  # item_description
            'comments_value',  # comments
            'tag_value',  # tag
            'created_range_value',  # created_range
            'file_extensions_value',  # file_extensions
            'limit_value',  # limit
            'offset_value',  # offset
            'owner_uids_value',  # owner_user_ids
            'trash_content_value',  # trash_content
            'updated_at_range_value',  # updated_at_range
            'query_value',  # query
        ]
        mock_format_time_range.return_value = ('start', 'end')

        self.query_handler = QueryHandler(args='test_args')

    def test_initializations(self):
        self.assertEqual(self.query_handler.content_types, ['name', 'description', 'tag', 'comments'])
        self.assertEqual(self.query_handler.type, 'type_value')
        self.assertEqual(self.query_handler.ancestor_folder_ids, 'ancestor_folder_ids_value')
        self.assertEqual(self.query_handler.created_range, ('start', 'end'))
        self.assertEqual(self.query_handler.file_extensions, 'file_extensions_value')
        self.assertEqual(self.query_handler.limit, 'limit_value')
        self.assertEqual(self.query_handler.offset, 'offset_value')
        self.assertEqual(self.query_handler.owner_user_ids, 'owner_uids_value')
        self.assertEqual(self.query_handler.trash_content, 'trash_content_value')
        self.assertEqual(self.query_handler.updated_at_range, ('start', 'end'))
        self.assertEqual(self.query_handler.query, 'comments_value')
        self.assertEqual(self.query_handler.args, 'test_args')

    @patch('BoxV2.remove_empty_elements')
    @patch('BoxV2.BoxV2.http_request')
    def test_list_users(self, mock_http_request, mock_remove_empty_elements):
        instance = BoxV2()

        # Mock responses
        mock_remove_empty_elements.return_value = {
            'fields': 'id,name,email',
            'filter_term': 'active',
            'limit': 10,
            'offset': 0,
            'user_type': 'admin'
        }
        mock_http_request.return_value = 'response_data'

        # Call method
        result = instance.list_users(
            fields='id,name,email',
            filter_term='active',
            limit=10,
            offset=0,
            user_type='admin'
        )

        # Assertions
        mock_remove_empty_elements.assert_called_once_with({
            'fields': 'id,name,email',
            'filter_term': 'active',
            'limit': 10,
            'offset': 0,
            'user_type': 'admin'
        })
        mock_http_request.assert_called_once_with(
            method='GET',
            url_suffix='/users/',
            params=mock_remove_empty_elements.return_value
        )
        self.assertEqual(result, 'response_data')

    def test_parse_date_range_months(self):
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=6 * 30)
        result_start_time, result_end_time = parse_date_range("6 months")
        self.assertAlmostEqual(result_start_time, start_time, delta=timedelta(seconds=1))
        self.assertAlmostEqual(result_end_time, end_time, delta=timedelta(seconds=1))

    def test_parse_date_range_years(self):
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=2 * 365)
        result_start_time, result_end_time = parse_date_range("2 years")
        self.assertAlmostEqual(result_start_time, start_time, delta=timedelta(seconds=1))
        self.assertAlmostEqual(result_end_time, end_time, delta=timedelta(seconds=1))

    def test_parse_date_range_minutes(self):
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=5)
        result_start_time, result_end_time = parse_date_range("5 minutes")
        self.assertAlmostEqual(result_start_time, start_time, delta=timedelta(seconds=1))
        self.assertAlmostEqual(result_end_time, end_time, delta=timedelta(seconds=1))

    def test_timezone_offset(self):
        start_time, end_time = parse_date_range("1 hour", timezone_offset=2, utc=False)
        expected_start_time = datetime.now() - timedelta(hours=1 - 2)  # Adjust for timezone
        expected_end_time = datetime.now() + timedelta(hours=2)

        self.assertAlmostEqual(start_time.timestamp(), expected_start_time.timestamp(), delta=1)
        self.assertAlmostEqual(end_time.timestamp(), expected_end_time.timestamp(), delta=1)

    def test_to_timestamp(self):
        start_timestamp, end_timestamp = parse_date_range("30 minutes", to_timestamp=True, utc=True)
        expected_start_time = datetime.now(timezone.utc) - timedelta(minutes=30)
        expected_end_time = datetime.now(timezone.utc)

        self.assertAlmostEqual(start_timestamp, expected_start_time.timestamp(), delta=1)
        self.assertAlmostEqual(end_timestamp, expected_end_time.timestamp(), delta=1)

    @patch('orenctl.getParam')
    def test_prepare_params_object(self, mock_get_param):
        mock_get_param.side_effect = lambda x: {
            'type': 'document',
            'ancestor_folder_ids': '123',
            'item_name': 'report',
            'item_description': None,
            'comments': None,
            'tag': None,
            'created_range': None,
            'file_extensions': '.pdf',
            'limit': '10',
            'offset': '0',
            'owner_uids': None,
            'trash_content': 'false',
            'updated_at_range': None,
            'query': None
        }.get(x, '')

        query_handler = QueryHandler(args={})

        params = query_handler.prepare_params_object()
        expected_params = {
            'content_types': ['name'],
            'type': 'document',
            'ancestor_folder_ids': '123',
            'query': 'report',
            'file_extensions': '.pdf',
            'limit': '10',
            'offset': '0',
            'trash_content': 'false',
        }

        self.assertEqual(params, expected_params)

    @patch('BoxV2.BoxV2.list_users')
    def test_search_user_ids_success(self, mock_list_users):
        mock_list_users.return_value = {
            'entries': [{'id': '12345', 'name': 'test_user'}]
        }
        box_v2 = BoxV2()

        user_id = box_v2.search_user_ids('test_user')

        self.assertEqual(user_id, '12345')

    @patch('BoxV2.BoxV2.list_users')
    def test_search_user_ids_no_entries(self, mock_list_users):
        mock_list_users.return_value = {
            'entries': []
        }

        box_v2 = BoxV2()

        with self.assertRaises(ValueError) as context:
            box_v2.search_user_ids('nonexistent_user')

    @patch('BoxV2.BoxV2.search_user_ids')
    @patch('BoxV2.BoxV2.handle_default_user')
    def test_handle_as_user_valid_email_and_auto_detect(self, mock_handle_default_user, mock_search_user_ids):
        mock_handle_default_user.return_value = 'test@example.com'
        mock_search_user_ids.return_value = '12345'

        box_v2 = BoxV2()
        box_v2.search_user_id = True

        user_id = box_v2.handle_as_user('test@example.com')

        self.assertEqual(user_id, '12345')

    @patch('BoxV2.BoxV2.handle_default_user')
    def test_handle_as_user_valid_email_without_auto_detect(self, mock_handle_default_user):
        mock_handle_default_user.return_value = 'test@example.com'

        box_v2 = BoxV2()
        box_v2.search_user_id = False

        with self.assertRaises(ValueError) as context:
            box_v2.handle_as_user('test@example.com')

        self.assertIn(
            "The current as-user is invalid. Please either specify the user ID, or enable the auto-detect user IDs setting.",
            str(context.exception))

    @patch('BoxV2.BoxV2.handle_default_user')
    def test_handle_as_user_invalid_email(self, mock_handle_default_user):
        mock_handle_default_user.return_value = 'invalid-email'

        box_v2 = BoxV2()

        result = box_v2.handle_as_user('invalid-email')

        self.assertEqual(result, 'invalid-email')

    @patch('BoxV2.BoxV2.__init__', return_value=None)
    def test_handle_default_user_no_default(self, mock_init):
        box_v2 = BoxV2()
        box_v2.default_as_user = None

        with self.assertRaises(ValueError) as context:
            box_v2.handle_default_user(None)

        self.assertIn(
            "A user ID has not been specified. Please configure a default, or add the user ID in the as_user argument.",
            str(context.exception))

    @patch('BoxV2.BoxV2.__init__', return_value=None)
    def test_handle_default_user_with_default(self, mock_init):
        box_v2 = BoxV2()
        box_v2.default_as_user = 'default_user_id'

        result = box_v2.handle_default_user(None)

        self.assertEqual(result, 'default_user_id')

    @patch('BoxV2.BoxV2.__init__', return_value=None)
    def test_handle_default_user_with_provided_user(self, mock_init):
        box_v2 = BoxV2()
        box_v2.default_as_user = None

        result = box_v2.handle_default_user('provided_user_id')

        self.assertEqual(result, 'provided_user_id')

    @patch('BoxV2.BoxV2.__init__', return_value=None)
    def test_search_content(self, mock_init):
        box_v2 = BoxV2()
        as_user = 'test_user'
        query_object = MagicMock()
        query_object.prepare_params_object.return_value = {'param1': 'value1'}

        box_v2.handle_as_user.return_value = 'validated_user_id'

        box_v2.http_request.return_value = {'result': 'success'}

        result = self.box_v2.search_content(as_user, query_object)

        self.assertEqual(self.box_v2.session.headers['As-User'], 'validated_user_id')

        self.assertEqual(result, {'result': 'success'})

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    @patch('requests.Session.request')
    def test_search_content(self, mock_session, mock_handle_as_user, mock_http_request):
        box_v2_instance = BoxV2()

        as_user = "test_user"
        query_object = MagicMock()
        query_object.prepare_params_object.return_value = {"query": "test_query"}

        mock_handle_as_user.return_value = "validated_test_user"

        # Act
        result = box_v2_instance.search_content(as_user, query_object)

        self.assertIsNotNone(result)

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    def test_get_folder(self, mock_handle_as_user, mock_http_request):
        #  BoxV2
        box_v2_instance = BoxV2()

        folder_id = '12345'
        as_user = 'test_user'

        mock_handle_as_user.return_value = 'validated_test_user'
        mock_http_request.return_value = {'folder': 'data'}

        result = box_v2_instance.get_folder(folder_id, as_user)

        mock_handle_as_user.assert_called_once_with(as_user_arg=as_user)

        self.assertEqual(box_v2_instance.session.headers.get('As-User'), 'validated_test_user')

        self.assertEqual(result, {'folder': 'data'})

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    def test_list_folder_items(self, mock_handle_as_user, mock_http_request):
        box_v2_instance = BoxV2()

        folder_id = '12345'
        as_user = 'test_user'
        limit = 10
        offset = 0
        sort = 'name'

        mock_handle_as_user.return_value = 'validated_test_user'
        mock_http_request.return_value = {'items': 'data'}

        result = box_v2_instance.list_folder_items(folder_id, as_user, limit, offset, sort)
        self.assertIsNotNone(result)

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    def test_create_upload_session(self, mock_handle_as_user, mock_http_request):
        box_v2_instance = BoxV2()

        file_name = 'test_file.txt'
        file_size = 123456
        folder_id = '67890'
        as_user = 'test_user'

        mock_handle_as_user.return_value = 'validated_test_user'
        mock_http_request.return_value = {'upload_url': 'https://upload.url'}

        result = box_v2_instance.create_upload_session(file_name, file_size, folder_id, as_user)

        self.assertIsNotNone(result)

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    def test_get_current_user(self, mock_handle_as_user, mock_http_request):
        box_v2_instance = BoxV2()

        as_user = "test_user"
        validated_as_user = "validated_test_user"
        mock_handle_as_user.return_value = validated_as_user
        expected_response = {"id": "user_id", "name": "Test User"}
        mock_http_request.return_value = expected_response

        result = box_v2_instance.get_current_user(as_user)
        self.assertIsNotNone(result)

    @patch('BoxV2.BoxV2.http_request')
    @patch('BoxV2.BoxV2.handle_as_user')
    def test_list_events(self, mock_handle_as_user, mock_http_request):
        box_v2_instance = BoxV2()

        as_user = "test_user"
        stream_type = "admin_logs"
        created_after = "2024-01-01T00:00:00Z"
        limit = 50
        validated_as_user = "validated_test_user"
        mock_handle_as_user.return_value = validated_as_user
        expected_response = {"events": [{"id": "event_id", "type": "event_type"}]}
        mock_http_request.return_value = expected_response

        result = box_v2_instance.list_events(as_user, stream_type, created_after, limit)

        self.assertIsNotNone(result)