import json
import os
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

import orenctl
from Cherwell import Cherwell, createContext, date_to_timestamp, get_access_token, request_new_access_token, \
    http_request, SECURED, parse_response, get_new_access_token, HTTP_CODES, make_request, fileResult, formats, \
    validate_query_list, parse_string_query_to_list, build_query_dict, build_query_dict_list, \
    raise_or_return_error, parse_fields_from_business_object_list, query_business_object, query_business_object_string, \
    upload_attachment, download_attachments, attachment_results, resolve_business_object_id_by_name, \
    build_business_object_json, create_business_object, update_business_object, get_business_object, \
    get_key_value_dict_from_template, cherwell_dict_parser, HEADERS, entryTypes, BUSINESS_OBJECT_CONTEXT_KEY, \
    create_business_object_command, update_business_object_command, get_business_object_command, \
    download_attachments_command, upload_attachment_command, get_attachments_info_command, remove_attachment_command, \
    query_business_object_command, cherwell_run_saved_search_command, cherwell_get_business_object_id_command, \
    cherwell_get_business_object_summary_command

BASE_URL = ""
CLIENT_ID = ""
USERNAME = ""
PASSWORD = ""
IS_PY3 = True


class TestCherwell(unittest.TestCase):

    @patch('orenctl.getParam')
    @patch('requests.Session')
    def setUp(self, mock_session, mock_get_param):
        mock_get_param.side_effect = lambda x: {
            "url": "http://test-url.com",
            "user_name": "test_user",
            "password": "test_password",
            "client_id": "test_client_id",
            "proxy": "http://test-proxy.com"
        }.get(x)

        self.mock_session_instance = mock_session.return_value
        self.cherwell = Cherwell()

    @patch.object(Cherwell, 'http_request')
    def test_http_request_success(self, mock_http_request):
        mock_http_request.return_value = {"success": True}

        response = self.cherwell.http_request("GET", "http://test-url.com")
        self.assertIsNotNone(response, {"success": True})

    @patch('orenctl.results')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_results):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.content = b"Bad request"
        mock_request.return_value = mock_response

        # Check that ValueError is raised on failed request
        with self.assertRaises(ValueError):
            self.cherwell.http_request("GET", "http://test-url.com")

        # Check that the error message was logged via orenctl
        mock_results.assert_called_once_with(orenctl.error("Http request error: 400 b'Bad request'"))

    @patch('Cherwell.createContextSingle')  # Mock createContextSingle
    def test_createContext_with_list(self, mock_createContextSingle):
        mock_createContextSingle.side_effect = lambda d, id, kt, rn: f"Processed: {d}"

        data = [{"name": "Alice"}, {"name": "Bob"}]

        result = createContext(data, id=1, keyTransform=str.upper, removeNull=True)

        self.assertEqual(mock_createContextSingle.call_count, 2)

        expected_result = ["Processed: {'name': 'Alice'}", "Processed: {'name': 'Bob'}"]
        self.assertIsNotNone(result, expected_result)

    @patch('Cherwell.createContextSingle')  # Mock createContextSingle
    def test_createContext_with_tuple(self, mock_createContextSingle):
        mock_createContextSingle.side_effect = lambda d, id, kt, rn: f"Processed: {d}"

        data = ({"name": "Charlie"}, {"name": "David"})

        result = createContext(data, id=2, keyTransform=str.lower, removeNull=False)

        self.assertEqual(mock_createContextSingle.call_count, 2)

        expected_result = ["Processed: {'name': 'Charlie'}", "Processed: {'name': 'David'}"]
        self.assertIsNotNone(result, expected_result)

    def test_date_str_conversion(self):
        date_str = "2024-08-19T12:34:56"
        expected_timestamp = int(time.mktime(time.strptime(date_str, '%Y-%m-%dT%H:%M:%S')) * 1000)
        result = date_to_timestamp(date_str)
        self.assertIsNotNone(result, expected_timestamp)

    def test_datetime_obj_conversion(self):
        date_dt = datetime(2024, 8, 19, 12, 34, 56)
        expected_timestamp = int(time.mktime(date_dt.timetuple()) * 1000)
        result = date_to_timestamp(date_dt)
        self.assertIsNotNone(result, expected_timestamp)

    @patch('Cherwell.getIntegrationContext')
    @patch('Cherwell.date_to_timestamp')
    @patch('Cherwell.get_new_access_token')
    def test_get_access_token_new_token(self, mock_get_new_access_token, mock_date_to_timestamp,
                                        mock_get_integration_context):
        mock_get_integration_context.return_value = {'access_token': 'old_token', 'token_expiration_time': 0}
        mock_date_to_timestamp.return_value = int(
            datetime(2024, 8, 19, 12, 34, 56, tzinfo=timezone.utc).timestamp() * 1000)
        mock_get_new_access_token.return_value = 'new_token'

        result = get_access_token(new_token=True, is_fetch=False)

        # Verify that get_new_access_token is called and returned result
        mock_get_new_access_token.assert_called_once_with(is_fetch=False)
        self.assertIsNotNone(result, 'new_token')

    @patch('Cherwell.getIntegrationContext')
    @patch('Cherwell.date_to_timestamp')
    @patch('Cherwell.get_new_access_token')
    def test_get_access_token_expired_token(self, mock_get_new_access_token, mock_date_to_timestamp,
                                            mock_get_integration_context):
        mock_get_integration_context.return_value = {'access_token': 'old_token', 'token_expiration_time': 1000}
        mock_date_to_timestamp.return_value = int(
            datetime(2024, 8, 19, 12, 34, 56, tzinfo=timezone.utc).timestamp() * 1000)
        mock_get_new_access_token.return_value = 'new_token'

        result = get_access_token(new_token=False, is_fetch=False)

        mock_get_new_access_token.assert_called_once_with(is_fetch=False)
        self.assertIsNotNone(result, 'new_token')

    @patch('Cherwell.getIntegrationContext')
    @patch('Cherwell.http_request')
    def test_request_new_access_token_using_refresh(self, mock_http_request, mock_get_integration_context):
        mock_get_integration_context.return_value = {'refresh_token': 'refresh_token_value'}
        mock_http_request.return_value = 'mock_response'

        result = request_new_access_token(using_refresh=True)

        expected_payload = 'client_id=&grant_type=refresh_token&refresh_token=refresh_token_value'
        expected_headers = {
            'Accept': "application/json",
            'Content-Type': "application/x-www-form-urlencoded",
        }
        mock_http_request.assert_called_once_with('POST', BASE_URL + "token", expected_payload,
                                                  custom_headers=expected_headers)
        self.assertIsNotNone(result, 'mock_response')

    @patch('Cherwell.getIntegrationContext')
    @patch('Cherwell.http_request')
    def test_request_new_access_token_without_refresh(self, mock_http_request, mock_get_integration_context):
        mock_get_integration_context.return_value = {'refresh_token': 'refresh_token_value'}
        mock_http_request.return_value = 'mock_response'

        result = request_new_access_token(using_refresh=False)

        expected_payload = f'client_id={CLIENT_ID}&grant_type=password&username={USERNAME}&password={PASSWORD}'
        expected_headers = {
            'Accept': "application/json",
            'Content-Type': "application/x-www-form-urlencoded",
        }
        mock_http_request.assert_called_once_with('POST', BASE_URL + "token", expected_payload,
                                                  custom_headers=expected_headers)
        self.assertIsNotNone(result, 'mock_response')

    @patch('requests.request')
    @patch('Cherwell.build_headers')
    def test_http_request_success(self, mock_build_headers, mock_requests_request):
        mock_build_headers.return_value = {'Authorization': 'Bearer token', 'Custom-Header': 'value'}
        mock_requests_request.return_value = MagicMock(status_code=200, text='response_text')

        method = 'POST'
        url = 'https://example.com/api'
        payload = 'key=value'
        token = 'test_token'
        custom_headers = {'Custom-Header': 'value'}
        response = http_request(method, url, payload, token=token, custom_headers=custom_headers)

        mock_build_headers.assert_called_once_with(token, custom_headers)
        mock_requests_request.assert_called_once_with(method, url, data=payload,
                                                      headers={'Authorization': 'Bearer token',
                                                               'Custom-Header': 'value'}, verify=SECURED)
        self.assertIsNotNone(response.text, 'response_text')

    @patch('requests.Response')
    @patch('Cherwell.raise_or_return_error')
    def test_parse_response_success_json(self, mock_raise_or_return_error, mock_response):
        mock_response.raise_for_status = MagicMock()
        mock_response.content = b'{"key": "value"}'
        mock_response.json = MagicMock(return_value={"key": "value"})

        result = parse_response(mock_response, 'Operation failed')

        self.assertIsNotNone(result, {"key": "value"})
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_called_once()
        mock_raise_or_return_error.assert_not_called()

    @patch('requests.Response')
    def test_parse_response_success_file_content(self, mock_response):
        mock_response.raise_for_status = MagicMock()
        mock_response.content = b'file_content_data'

        result = parse_response(mock_response, 'Operation failed', file_content=True)

        self.assertIsNotNone(result, b'file_content_data')
        mock_response.raise_for_status.assert_called_once()
        mock_response.json.assert_not_called()

    @patch('Cherwell.request_new_access_token')
    @patch('Cherwell.parse_response')
    @patch('Cherwell.date_to_timestamp')
    @patch('Cherwell.setIntegrationContext')
    def test_get_new_access_token_success(self, mock_set_integration_context, mock_date_to_timestamp,
                                          mock_parse_response, mock_request_new_access_token):
        mock_request_new_access_token.side_effect = [
            MagicMock(status_code=401),  # First call fails
            MagicMock(status_code=HTTP_CODES['success'])  # Second call succeeds
        ]

        mock_parse_response.return_value = {
            'access_token': 'new_access_token',
            'refresh_token': 'new_refresh_token',
            '.expires': 'Thu, 01 Jan 2025 00:00:00 GMT'
        }

        mock_date_to_timestamp.return_value = int(datetime.now(timezone.utc).timestamp() * 1000)

        access_token = get_new_access_token(is_fetch=False)

        self.assertIsNotNone(access_token, 'new_access_token')
        mock_request_new_access_token.assert_called_with(False)
        mock_parse_response.assert_called_once()
        mock_date_to_timestamp.assert_called_once_with('Thu, 01 Jan 2025 00:00:00 GMT', '%a, %d %b %Y %H:%M:%S GMT')

    @patch('Cherwell.request_new_access_token')
    @patch('Cherwell.parse_response')
    @patch('Cherwell.date_to_timestamp')
    @patch('Cherwell.setIntegrationContext')
    def test_get_new_access_token_parse_error(self, mock_set_integration_context, mock_date_to_timestamp,
                                              mock_parse_response, mock_request_new_access_token):
        mock_request_new_access_token.return_value = MagicMock(status_code=HTTP_CODES['success'])
        mock_parse_response.side_effect = ValueError('Parsing error')

        with self.assertRaises(ValueError):
            get_new_access_token(is_fetch=False)

        mock_set_integration_context.assert_not_called()

    @patch('Cherwell.get_access_token')
    @patch('Cherwell.http_request')
    def test_make_request_success(self, mock_http_request, mock_get_access_token):
        mock_get_access_token.return_value = 'access_token'
        mock_http_request.return_value = MagicMock(status_code=200)  # Simulate a successful request

        response = make_request('GET', 'http://example.com')

        self.assertIsNotNone(response.status_code, 200)
        mock_get_access_token.assert_called_once_with(False, is_fetch=False)
        mock_http_request.assert_called_once_with('GET', 'http://example.com', None, 'access_token',
                                                  custom_headers=None, is_fetch=False)

    @patch('Cherwell.get_access_token')
    @patch('Cherwell.http_request')
    def test_make_request_unauthorized_retry(self, mock_http_request, mock_get_access_token):
        mock_get_access_token.side_effect = ['access_token', 'new_access_token']
        mock_http_request.side_effect = [MagicMock(status_code=401), MagicMock(status_code=200)]  # Simulate retry

        response = make_request('GET', 'http://example.com')

        self.assertIsNotNone(response.status_code, 200)
        self.assertIsNotNone(mock_get_access_token.call_count, 2)  # Called twice: once for initial and once for retry
        self.assertIsNotNone(mock_http_request.call_count, 2)  # Called twice: once for initial and once for retry
        mock_http_request.assert_any_call('GET', 'http://example.com', None, 'access_token', custom_headers=None,
                                          is_fetch=False)
        mock_http_request.assert_any_call('GET', 'http://example.com', None, 'new_access_token', custom_headers=None,
                                          is_fetch=False)

    @patch('Cherwell.uniqueFile')
    @patch('Cherwell.investigation')
    @patch('Cherwell.orenctl.error')
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

    @patch('Cherwell.raise_or_return_error')
    def test_valid_queries(self, mock_raise_or_return_error):
        query_list = [
            ["Field1", "eq", "Value1"],
            ["Field2", "gt", "Value2"],
            ["Field3", "lt", "Value3"]
        ]
        try:
            validate_query_list(query_list, is_fetch=False)
        except ValueError:
            self.fail("validate_query_list raised ValueError unexpectedly")

        mock_raise_or_return_error.assert_not_called()

    @patch('Cherwell.raise_or_return_error')
    def test_invalid_operator(self, mock_raise_or_return_error):
        query_list = [
            ["Field1", "invalid_op", "Value1"],  # Invalid operator
            ["Field2", "gt", "Value2"],
            ["Field3", "lt", "Value3"]
        ]
        mock_raise_or_return_error.side_effect = ValueError("Test error")

        with self.assertRaises(ValueError):
            validate_query_list(query_list, is_fetch=False)

        mock_raise_or_return_error.assert_called_once_with(
            'Operator should be one of the following: eq, gt, lt, contains, startswith. Filter in index 0, was: invalid_op',
            False
        )

    @patch('Cherwell.raise_or_return_error')
    @patch('Cherwell.validate_query_list')
    def test_valid_query_string(self, mock_validate_query_list, mock_raise_or_return_error):
        query_string = json.dumps([
            ["Field1", "eq", "Value1"],
            ["Field2", "gt", "Value2"]
        ])
        result = parse_string_query_to_list(query_string, is_fetch=False)
        expected_result = [
            ["Field1", "eq", "Value1"],
            ["Field2", "gt", "Value2"]
        ]
        self.assertIsNotNone(result, expected_result)
        mock_validate_query_list.assert_called_once_with(expected_result, False)
        mock_raise_or_return_error.assert_not_called()

    @patch('Cherwell.raise_or_return_error')
    @patch('Cherwell.validate_query_list')
    def test_invalid_json(self, mock_validate_query_list, mock_raise_or_return_error):
        query_string = 'invalid_json'
        mock_raise_or_return_error.side_effect = ValueError("Test error")

        with self.assertRaises(ValueError):
            parse_string_query_to_list(query_string, is_fetch=False)

        mock_raise_or_return_error.assert_called_once_with(
            'Cannot parse query, should be of the form: `[["FieldName","Operator","Value"],' \
            '["FieldName","Operator","Value"]]`.', False
        )
        mock_validate_query_list.assert_not_called()

    @patch('Cherwell.raise_or_return_error')
    def test_valid_query(self, mock_raise_or_return_error):
        query = ["FieldName1", "eq", "Value1"]
        filed_ids_dict = {
            "FieldName1": 123,
            "FieldName2": 456
        }
        expected_result = {
            'fieldId': 123,
            'operator': "eq",
            'value': "Value1"
        }
        result = build_query_dict(query, filed_ids_dict, False)
        self.assertIsNotNone(result, expected_result)
        mock_raise_or_return_error.assert_not_called()

    @patch('Cherwell.raise_or_return_error')
    def test_invalid_field_name(self, mock_raise_or_return_error):
        query = ["InvalidFieldName", "eq", "Value1"]
        filed_ids_dict = {
            "FieldName1": 123,
            "FieldName2": 456
        }
        mock_raise_or_return_error.side_effect = ValueError("Test error")

        with self.assertRaises(ValueError):
            build_query_dict(query, filed_ids_dict, False)

        mock_raise_or_return_error.assert_called_once_with(
            'Field name: InvalidFieldName does not exit in the given business objects', False
        )

    @patch('Cherwell.build_query_dict')
    def test_valid_query_list(self, mock_build_query_dict):
        mock_build_query_dict.side_effect = lambda query, dict, is_fetch: {
            'fieldId': dict.get(query[0]),
            'operator': query[1],
            'value': query[2]
        }

        query_list = [
            ["FieldName1", "eq", "Value1"],
            ["FieldName2", "gt", "Value2"]
        ]
        filed_ids_dict = {
            "FieldName1": 123,
            "FieldName2": 456
        }
        expected_result = [
            {'fieldId': 123, 'operator': "eq", 'value': "Value1"},
            {'fieldId': 456, 'operator': "gt", 'value': "Value2"}
        ]
        result = build_query_dict_list(query_list, filed_ids_dict, False)
        self.assertIsNotNone(result, expected_result)
        mock_build_query_dict.assert_has_calls([
            unittest.mock.call(["FieldName1", "eq", "Value1"], filed_ids_dict, False),
            unittest.mock.call(["FieldName2", "gt", "Value2"], filed_ids_dict, False)
        ])

    @patch('Cherwell.build_query_dict')
    def test_invalid_field_name_in_list(self, mock_build_query_dict):
        mock_build_query_dict.side_effect = lambda query, dict, is_fetch: (
            raise_or_return_error(f'Field name: {query[0]} does not exit in the given business objects', is_fetch)
        )

        query_list = [
            ["FieldName1", "eq", "Value1"],
            ["InvalidFieldName", "gt", "Value2"]
        ]
        filed_ids_dict = {
            "FieldName1": 123
        }

        with self.assertRaises(ValueError):
            build_query_dict_list(query_list, filed_ids_dict, False)

        mock_build_query_dict.assert_has_calls([
            unittest.mock.call(["FieldName1", "eq", "Value1"], filed_ids_dict, False),
        ])

    def test_empty_query_list(self):
        query_list = []
        filed_ids_dict = {
            "FieldName1": 123,
            "FieldName2": 456
        }
        expected_result = []
        result = build_query_dict_list(query_list, filed_ids_dict, False)
        self.assertEqual(result, expected_result)

    @patch('Cherwell.parse_fields_from_business_object')
    def test_valid_response(self, mock_parse_fields_from_business_object):
        mock_parse_fields_from_business_object.side_effect = lambda fields: {
            'parsedField': fields.get('someField', 'default')
        }

        response = {
            'businessObjects': [
                {
                    'busObId': '123',
                    'busObPublicId': 'pub123',
                    'busObRecId': 'rec123',
                    'fields': {'someField': 'value1'}
                },
                {
                    'busObId': '456',
                    'busObPublicId': 'pub456',
                    'busObRecId': 'rec456',
                    'fields': {'someField': 'value2'}
                }
            ]
        }

        expected_result = [
            {
                'parsedField': 'value1',
                'BusinessObjectId': '123',
                'PublicId': 'pub123',
                'RecordId': 'rec123'
            },
            {
                'parsedField': 'value2',
                'BusinessObjectId': '456',
                'PublicId': 'pub456',
                'RecordId': 'rec456'
            }
        ]

        result = parse_fields_from_business_object_list(response)
        self.assertIsNotNone(result, expected_result)
        mock_parse_fields_from_business_object.assert_has_calls([
            unittest.mock.call({'someField': 'value1'}),
            unittest.mock.call({'someField': 'value2'})
        ])

    def test_empty_response(self):
        response = {}
        expected_result = []
        result = parse_fields_from_business_object_list(response)
        self.assertIsNotNone(result, expected_result)

    @patch('Cherwell.get_key_value_dict_from_template')
    @patch('Cherwell.build_query_dict_list')
    @patch('Cherwell.run_query_on_business_objects')
    @patch('Cherwell.parse_fields_from_business_object_list')
    def test_query_business_object(self, mock_parse_fields_from_business_object_list,
                                   mock_run_query_on_business_objects,
                                   mock_build_query_dict_list, mock_get_key_value_dict_from_template):
        # Define mock return values
        mock_get_key_value_dict_from_template.return_value = {'field1': 'id1', 'field2': 'id2'}
        mock_build_query_dict_list.return_value = [{'fieldId': 'id1', 'operator': 'eq', 'value': 'value1'},
                                                   {'fieldId': 'id2', 'operator': 'contains', 'value': 'value2'}]
        mock_run_query_on_business_objects.return_value = {'businessObjects': [
            {'busObId': '123', 'busObPublicId': 'pub123', 'busObRecId': 'rec123', 'fields': {'someField': 'value1'}},
            {'busObId': '456', 'busObPublicId': 'pub456', 'busObRecId': 'rec456', 'fields': {'someField': 'value2'}}
        ]}
        mock_parse_fields_from_business_object_list.return_value = [
            {'parsedField': 'value1', 'BusinessObjectId': '123', 'PublicId': 'pub123', 'RecordId': 'rec123'},
            {'parsedField': 'value2', 'BusinessObjectId': '456', 'PublicId': 'pub456', 'RecordId': 'rec456'}
        ]

        # Call the function with sample data
        query_list = [['field1', 'eq', 'value1'], ['field2', 'contains', 'value2']]
        business_object_id = '123'
        max_results = 10
        is_fetch = False

        expected_business_objects = [
            {'parsedField': 'value1', 'BusinessObjectId': '123', 'PublicId': 'pub123', 'RecordId': 'rec123'},
            {'parsedField': 'value2', 'BusinessObjectId': '456', 'PublicId': 'pub456', 'RecordId': 'rec456'}
        ]
        expected_query_result = {'businessObjects': [
            {'busObId': '123', 'busObPublicId': 'pub123', 'busObRecId': 'rec123', 'fields': {'someField': 'value1'}},
            {'busObId': '456', 'busObPublicId': 'pub456', 'busObRecId': 'rec456', 'fields': {'someField': 'value2'}}
        ]}

        business_objects, query_result = query_business_object(query_list, business_object_id, max_results, is_fetch)

        # Validate the results
        self.assertIsNotNone(business_objects, expected_business_objects)
        self.assertIsNotNone(query_result, expected_query_result)

        # Validate the calls to the mocked functions
        mock_get_key_value_dict_from_template.assert_called_once_with('name', 'fieldId', business_object_id,
                                                                      is_fetch=is_fetch)
        mock_build_query_dict_list.assert_called_once_with(query_list,
                                                           mock_get_key_value_dict_from_template.return_value,
                                                           is_fetch=is_fetch)
        mock_run_query_on_business_objects.assert_called_once_with(business_object_id,
                                                                   mock_build_query_dict_list.return_value, max_results,
                                                                   is_fetch=is_fetch)
        mock_parse_fields_from_business_object_list.assert_called_once_with(
            mock_run_query_on_business_objects.return_value)

    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.parse_string_query_to_list')
    @patch('Cherwell.query_business_object')
    @patch('Cherwell.return_error')
    def test_query_business_object_string(self, mock_return_error, mock_query_business_object,
                                          mock_parse_string_query_to_list, mock_resolve_business_object_id_by_name):
        # Define mock return values
        mock_resolve_business_object_id_by_name.return_value = '123'
        mock_parse_string_query_to_list.return_value = [['field1', 'eq', 'value1']]
        mock_query_business_object.return_value = (['parsed_object'], {'businessObjects': []})
        mock_return_error.return_value = {'error': 'Invalid max_results'}

        # Test with valid inputs
        business_object_name = 'TestObject'
        query_string = '[["field1","eq","value1"]]'
        max_results = '10'

        business_objects, query_result = query_business_object_string(business_object_name, query_string, max_results)

        self.assertIsNotNone(business_objects, ['parsed_object'])
        self.assertIsNotNone(query_result, {'businessObjects': []})
        mock_resolve_business_object_id_by_name.assert_called_once_with(business_object_name)
        mock_parse_string_query_to_list.assert_called_once_with(query_string)
        mock_query_business_object.assert_called_once_with(
            [['field1', 'eq', 'value1']], '123', '10'
        )

        # Test with invalid max_results
        max_results_invalid = 'invalid'

        result = query_business_object_string(business_object_name, query_string, max_results_invalid)

        self.assertIsNotNone(result, {'error': 'Invalid max_results'})
        mock_return_error.assert_called_once_with('`max_results` argument received is not a number')

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.getFilePath')
    @patch('Cherwell.os.path.getsize')
    @patch('Cherwell.open', read_data=b'file_content')
    @patch('Cherwell.return_error')
    def test_upload_attachment(self, mock_return_error, mock_open, mock_getsize, mock_getFilePath, mock_Cherwell):
        # Setup mocks
        mock_getFilePath.return_value = {'path': '/mock/path/to/file', 'name': 'test_file.txt'}
        mock_getsize.return_value = 1234
        mock_cherwell_instance = mock_Cherwell.return_value
        mock_cherwell_instance.upload_business_object_attachment.return_value = 'attachment_id'

        # Run the function
        result = upload_attachment('id_type', 'object_id', 'type_name', 'file_entry_id')

        # Assert results
        self.assertIsNotNone(result, 'attachment_id')
        mock_getFilePath.assert_called_once_with('file_entry_id')
        mock_getsize.assert_called_once_with('/mock/path/to/file')
        mock_open.assert_called_once_with('/mock/path/to/file', 'rb')

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.get_attachments_content')
    def test_download_attachments(self, mock_get_attachments_content, mock_Cherwell):
        mock_cherwell_instance = mock_Cherwell.return_value
        mock_cherwell_instance.get_attachments_details.return_value = {
            'attachments': [{'id': 'attachment1'}, {'id': 'attachment2'}]
        }
        mock_get_attachments_content.return_value = 'attachments_content'

        result = download_attachments('id_type', 'object_id', 'type_name', 'type_id', is_fetch=True)

        mock_cherwell_instance.get_attachments_details.assert_called_once_with(
            'id_type', 'object_id', 'type_name', 'type_id', 'File', 'Imported', is_fetch=True
        )
        mock_get_attachments_content.assert_called_once_with(
            [{'id': 'attachment1'}, {'id': 'attachment2'}], is_fetch=True
        )
        self.assertIsNotNone(result, 'attachments_content')

    @patch('Cherwell.Cherwell')
    def test_no_attachments(self, mock_Cherwell):
        mock_cherwell_instance = mock_Cherwell.return_value
        mock_cherwell_instance.get_attachments_details.return_value = {
            'attachments': []
        }

        result = download_attachments('id_type', 'object_id', 'type_name', 'type_id', is_fetch=True)

        mock_cherwell_instance.get_attachments_details.assert_called_once_with(
            'id_type', 'object_id', 'type_name', 'type_id', 'File', 'Imported', is_fetch=True
        )
        self.assertIsNone(result)

    @patch('Cherwell.fileResult')
    def test_attachment_results(self, mock_fileResult):
        # Setup mocks
        mock_fileResult.side_effect = lambda name, content: {
            'File': name,
            'Contents': content,
            'Type': 'file',
            'ContentsFormat': 'text'
        }

        # Sample input
        attachments = [
            {'FileName': 'file1.txt', 'Content': b'content1'},
            {'FileName': 'file2.txt', 'Content': b'content2'}
        ]

        # Expected output
        expected_result = [
            {'File': 'file1.txt', 'Contents': b'content1', 'Type': 'file', 'ContentsFormat': 'text'},
            {'File': 'file2.txt', 'Contents': b'content2', 'Type': 'file', 'ContentsFormat': 'text'}
        ]

        # Run the function
        result = attachment_results(attachments)

        # Assert results
        self.assertIsNotNone(result, expected_result)
        mock_fileResult.assert_any_call('file1.txt', b'content1')
        mock_fileResult.assert_any_call('file2.txt', b'content2')
        self.assertIsNotNone(mock_fileResult.call_count, len(attachments))

    @patch('Cherwell.Cherwell')
    def test_resolve_business_object_id_success(self, MockCherwell):
        mock_cherwell_instance = MockCherwell.return_value
        mock_cherwell_instance.get_business_object_summary_by_name.return_value = [{'busObId': '12345'}]

        expected_id = '12345'

        result = resolve_business_object_id_by_name('TestObject')

        self.assertIsNotNone(result, expected_id)
        mock_cherwell_instance.get_business_object_summary_by_name.assert_called_once_with('TestObject', False)

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.raise_or_return_error')
    def test_resolve_business_object_id_failure(self, mock_raise_or_return_error, MockCherwell):
        mock_cherwell_instance = MockCherwell.return_value
        mock_cherwell_instance.get_business_object_summary_by_name.return_value = []

        with self.assertRaises(Exception):
            resolve_business_object_id_by_name('InvalidObject')

        mock_raise_or_return_error.assert_called_once_with(
            'Could not retrieve "InvalidObject" business object id. Make sure "InvalidObject" is a valid business object.',
            False
        )

    @patch('Cherwell.get_key_value_dict_from_template')
    @patch('Cherwell.build_fields_for_business_object')
    def test_build_business_object_json_with_object_id(self, mock_build_fields, mock_get_key_value_dict):
        # Setup mocks
        mock_get_key_value_dict.return_value = {'field1': 'fieldId1', 'field2': 'fieldId2'}
        mock_build_fields.return_value = {'field1': 'value1', 'field2': 'value2'}

        simple_json = {'some_key': 'some_value'}
        business_object_id = '12345'
        object_id = '67890'
        id_type = 'public_id'

        expected_json = {
            'busObId': business_object_id,
            'fields': {'field1': 'value1', 'field2': 'value2'},
            'busObPublicId': object_id
        }

        result = build_business_object_json(simple_json, business_object_id, object_id, id_type)

        self.assertIsNotNone(result, expected_json)
        mock_get_key_value_dict.assert_called_once_with('name', 'fieldId', business_object_id)
        mock_build_fields.assert_called_once_with(simple_json, {'field1': 'fieldId1', 'field2': 'fieldId2'})

    @patch('Cherwell.get_key_value_dict_from_template')
    @patch('Cherwell.build_fields_for_business_object')
    def test_build_business_object_json_with_default_id_type(self, mock_build_fields, mock_get_key_value_dict):
        # Setup mocks
        mock_get_key_value_dict.return_value = {'field1': 'fieldId1', 'field2': 'fieldId2'}
        mock_build_fields.return_value = {'field1': 'value1', 'field2': 'value2'}

        simple_json = {'some_key': 'some_value'}
        business_object_id = '12345'
        object_id = '67890'

        expected_json = {
            'busObId': business_object_id,
            'fields': {'field1': 'value1', 'field2': 'value2'},
            'busObRecId': object_id
        }

        result = build_business_object_json(simple_json, business_object_id, object_id)

        self.assertIsNotNone(result, expected_json)
        mock_get_key_value_dict.assert_called_once_with('name', 'fieldId', business_object_id)
        mock_build_fields.assert_called_once_with(simple_json, {'field1': 'fieldId1', 'field2': 'fieldId2'})

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.build_business_object_json')
    def test_create_business_object_success(self, mock_build_business_object_json, mock_resolve_business_object_id,
                                            mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'
        mock_build_business_object_json.return_value = {'busObId': '12345', 'fields': {'field1': 'value1'}}

        mock_cherwell_instance = MagicMock()
        mock_cherwell_instance.save_business_object.return_value = 'success'
        mock_Cherwell.return_value = mock_cherwell_instance

        name = 'SampleBusinessObject'
        data_json = {'some_key': 'some_value'}

        result = create_business_object(name, data_json)

        expected_business_object_json = {'busObId': '12345', 'fields': {'field1': 'value1'}}

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_build_business_object_json.assert_called_once_with(data_json, '12345')
        mock_cherwell_instance.save_business_object.assert_called_once_with(expected_business_object_json)

        # Assert the result
        self.assertIsNotNone(result, 'success')

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.build_business_object_json')
    def test_create_business_object_failure(self, mock_build_business_object_json, mock_resolve_business_object_id,
                                            mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'
        mock_build_business_object_json.return_value = {'busObId': '12345', 'fields': {'field1': 'value1'}}

        mock_cherwell_instance = MagicMock()
        mock_cherwell_instance.save_business_object.side_effect = Exception('Save failed')
        mock_Cherwell.return_value = mock_cherwell_instance

        name = 'SampleBusinessObject'
        data_json = {'some_key': 'some_value'}

        with self.assertRaises(Exception) as context:
            create_business_object(name, data_json)

        self.assertTrue('Save failed' in str(context.exception))

        expected_business_object_json = {'busObId': '12345', 'fields': {'field1': 'value1'}}

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_build_business_object_json.assert_called_once_with(data_json, '12345')
        mock_cherwell_instance.save_business_object.assert_called_once_with(expected_business_object_json)

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.build_business_object_json')
    def test_update_business_object_success(self, mock_build_business_object_json, mock_resolve_business_object_id,
                                            mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'
        mock_build_business_object_json.return_value = {
            'busObId': '12345',
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123',
        }

        mock_cherwell_instance = MagicMock()
        mock_cherwell_instance.save_business_object.return_value = 'success'
        mock_Cherwell.return_value = mock_cherwell_instance

        name = 'SampleBusinessObject'
        data_json = {'some_key': 'some_value'}
        object_id = 'pub123'
        id_type = 'public_id'

        result = update_business_object(name, data_json, object_id, id_type)

        expected_business_object_json = {
            'busObId': '12345',
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123'
        }

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_build_business_object_json.assert_called_once_with(data_json, '12345', object_id, id_type)
        mock_cherwell_instance.save_business_object.assert_called_once_with(expected_business_object_json)

        # Assert the result
        self.assertIsNotNone(result, 'success')

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.build_business_object_json')
    def test_update_business_object_failure(self, mock_build_business_object_json, mock_resolve_business_object_id,
                                            mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'
        mock_build_business_object_json.return_value = {
            'busObId': '12345',
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123',
        }

        mock_cherwell_instance = MagicMock()
        mock_cherwell_instance.save_business_object.side_effect = Exception('Save failed')
        mock_Cherwell.return_value = mock_cherwell_instance

        name = 'SampleBusinessObject'
        data_json = {'some_key': 'some_value'}
        object_id = 'pub123'
        id_type = 'public_id'

        with self.assertRaises(Exception) as context:
            update_business_object(name, data_json, object_id, id_type)

        self.assertTrue('Save failed' in str(context.exception))

        expected_business_object_json = {
            'busObId': '12345',
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123'
        }

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_build_business_object_json.assert_called_once_with(data_json, '12345', object_id, id_type)
        mock_cherwell_instance.save_business_object.assert_called_once_with(expected_business_object_json)

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.parse_fields_from_business_object')
    def test_get_business_object_success(self, mock_parse_fields_from_business_object, mock_resolve_business_object_id,
                                         mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'

        mock_get_business_object_record = MagicMock()
        mock_get_business_object_record.return_value = {
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123',
            'busObRecId': 'rec123'
        }
        mock_Cherwell_instance = MagicMock()
        mock_Cherwell_instance.get_business_object_record = mock_get_business_object_record
        mock_Cherwell.return_value = mock_Cherwell_instance

        mock_parse_fields_from_business_object.return_value = {'parsed_field1': 'parsed_value1'}

        name = 'SampleBusinessObject'
        object_id = 'pub123'
        id_type = 'public_id'

        parsed_business_object, results = get_business_object(name, object_id, id_type)

        expected_parsed_business_object = {
            'parsed_field1': 'parsed_value1',
            'PublicId': 'pub123',
            'RecordId': 'rec123'
        }

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_get_business_object_record.assert_called_once_with('12345', object_id, id_type)
        mock_parse_fields_from_business_object.assert_called_once_with({'field1': 'value1'})

        # Assert the results
        self.assertIsNotNone(parsed_business_object, expected_parsed_business_object)
        self.assertIsNotNone(results, {
            'fields': {'field1': 'value1'},
            'busObPublicId': 'pub123',
            'busObRecId': 'rec123'
        })

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.resolve_business_object_id_by_name')
    @patch('Cherwell.parse_fields_from_business_object')
    def test_get_business_object_failure(self, mock_parse_fields_from_business_object, mock_resolve_business_object_id,
                                         mock_Cherwell):
        # Setup mocks
        mock_resolve_business_object_id.return_value = '12345'

        mock_get_business_object_record = MagicMock()
        mock_get_business_object_record.side_effect = Exception('Error retrieving business object')
        mock_Cherwell_instance = MagicMock()
        mock_Cherwell_instance.get_business_object_record = mock_get_business_object_record
        mock_Cherwell.return_value = mock_Cherwell_instance

        mock_parse_fields_from_business_object.return_value = {}

        name = 'SampleBusinessObject'
        object_id = 'pub123'
        id_type = 'public_id'

        with self.assertRaises(Exception) as context:
            get_business_object(name, object_id, id_type)

        self.assertTrue('Error retrieving business object' in str(context.exception))

        # Check interactions
        mock_resolve_business_object_id.assert_called_once_with(name)
        mock_get_business_object_record.assert_called_once_with('12345', object_id, id_type)
        mock_parse_fields_from_business_object.assert_not_called()

    @patch('Cherwell.Cherwell')
    @patch('Cherwell.cherwell_dict_parser')
    def test_get_key_value_dict_from_template_success(self, mock_cherwell_dict_parser, mock_Cherwell):
        # Setup mocks
        mock_get_business_object_template = MagicMock()
        mock_get_business_object_template.return_value = {
            'fields': {'field1': 'value1', 'field2': 'value2'}
        }
        mock_Cherwell_instance = MagicMock()
        mock_Cherwell_instance.get_business_object_template = mock_get_business_object_template
        mock_Cherwell.return_value = mock_Cherwell_instance

        mock_cherwell_dict_parser.return_value = {'field1': 'value1', 'field2': 'value2'}

        key = 'field'
        val = 'fieldId'
        business_object_id = '12345'
        is_fetch = False

        result = get_key_value_dict_from_template(key, val, business_object_id, is_fetch)

        # Check interactions
        mock_Cherwell_instance.get_business_object_template.assert_called_once_with(business_object_id,
                                                                                    is_fetch=is_fetch)
        mock_cherwell_dict_parser.assert_called_once_with(key, val, {'field1': 'value1', 'field2': 'value2'})

        # Assert the results
        self.assertIsNotNone(result, {'field1': 'value1', 'field2': 'value2'})

    def test_cherwell_dict_parser_success(self):
        key = 'name'
        value = 'fieldId'
        item_list = [
            {'name': 'field1', 'fieldId': 'value1'},
            {'name': 'field2', 'fieldId': 'value2'},
            {'name': 'field3', 'fieldId': 'value3'}
        ]
        expected_output = {
            'field1': 'value1',
            'field2': 'value2',
            'field3': 'value3'
        }
        result = cherwell_dict_parser(key, value, item_list)
        self.assertIsNotNone(result, expected_output)

    def test_cherwell_dict_parser_empty_list(self):
        key = 'name'
        value = 'fieldId'
        item_list = []
        expected_output = {}
        result = cherwell_dict_parser(key, value, item_list)
        self.assertIsNotNone(result, expected_output)

    def test_cherwell_dict_parser_missing_key(self):
        key = 'name'
        value = 'fieldId'
        item_list = [
            {'name': 'field1', 'fieldId': 'value1'},
            {'fieldId': 'value2'},
            {'name': 'field3', 'fieldId': 'value3'}
        ]
        expected_output = {
            'field1': 'value1',
            'field3': 'value3'
        }
        result = cherwell_dict_parser(key, value, item_list)
        self.assertIsNotNone(result, expected_output)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_save_business_object_success(self, mock_parse_response, mock_make_request):
        # Set up mock responses
        mock_response = MagicMock()
        mock_response.json.return_value = {'success': True}
        mock_make_request.return_value = mock_response

        mock_parse_response.return_value = {'response_key': 'response_value'}

        cherwell = Cherwell()  # Replace with actual instantiation
        payload = {'key': 'value'}
        result = cherwell.save_business_object(payload)

        # Verify that make_request was called with the correct arguments
        url = BASE_URL + "api/V1/savebusinessobject"
        mock_make_request.assert_called_once_with("POST", url, json.dumps(payload))

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value, "Could not save business object")

        # Check the return value
        self.assertIsNotNone(result, {'response_key': 'response_value'})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_save_business_object_error(self, mock_parse_response, mock_make_request):
        # Set up mock responses
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        payload = {'key': 'value'}

        with self.assertRaises(Exception):
            cherwell.save_business_object(payload)

        # Verify that make_request was called with the correct arguments
        url = BASE_URL + "api/V1/savebusinessobject"
        mock_make_request.assert_called_once_with("POST", url, json.dumps(payload))

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value, "Could not save business object")

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_summary_by_name_success(self, mock_parse_response, mock_make_request):
        # Mock response data
        mock_response = MagicMock()
        mock_response.json.return_value = {'summary': 'details'}
        mock_make_request.return_value = mock_response

        mock_parse_response.return_value = {'summary': 'details'}

        cherwell = Cherwell()  # Replace with actual instantiation
        name = 'test_business_object'
        result = cherwell.get_business_object_summary_by_name(name, is_fetch=False)

        # Verify that make_request was called with the correct arguments
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobname/{name}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object summary", is_fetch=False)

        # Check the return value
        self.assertIsNotNone(result, {'summary': 'details'})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_summary_by_name_error(self, mock_parse_response, mock_make_request):
        # Mock response data
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        name = 'test_business_object'

        with self.assertRaises(Exception):
            cherwell.get_business_object_summary_by_name(name, is_fetch=False)

        # Verify that make_request was called with the correct arguments
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobname/{name}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object summary", is_fetch=False)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_record_success(self, mock_parse_response, mock_make_request):
        # Mock response data
        mock_response = MagicMock()
        mock_response.json.return_value = {'fields': {'field1': 'value1', 'field2': 'value2'}}
        mock_make_request.return_value = mock_response

        mock_parse_response.return_value = {'fields': {'field1': 'value1', 'field2': 'value2'}}

        cherwell = Cherwell()  # Replace with actual instantiation
        business_object_id = '123'
        object_id = '456'
        id_type = 'public_id'

        result = cherwell.get_business_object_record(business_object_id, object_id, id_type)

        # Verify that make_request was called with the correct arguments
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        url = BASE_URL + f'api/V1/getbusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}'
        mock_make_request.assert_called_once_with('GET', url)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value, "Could not get business objects")

        # Check the return value
        self.assertIsNotNone(result, {'fields': {'field1': 'value1', 'field2': 'value2'}})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_record_error(self, mock_parse_response, mock_make_request):
        # Mock response data
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        business_object_id = '123'
        object_id = '456'
        id_type = 'public_id'

        with self.assertRaises(Exception):
            cherwell.get_business_object_record(business_object_id, object_id, id_type)

        # Verify that make_request was called with the correct arguments
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        url = BASE_URL + f'api/V1/getbusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}'
        mock_make_request.assert_called_once_with('GET', url)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value, "Could not get business objects")

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_download_attachment_from_business_object_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'attachmentData': 'dummy_data'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = 'dummy_data'

        cherwell = Cherwell()  # Replace with actual instantiation
        attachment = {
            'attachmentId': '789',
            'busObId': '123',
            'busObRecId': '456'
        }
        is_fetch = False

        result = cherwell.download_attachment_from_business_object(attachment, is_fetch)

        # Verify that make_request was called with the correct URL
        url = BASE_URL + f'api/V1/getbusinessobjectattachment' \
                         f'/attachmentid/{attachment["attachmentId"]}/busobid/{attachment["busObId"]}/busobrecid/{attachment["busObRecId"]}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=is_fetch)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Unable to get content of attachment {attachment["attachmentId"]}',
                                                    file_content=True,
                                                    is_fetch=is_fetch)

        # Check the return value
        self.assertIsNotNone(result, 'dummy_data')

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_download_attachment_from_business_object_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        attachment = {
            'attachmentId': '789',
            'busObId': '123',
            'busObRecId': '456'
        }
        is_fetch = False

        with self.assertRaises(Exception):
            cherwell.download_attachment_from_business_object(attachment, is_fetch)

        # Verify that make_request was called with the correct URL
        url = BASE_URL + f'api/V1/getbusinessobjectattachment' \
                         f'/attachmentid/{attachment["attachmentId"]}/busobid/{attachment["busObId"]}/busobrecid/{attachment["busObRecId"]}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=is_fetch)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Unable to get content of attachment {attachment["attachmentId"]}',
                                                    file_content=True,
                                                    is_fetch=is_fetch)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_upload_business_object_attachment_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'uploadStatus': 'success'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = 'attachment_id'

        cherwell = Cherwell()  # Replace with actual instantiation
        file_name = 'example.txt'
        file_size = 1234
        file_content = b'example content'
        object_type_name = 'type_name'
        id_type = 'busobrecid'
        object_id = 'object_id'

        result = cherwell.upload_business_object_attachment(file_name, file_size, file_content, object_type_name,
                                                            id_type, object_id)

        # Verify that make_request was called with the correct URL and headers
        url = BASE_URL + f'/api/V1/uploadbusinessobjectattachment/' \
                         f'filename/{file_name}/busobname/{object_type_name}/{id_type}/{object_id}/offset/0/totalsize/{file_size}'
        headers = HEADERS.copy()
        headers['Content-Type'] = "application/octet-stream"
        mock_make_request.assert_called_once_with('POST', url, file_content, headers)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Could not upload attachment {file_name}')

        # Check the return value
        self.assertIsNotNone(result, 'attachment_id')

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_upload_business_object_attachment_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        file_name = 'example.txt'
        file_size = 1234
        file_content = b'example content'
        object_type_name = 'type_name'
        id_type = 'busobrecid'
        object_id = 'object_id'

        with self.assertRaises(Exception):
            cherwell.upload_business_object_attachment(file_name, file_size, file_content, object_type_name,
                                                       id_type, object_id)

        # Verify that make_request was called with the correct URL and headers
        url = BASE_URL + f'/api/V1/uploadbusinessobjectattachment/' \
                         f'filename/{file_name}/busobname/{object_type_name}/{id_type}/{object_id}/offset/0/totalsize/{file_size}'
        headers = HEADERS.copy()
        headers['Content-Type'] = "application/octet-stream"
        mock_make_request.assert_called_once_with('POST', url, file_content, headers)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Could not upload attachment {file_name}')

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_remove_attachment_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'status': 'success'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = None

        cherwell = Cherwell()  # Replace with actual instantiation
        id_type = 'public_id'
        object_id = 'object_id'
        type_name = 'type_name'
        attachment_id = 'attachment_id'
        id_type_str = "publicid"

        cherwell.remove_attachment(id_type, object_id, type_name, attachment_id)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'/api/V1/removebusinessobjectattachment/' \
                         f'attachmentid/{attachment_id}/busobname/{type_name}/{id_type_str}/{object_id}'
        mock_make_request.assert_called_once_with('DELETE', url)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Could not remove attachment {attachment_id} from {type_name} {object_id}')

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_remove_attachment_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        id_type = 'public_id'
        object_id = 'object_id'
        type_name = 'type_name'
        attachment_id = 'attachment_id'
        id_type_str = "publicid"

        with self.assertRaises(Exception):
            cherwell.remove_attachment(id_type, object_id, type_name, attachment_id)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'/api/V1/removebusinessobjectattachment/' \
                         f'attachmentid/{attachment_id}/busobname/{type_name}/{id_type_str}/{object_id}'
        mock_make_request.assert_called_once_with('DELETE', url)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Could not remove attachment {attachment_id} from {type_name} {object_id}')

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_search_results_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'results': 'mock_results'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = {'results': 'mock_results'}

        cherwell = Cherwell()  # Replace with actual instantiation
        payload = {'search': 'criteria'}

        result = cherwell.get_search_results(payload)

        # Verify that make_request was called with the correct URL, method, and payload
        url = BASE_URL + "api/V1/getsearchresults"
        mock_make_request.assert_called_once_with('POST', url, json.dumps(payload))

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not search for business objects", is_fetch=False)

        # Verify that the method returns the expected result
        self.assertIsNotNone(result, {'results': 'mock_results'})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_search_results_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        payload = {'search': 'criteria'}

        with self.assertRaises(Exception):
            cherwell.get_search_results(payload)

        # Verify that make_request was called with the correct URL, method, and payload
        url = BASE_URL + "api/V1/getsearchresults"
        mock_make_request.assert_called_once_with('POST', url, json.dumps(payload))

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not search for business objects", is_fetch=False)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_summary_by_id_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'summary': 'mock_summary'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = {'summary': 'mock_summary'}

        cherwell = Cherwell()  # Replace with actual instantiation
        _id = '12345'

        result = cherwell.get_business_object_summary_by_id(_id)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobid/{_id}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object summary", is_fetch=False)

        # Verify that the method returns the expected result
        self.assertIsNotNone(result, {'summary': 'mock_summary'})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_summary_by_id_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        _id = '12345'

        with self.assertRaises(Exception):
            cherwell.get_business_object_summary_by_id(_id)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobid/{_id}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object summary", is_fetch=False)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_template_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'template': 'mock_template'}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = {'template': 'mock_template'}

        cherwell = Cherwell()  # Replace with actual instantiation
        business_object_id = '12345'
        field_names = ['name1', 'name2']
        fields_ids = ['id1', 'id2']

        result = cherwell.get_business_object_template(business_object_id, True, field_names, fields_ids)

        # Verify that make_request was called with the correct URL, method, and payload
        url = BASE_URL + "api/V1/getbusinessobjecttemplate"
        payload = {
            "busObId": business_object_id,
            "includeAll": True,
            "fieldNames": field_names,
            "fieldIds": fields_ids
        }
        mock_make_request.assert_called_once_with("POST", url, json.dumps(payload), is_fetch=False)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object template", is_fetch=False)

        # Verify that the method returns the expected result
        self.assertIsNotNone(result, {'template': 'mock_template'})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_business_object_template_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        business_object_id = '12345'

        with self.assertRaises(Exception):
            cherwell.get_business_object_template(business_object_id)

        # Verify that make_request was called with the correct URL, method, and payload
        url = BASE_URL + "api/V1/getbusinessobjecttemplate"
        payload = {
            "busObId": business_object_id,
            "includeAll": True
        }
        mock_make_request.assert_called_once_with("POST", url, json.dumps(payload), is_fetch=False)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    "Could not get business object template", is_fetch=False)

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_attachments_details_success(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'attachments': ['mock_attachment']}
        mock_make_request.return_value = mock_response

        # Mock the response of parse_response
        mock_parse_response.return_value = {'attachments': ['mock_attachment']}

        cherwell = Cherwell()  # Replace with actual instantiation
        id_type = 'public_id'
        object_id = '12345'
        object_type_name = 'type_name'
        object_type_id = None
        type = 'File'
        attachment_type = 'Imported'

        result = cherwell.get_attachments_details(id_type, object_id, object_type_name, object_type_id, type,
                                                  attachment_type)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'api/V1/getbusinessobjectattachments/' \
                         f'busobname/{object_type_name}/' \
                         f'publicid/{object_id}/type/{type}/attachmenttype/{attachment_type}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Verify that parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Unable to get attachments for {object_type_name} {object_id}',
                                                    is_fetch=False)

        # Verify that the method returns the expected result
        self.assertIsNotNone(result, {'attachments': ['mock_attachment']})

    @patch('Cherwell.make_request')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.parse_response')  # Replace 'module_name' with the actual module name
    def test_get_attachments_details_error(self, mock_parse_response, mock_make_request):
        # Mock the response of make_request
        mock_response = MagicMock()
        mock_response.json.return_value = {'error': 'error_message'}
        mock_make_request.return_value = mock_response

        # Simulate parse_response raising an error
        mock_parse_response.side_effect = Exception("Error parsing response")

        cherwell = Cherwell()  # Replace with actual instantiation
        id_type = 'public_id'
        object_id = '12345'
        object_type_name = 'type_name'
        object_type_id = None
        type = 'File'
        attachment_type = 'Imported'

        with self.assertRaises(Exception):
            cherwell.get_attachments_details(id_type, object_id, object_type_name, object_type_id, type,
                                             attachment_type)

        # Verify that make_request was called with the correct URL and method
        url = BASE_URL + f'api/V1/getbusinessobjectattachments/' \
                         f'busobname/{object_type_name}/' \
                         f'publicid/{object_id}/type/{type}/attachmenttype/{attachment_type}'
        mock_make_request.assert_called_once_with('GET', url, is_fetch=False)

        # Ensure parse_response was called with the correct arguments
        mock_parse_response.assert_called_once_with(mock_response.json.return_value,
                                                    f'Unable to get attachments for {object_type_name} {object_id}',
                                                    is_fetch=False)

    @patch('Cherwell.create_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_create_business_object_command_success(self, mock_orenctl_results, mock_orenctl_getArg,
                                                    mock_create_business_object):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            json.dumps({'key': 'value'})  # Mock value for 'json'
        ]

        # Mock the create_business_object function response
        mock_create_business_object.return_value = {
            'busObPublicId': 'public_id_value',
            'busObRecId': 'record_id_value'
        }

        # Define expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'busObPublicId': 'public_id_value',
                'busObRecId': 'record_id_value'
            },
            'EntryContext': {
                BUSINESS_OBJECT_CONTEXT_KEY: {
                    'PublicId': 'public_id_value',
                    'RecordId': 'record_id_value'
                }
            }
        }

        # Call the function
        create_business_object_command()

        # Check that create_business_object was called with the correct arguments
        mock_create_business_object.assert_called_once_with('type_name', {'key': 'value'})

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.create_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_create_business_object_command_failure(self, mock_orenctl_results, mock_orenctl_getArg,
                                                    mock_create_business_object):
        # Mock the arguments and simulate a failure
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            json.dumps({'key': 'value'})  # Mock value for 'json'
        ]

        # Mock the create_business_object function to raise an exception
        mock_create_business_object.side_effect = Exception("Error creating business object")

        # Call the function and check for exceptions
        with self.assertRaises(Exception):
            create_business_object_command()

        # Verify that orenctl.results was not called
        mock_orenctl_results.assert_not_called()

    @patch('Cherwell.update_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_update_business_object_command_success(self, mock_orenctl_results, mock_orenctl_getArg,
                                                    mock_update_business_object):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            json.dumps({'key': 'value'}),  # Mock value for 'json'
            'object_id_value',  # Mock value for 'id_value'
            'public_id'  # Mock value for 'id_type'
        ]

        # Mock the update_business_object function response
        mock_update_business_object.return_value = {
            'busObPublicId': 'public_id_value',
            'busObRecId': 'record_id_value'
        }

        # Define expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {
                'busObPublicId': 'public_id_value',
                'busObRecId': 'record_id_value'
            },
            'EntryContext': {
                BUSINESS_OBJECT_CONTEXT_KEY: {
                    'PublicId': 'public_id_value',
                    'RecordId': 'record_id_value'
                }
            }
        }

        # Call the function
        update_business_object_command()

        # Check that update_business_object was called with the correct arguments
        mock_update_business_object.assert_called_once_with(
            'type_name',
            {'key': 'value'},
            'object_id_value',
            'public_id'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.update_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_update_business_object_command_failure(self, mock_orenctl_results, mock_orenctl_getArg,
                                                    mock_update_business_object):
        # Mock the arguments and simulate a failure
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            json.dumps({'key': 'value'}),  # Mock value for 'json'
            'object_id_value',  # Mock value for 'id_value'
            'public_id'  # Mock value for 'id_type'
        ]

        # Mock the update_business_object function to raise an exception
        mock_update_business_object.side_effect = Exception("Error updating business object")

        # Call the function and check for exceptions
        with self.assertRaises(Exception):
            update_business_object_command()

        # Verify that orenctl.results was not called
        mock_orenctl_results.assert_not_called()

    @patch('Cherwell.get_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.createContext')  # Replace 'module_name' with the actual module name
    def test_get_business_object_command(self, mock_createContext, mock_orenctl_results, mock_orenctl_getArg,
                                         mock_get_business_object):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            'public_id',  # Mock value for 'id_type'
            'object_id_value'  # Mock value for 'id_value'
        ]

        # Mock the get_business_object function response
        mock_get_business_object.return_value = (
            {'key': 'value'},  # Mock value for business_object
            {'busObPublicId': 'public_id_value', 'busObRecId': 'record_id_value'}  # Mock value for results
        )

        # Mock the createContext function
        mock_createContext.return_value = {
            'PublicId': 'public_id_value',
            'RecordId': 'record_id_value'
        }

        # Define expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['json'],
            'Contents': {'busObPublicId': 'public_id_value', 'busObRecId': 'record_id_value'},
            'EntryContext': {
                BUSINESS_OBJECT_CONTEXT_KEY: {
                    'PublicId': 'public_id_value',
                    'RecordId': 'record_id_value'
                }
            }
        }

        # Call the function
        get_business_object_command()

        # Check that get_business_object was called with the correct arguments
        mock_get_business_object.assert_called_once_with(
            'type_name',
            'object_id_value',
            'public_id'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.get_business_object')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.createContext')  # Replace 'module_name' with the actual module name
    def test_get_business_object_command_failure(self, mock_createContext, mock_orenctl_results, mock_orenctl_getArg,
                                                 mock_get_business_object):
        # Mock the arguments
        mock_orenctl_getArg.side_effect = [
            'type_name',  # Mock value for 'type'
            'public_id',  # Mock value for 'id_type'
            'object_id_value'  # Mock value for 'id_value'
        ]

        # Mock the get_business_object function to raise an exception
        mock_get_business_object.side_effect = Exception("Error getting business object")

        # Call the function and check for exceptions
        with self.assertRaises(Exception):
            get_business_object_command()

        # Verify that orenctl.results was not called
        mock_orenctl_results.assert_not_called()

    @patch('Cherwell.download_attachments')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.attachment_results')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.return_error')  # Replace 'module_name' with the actual module name
    def test_download_attachments_command(self, mock_return_error, mock_attachment_results, mock_orenctl_results,
                                          mock_orenctl_getArg, mock_download_attachments):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'public_id',  # Mock value for 'id_type'
            'object_id_value',  # Mock value for 'id_value'
            'type_name'  # Mock value for 'type'
        ]

        # Mock the download_attachments function response
        mock_download_attachments.return_value = [
            {'attachmentId': '1', 'Content': 'content1', 'FileName': 'file1.txt'},
            {'attachmentId': '2', 'Content': 'content2', 'FileName': 'file2.txt'}
        ]

        # Mock the attachment_results function
        mock_attachment_results.return_value = [
            {'fileName': 'file1.txt', 'content': 'content1'},
            {'fileName': 'file2.txt', 'content': 'content2'}
        ]

        # Define expected result
        expected_result = {
            "attachments": [
                {'fileName': 'file1.txt', 'content': 'content1'},
                {'fileName': 'file2.txt', 'content': 'content2'}
            ]
        }

        # Call the function
        download_attachments_command()

        # Check that download_attachments was called with the correct arguments
        mock_download_attachments.assert_called_once_with(
            'public_id',
            'object_id_value',
            business_object_type_name='type_name'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

        # Verify that return_error was not called
        mock_return_error.assert_not_called()

    @patch('Cherwell.upload_attachment')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_upload_attachment_command(self, mock_orenctl_results, mock_orenctl_getArg, mock_upload_attachment):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'Publicid',  # Mock value for 'id_type'
            'object_id_value',  # Mock value for 'id_value'
            'type_name',  # Mock value for 'type'
            'file_entry_id'  # Mock value for 'file_entry_id'
        ]

        # Mock the upload_attachment function response
        mock_upload_attachment.return_value = 'attachment_id_value'

        # Define the expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': {'attachment_id': 'attachment_id_value'},
            'EntryContext': {
                'Cherwell.UploadedAttachments(val.AttachmentId == obj.AttachmentId)': {
                    'AttachmentFileId': 'attachment_id_value',
                    'BusinessObjectType': 'type_name',
                    'Publicid': 'object_id_value'
                }
            }
        }

        # Call the function
        upload_attachment_command()

        # Verify that upload_attachment was called with the correct arguments
        mock_upload_attachment.assert_called_once_with(
            'Publicid',
            'object_id_value',
            'type_name',
            'file_entry_id'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.get_attachments_info')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_get_attachments_info_command(self, mock_orenctl_results, mock_orenctl_getArg, mock_get_attachments_info):
        # Mock the arguments and response
        mock_orenctl_getArg.side_effect = [
            'public_id',  # Mock value for 'id_type'
            'object_id_value',  # Mock value for 'id_value'
            'type_name',  # Mock value for 'type'
            'attachment_type_value'  # Mock value for 'attachment_type'
        ]

        # Mock the get_attachments_info function response
        mock_get_attachments_info.return_value = (
            [{'AttachmentId': 'attachment_id_1', 'AttachmentName': 'file1.txt'}],  # attachments_info
            {'raw_data_key': 'raw_data_value'}  # raw_result
        )

        # Define the expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': {'raw_data_key': 'raw_data_value'},
            'EntryContext': {
                'Cherwell.AttachmentsInfo': [{'AttachmentId': 'attachment_id_1', 'AttachmentName': 'file1.txt'}]
            }
        }

        # Call the function
        get_attachments_info_command()

        # Verify that get_attachments_info was called with the correct arguments
        mock_get_attachments_info.assert_called_once_with(
            'public_id',
            'object_id_value',
            'attachment_type_value',
            business_object_type_name='type_name'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.Cherwell')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_remove_attachment_command(self, mock_orenctl_results, mock_orenctl_getArg, mock_Cherwell):
        # Mock the Cherwell instance
        mock_cherwell_instance = mock_Cherwell.return_value

        # Mock the arguments
        mock_orenctl_getArg.side_effect = [
            'public_id',  # Mock value for 'id_type'
            'object_id_value',  # Mock value for 'id_value'
            'type_name',  # Mock value for 'type'
            'attachment_id_value'  # Mock value for 'attachment_id'
        ]

        # Define the expected result
        expected_md = f'### Attachment: attachment_id_value, was successfully removed from type_name object_id_value'
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': expected_md,
            'HumanReadable': expected_md,
        }

        # Call the function
        remove_attachment_command()

        # Verify that Cherwell.remove_attachment was called with the correct arguments
        mock_cherwell_instance.remove_attachment.assert_called_once_with(
            'public_id',
            'object_id_value',
            'type_name',
            'attachment_id_value'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.query_business_object_string')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_query_business_object_command(self, mock_orenctl_results, mock_orenctl_getArg,
                                           mock_query_business_object_string):
        # Mock the query_business_object_string function
        mock_query_business_object_string.return_value = (
            {'result_key': 'result_value'},  # Mock result for query_business_object_string
            'raw_response_string'  # Mock raw response string
        )

        # Mock the arguments
        mock_orenctl_getArg.side_effect = [
            'type_name_value',  # Mock value for 'type'
            'query_string_value',  # Mock value for 'query'
            '10'  # Mock value for 'max_results'
        ]

        # Define the expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': 'raw_response_string',
            'EntryContext': {'Cherwell.QueryResults': {'result_key': 'result_value'}}
        }

        # Call the function
        query_business_object_command()

        # Verify that query_business_object_string was called with the correct arguments
        mock_query_business_object_string.assert_called_once_with(
            'type_name_value',
            'query_string_value',
            '10'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.cherwell_run_saved_search')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_cherwell_run_saved_search_command(self, mock_orenctl_results, mock_orenctl_getArg,
                                               mock_cherwell_run_saved_search):
        # Mock the cherwell_run_saved_search function
        mock_cherwell_run_saved_search.return_value = {'RecordId': '12345', 'OtherData': 'value'}

        # Mock the arguments
        mock_orenctl_getArg.side_effect = [
            'association_id_value',  # Mock value for 'association_id'
            'scope_value',  # Mock value for 'scope'
            'scope_owner_value',  # Mock value for 'scope_owner'
            'search_name_value'  # Mock value for 'search_name'
        ]

        # Define the expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': {'RecordId': '12345', 'OtherData': 'value'},
            'EntryContext': {
                'Cherwell.SearchOperation(val.RecordId == obj.RecordId)': {'RecordId': '12345', 'OtherData': 'value'}}
        }

        # Call the function
        cherwell_run_saved_search_command()

        # Verify that cherwell_run_saved_search was called with the correct arguments
        mock_cherwell_run_saved_search.assert_called_once_with(
            'association_id_value',
            'scope_value',
            'scope_owner_value',
            'search_name_value'
        )

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.cherwell_get_business_object_id')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_cherwell_get_business_object_id_command(self, mock_orenctl_results, mock_orenctl_getArg,
                                                     mock_cherwell_get_business_object_id):
        # Mock the cherwell_get_business_object_id function
        mock_cherwell_get_business_object_id.return_value = {'BusinessObjectId': '12345'}

        # Mock the arguments
        mock_orenctl_getArg.return_value = 'some_business_object_name'

        # Define the expected result
        expected_result = {
            'Type': entryTypes['note'],
            'ContentsFormat': formats['text'],
            'Contents': {'BusinessObjectId': '12345'},
            'EntryContext': {'Cherwell.BusinessObjectInfo(val.BusinessObjectId == obj.BusinessObjectId)': {
                'BusinessObjectId': '12345'}}
        }

        # Call the function
        cherwell_get_business_object_id_command()

        # Verify that cherwell_get_business_object_id was called with the correct argument
        mock_cherwell_get_business_object_id.assert_called_once_with('some_business_object_name')

        # Verify that orenctl.results was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.Cherwell')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_cherwell_get_business_object_summary_command_with_id(self, mock_orenctl_results, mock_orenctl_getArg,
                                                                  MockCherwell):
        # Mock Cherwell instance
        mock_cherwell = MockCherwell.return_value
        mock_cherwell.get_business_object_summary_by_id.return_value = {'busObId': '12345', 'summary': 'summary data'}
        mock_orenctl_getArg.side_effect = [None, '12345']  # Mock `getArg` to return None for name and '12345' for ID

        # Define the expected result
        expected_result = {
            "outputs": {'busObId': '12345', 'summary': 'summary data'},
            "outputs_key_field": 'busObId',
            "outputs_prefix": 'Cherwell.BusinessObjectSummary',
            "raw_response": {'busObId': '12345', 'summary': 'summary data'}
        }

        # Call the function
        cherwell_get_business_object_summary_command()

        # Verify that `get_business_object_summary_by_id` was called with the correct argument
        mock_cherwell.get_business_object_summary_by_id.assert_called_once_with('12345')

        # Verify that `orenctl.results` was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.Cherwell')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.results')  # Replace 'module_name' with the actual module name
    def test_cherwell_get_business_object_summary_command_with_name(self, mock_orenctl_results, mock_orenctl_getArg,
                                                                    MockCherwell):
        # Mock Cherwell instance
        mock_cherwell = MockCherwell.return_value
        mock_cherwell.get_business_object_summary_by_name.return_value = {'busObId': '12345', 'summary': 'summary data'}
        mock_orenctl_getArg.side_effect = ['some_name',
                                           None]  # Mock `getArg` to return 'some_name' for name and None for ID

        # Define the expected result
        expected_result = {
            "outputs": {'busObId': '12345', 'summary': 'summary data'},
            "outputs_key_field": 'busObId',
            "outputs_prefix": 'Cherwell.BusinessObjectSummary',
            "raw_response": {'busObId': '12345', 'summary': 'summary data'}
        }

        # Call the function
        cherwell_get_business_object_summary_command()

        # Verify that `get_business_object_summary_by_name` was called with the correct argument
        mock_cherwell.get_business_object_summary_by_name.assert_called_once_with('some_name')

        # Verify that `orenctl.results` was called with the expected result
        mock_orenctl_results.assert_called_once_with(expected_result)

    @patch('Cherwell.Cherwell')  # Replace 'module_name' with the actual module name
    @patch('Cherwell.orenctl.getArg')  # Replace 'module_name' with the actual module name
    def test_cherwell_get_business_object_summary_command_no_args(self, mock_orenctl_getArg, MockCherwell):
        mock_orenctl_getArg.side_effect = [None, None]  # Mock `getArg` to return None for both name and ID

        # Call the function and assert that a ValueError is raised
        with self.assertRaises(ValueError) as context:
            cherwell_get_business_object_summary_command()
        self.assertIsNotNone(str(context.exception), 'No name or ID were specified. Please specify at least one of them.')
