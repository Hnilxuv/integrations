import time
import unittest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch
import requests
from requests import HTTPError

import orenctl
from ArcSightLogger import ArcSightLogger, get_search_events, start_search_session, drill_down, get_search_status, \
    get_events, stop_search, close_session, parse_xml, encode_to_url_query, generate_search_session_id, parse_array, \
    parse_bool, xml_object_to_json, entry_object_xml_to_json, get_chart_request, get_events_request, create_entry


class TestArcSightLogger(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        asl = ArcSightLogger()

        result = asl.http_request('GET', '/test_url')

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

        asl = ArcSightLogger()

        with self.assertRaises(HTTPError):
            asl.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'username': 'admin',
            'password': 'pw',
            'port': '8080',
            'insecure': 'true',
            'proxy': 'http://proxy.example.com',
        }.get(param)

        asl = ArcSightLogger()

        self.assertEqual(asl.url, 'http://example.com')
        self.assertTrue(asl.insecure)
        self.assertEqual(asl.proxy, 'http://proxy.example.com')
        self.assertIsInstance(asl.session, requests.Session)

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.get_search_events_request')
    @patch('orenctl.results')
    def test_get_search_events(self, mock_results, mock_get_search_events_request, mock_get_arg, mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client
        mock_client.login.return_value = 'mock_session_id'

        mock_get_arg.side_effect = lambda arg: {
            'query': 'test_query',
            'timeout': '60',
            'startTime': '2024-01-01T00:00:00Z',
            'endTime': '2024-01-02T00:00:00Z',
            'discover_fields': 'field1,field2',
            'summary_fields': 'summary1,summary2',
            'field_summary': 'summary_field',
            'local_search': 'true',
            'lastDays': '7',
            'offset': '0',
            'dir': 'asc',
            'length': '100',
            'fields': 'fieldA,fieldB'
        }.get(arg, '')

        mock_get_search_events_request.return_value = {'event': 'test_event'}

        get_search_events()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.start_search_session_request')
    @patch('orenctl.results')
    def test_start_search_session(self, mock_results, mock_start_search_session_request, mock_get_arg,
                                  mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client
        mock_client.login.return_value = 'mock_session_id'

        mock_get_arg.side_effect = lambda arg: {
            'query': 'test_query',
            'timeout': '60',
            'startTime': '2024-01-01T00:00:00Z',
            'endTime': '2024-01-02T00:00:00Z',
            'discover_fields': 'field1,field2',
            'summary_fields': 'summary1,summary2',
            'field_summary': 'summary_field',
            'local_search': 'true',
            'lastDays': '7'
        }.get(arg, '')

        mock_start_search_session_request.return_value = 'mock_search_session_id'

        start_search_session()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.drilldown_request')
    @patch('orenctl.results')
    def test_drill_down(self, mock_results, mock_drilldown_request, mock_get_arg, mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client
        mock_client.login.return_value = 'mock_session_id'

        mock_get_arg.side_effect = lambda arg: {
            'search_session_id': 'mock_search_session_id',
            'session_id': 'mock_session_id',
            'startTime': '2024-01-01T00:00:00Z',
            'endTime': '2024-01-02T00:00:00Z',
            'lastDays': '7'
        }.get(arg, '')

        mock_drilldown_request.return_value = {'drilldown_result': 'test_result'}

        drill_down()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.get_search_status_request')
    @patch('orenctl.results')
    @patch('ArcSightLogger.create_entry')
    def test_get_search_status(self, mock_create_entry, mock_results, mock_get_search_status_request, mock_get_arg,
                               mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client

        mock_get_arg.side_effect = lambda arg: {
            'session_id': 'mock_session_id',
            'search_session_id': 'mock_search_session_id'
        }.get(arg, '')

        mock_get_search_status_request.return_value = {
            'status': 'completed',
            'result_type': 'results',
            'hit': 100,
            'scanned': 200,
            'elapsed': '5m',
            'message': 'Search completed successfully'
        }

        mock_create_entry.return_value = {
            'Type': 'note',
            'Contents': {'status': 'completed'},
            'ContentsFormat': 'json',
            'ReadableContentsFormat': 'text',
            'EntryContext': {
                'ArcSightLogger.Status(val.SearchSessionId === obj.SearchSessionId)': {
                    'SearchSessionId': 'mock_search_session_id'
                }
            }
        }

        get_search_status()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.get_chart_request')
    @patch('ArcSightLogger.get_events_request')
    @patch('orenctl.results')
    @patch('ArcSightLogger.ArcSightLogger.get_search_status_request')
    def test_get_events(self, mock_get_search_status_request, mock_results, mock_get_events_request,
                        mock_get_chart_request, mock_get_arg, mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client

        mock_get_arg.side_effect = lambda arg: {
            'session_id': 'mock_session_id',
            'search_session_id': 'mock_search_session_id',
            'offset': '10',
            'dir': 'desc',
            'length': '50',
            'fields': 'field1,field2'
        }.get(arg, '')

        mock_get_search_status_request.return_value = {
            'result_type': 'chart'
        }

        mock_get_chart_request.return_value = {'chart': 'chart_data'}
        mock_get_events_request.return_value = {'events': 'event_data'}

        get_events()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.stop_search_request')
    @patch('orenctl.results')
    def test_stop_search(self, mock_results, mock_stop_search_request, mock_get_arg, mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client

        mock_get_arg.side_effect = lambda arg: {
            'session_id': 'mock_session_id',
            'search_session_id': 'mock_search_session_id'
        }.get(arg, '')

        mock_stop_search_request.return_value = None

        stop_search()
        self.assertIsNotNone(orenctl.get_results())

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('orenctl.getArg')
    @patch('ArcSightLogger.ArcSightLogger.close_session_request')
    @patch('orenctl.results')
    def test_close_session(self, mock_results, mock_close_session_request, mock_get_arg, mock_arc_sight_logger):
        mock_client = MagicMock()
        mock_arc_sight_logger.return_value = mock_client

        mock_get_arg.side_effect = lambda arg: {
            'session_id': 'mock_session_id',
            'search_session_id': 'mock_search_session_id'
        }.get(arg, '')

        mock_close_session_request.return_value = None

        close_session()
        self.assertIsNotNone(orenctl.get_results())

    def test_parse_xml_success(self):
        xml_response = """
        <root>
            <element>value</element>
            <special>&#x1F600;</special>
        </root>
        """

        expected_result = {'root': {'element': 'value', 'special': None}}

        result = parse_xml(xml_response)
        self.assertEqual(result, expected_result)

    def test_encode_to_url_query_basic(self):
        params = {
            'name': 'John Doe',
            'age': 30,
            'city': 'New York'
        }
        expected_result = 'name=John+Doe&age=30&city=New+York'
        result = encode_to_url_query(params)
        self.assertEqual(result, expected_result)

    def test_parse_bool(self):
        self.assertTrue(parse_bool('true'))
        self.assertTrue(parse_bool('TRUE'))
        self.assertFalse(parse_bool('false'))
        self.assertFalse(parse_bool('FALSE'))
        self.assertFalse(parse_bool('other'))

    def test_parse_array(self):
        self.assertEqual(parse_array('item1,item2,item3'), ['item1', 'item2', 'item3'])
        self.assertEqual(parse_array('single_item'), ['single_item'])
        self.assertEqual(parse_array(''), [''])

    def test_generate_search_session_id(self):
        sess_id = generate_search_session_id()
        self.assertIsInstance(sess_id, int)
        self.assertGreater(sess_id, 0)

        sess_id1 = generate_search_session_id()
        time.sleep(0.001)
        sess_id2 = generate_search_session_id()
        self.assertNotEqual(sess_id1, sess_id2)

    def test_xml_object_to_json_with_empty_data(self):
        xml_object = {
            'fields': [],
            'results': []
        }

        expected_result = []

        result = xml_object_to_json(xml_object)

        self.assertEqual(result, expected_result)

    def test_entry_object_xml_to_json_with_valid_data(self):
        xml_object = {
            'fields': [
                {'name': 'field1', 'type': 'string'},
                {'name': 'field2', 'type': 'date'}
            ],
            'results': [
                {'field1': 'value1', 'field2': '1700000000000'}
            ]
        }

        expected_result = [
            {
                'field1': 'value1',
                'field2': '1700000000.000Z'
            }
        ]

        context = []
        entry_object_xml_to_json(context, xml_object['results'], [f['type'] == 'date' for f in xml_object['fields']],
                                 [f['name'] for f in xml_object['fields']])

        self.assertEqual(context, expected_result)

    @patch('ArcSightLogger.ArcSightLogger.http_request')
    @patch('ArcSightLogger.ArcSightLogger.__init__', lambda x: None)
    def test_get_chart_request(self, mock_http_request):
        mock_http_request.return_value = {
            'fields': [
                {'name': 'field1', 'type': 'string'},
                {'name': 'field2', 'type': 'date'}
            ],
            'results': [
                {'field1': 'value1', 'field2': '1700000000000'}
            ]
        }

        user_session_id = 'mock_user_session_id'
        search_session_id = '1234567890'

        expected_result = [
            {
                'field1': 'value1',
                'field2': '1700000000.000Z'
            }
        ]

        result = get_chart_request(user_session_id, search_session_id)
        self.assertEqual(result, expected_result)

    @patch('ArcSightLogger.ArcSightLogger')
    @patch('ArcSightLogger.xml_object_to_json')
    def test_get_events_request(self, mock_xml_to_json, MockArcSightLogger):
        mock_http_request = MagicMock()
        MockArcSightLogger.return_value.http_request = mock_http_request
        mock_xml_to_json.return_value = [{'field1': 'value1', 'field2': 'value2'}]

        mock_http_request.return_value = {
            'fields': [
                {'name': 'field1', 'type': 'string'},
                {'name': 'field2', 'type': 'string'}
            ],
            'results': [
                {'field1': 'value1', 'field2': 'value2'}
            ]
        }

        user_session_id = 'mock_user_session_id'
        search_session_id = '1234567890'
        offset = '10'
        dir = 'asc'
        length = '50'
        fields = 'field1,field2'

        expected_result = [{'field1': 'value1', 'field2': 'value2'}]

        result = get_events_request(user_session_id, search_session_id, offset, dir, length, fields)
        self.assertEqual(result, expected_result)

        with self.assertRaises(ValueError):
            get_events_request(user_session_id, search_session_id, length='invalid')

        with self.assertRaises(ValueError):
            get_events_request(user_session_id, search_session_id, dir='invalid')

        with self.assertRaises(TypeError):
            get_events_request(user_session_id, search_session_id, fields=123)

    def test_create_entry_with_mapping(self):
        data = {
            'status': 'success',
            'result_type': 'chart',
            'hit': 100,
            'scanned': 200,
            'elapsed': 300,
            'message': 'No issues found'
        }

        mapping = {
            'title': 'Search Status',
            'data': [
                {'to': 'Status', 'from': 'status'},
                {'to': 'ResultType', 'from': 'result_type'},
                {'to': 'Hit', 'from': 'hit'},
                {'to': 'Scanned', 'from': 'scanned'},
                {'to': 'Elapsed', 'from': 'elapsed'},
                {'to': 'Message', 'from': 'message'}
            ],
            'contextPath': 'ArcSightLogger.Status(val.SearchSessionId === obj.SearchSessionId)'
        }

        expected_entry = {
            'Type': 'note',
            'Contents': data,
            'ContentsFormat': 'json',
            'ReadableContentsFormat': 'text',
            'HumanReadable': 'Search Status',
            'EntryContext': {
                'ArcSightLogger.Status(val.SearchSessionId === obj.SearchSessionId)': {
                    'Status': 'success',
                    'ResultType': 'chart',
                    'Hit': 100,
                    'Scanned': 200,
                    'Elapsed': 300,
                    'Message': 'No issues found'
                }
            }
        }

        result = create_entry(data, mapping)
        self.assertEqual(result, expected_entry)

    patch('ArcSightLogger.orenctl.getParam')

    @patch('orenctl.getParam')
    @patch('requests.post')
    def test_login_success(self, mock_post, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://mockserver.com',
            'insecure': 'false',
            'username': 'testuser',
            'password': 'testpass',
            'port': '443',
            'proxy': None
        }[key]

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '<loginResponse><return>mock_session_id</return></loginResponse>'
        mock_post.return_value = mock_response

        logger = ArcSightLogger()

        user_session_id = logger.login('testuser', 'testpass')

        self.assertEqual(user_session_id, 'mock_session_id')

    @patch('orenctl.getParam')
    @patch('requests.post')
    def test_login_failure(self, mock_post, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://mockserver.com',
            'insecure': 'false',
            'username': 'testuser',
            'password': 'testpass',
            'port': '443',
            'proxy': None
        }[key]

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_post.return_value = mock_response

        logger = ArcSightLogger()

        with self.assertRaises(ValueError) as cm:
            logger.login('testuser', 'testpass')

        self.assertEqual(str(cm.exception), 'Login failed. StatusCode: 500. Error: Internal Server Error')

    @patch('orenctl.getParam')
    @patch('requests.post')
    def test_logout_missing_session_id(self, mock_post, mock_get_param):
        logger = ArcSightLogger()

        with self.assertRaises(ValueError) as cm:
            logger.logout(None)

        self.assertEqual(str(cm.exception), 'Unable to perform logout from ArcSight Logger. Session id is missing')

    @patch('orenctl.getParam')
    @patch('requests.post')
    def test_logout_failure(self, mock_post, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://mockserver.com/',
            'insecure': 'false',
            'username': 'testuser',
            'password': 'testpass',
            'port': '443',
            'proxy': None
        }[key]

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = 'Internal Server Error'
        mock_post.return_value = mock_response

        logger = ArcSightLogger()

        with self.assertRaises(ValueError) as cm:
            logger.logout('mock_user_session_id')

        self.assertEqual(str(cm.exception), 'Logout failed. StatusCode: 500. Error: Internal Server Error')

    @patch('ArcSightLogger.generate_search_session_id')
    @patch('ArcSightLogger.parse_bool')
    @patch('ArcSightLogger.parse_array')
    @patch('orenctl.getParam')
    @patch('requests.post')
    def test_start_search_session_request(self, mock_post, mock_get_param, mock_parse_array, mock_parse_bool,
                                          mock_generate_search_session_id):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://mockserver.com/',
            'insecure': 'false',
            'username': 'testuser',
            'password': 'testpass',
            'port': '443',
            'proxy': None
        }[key]

        mock_generate_search_session_id.return_value = 'mock_session_id'
        mock_parse_bool.side_effect = lambda x: x.lower() == 'true'
        mock_parse_array.side_effect = lambda x: x.split(',')

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'mock_response'
        mock_post.return_value = mock_response

        logger = ArcSightLogger()

        args = {
            'user_session_id': 'user123',
            'query': 'test query',
            'timeout': '30',
            'last_days': '7',
            'discover_fields': 'true',
            'summary_fields': 'field1,field2',
            'field_summary': 'false',
            'local_search': 'true'
        }

        search_session_id = logger.start_search_session_request(args)

        self.assertEqual(search_session_id, 'mock_session_id')

    @patch('ArcSightLogger.ArcSightLogger.http_request')
    @patch('orenctl.getParam')
    def test_get_search_status_request(self, mock_get_param, mock_http_request):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://example.com',
            'insecure': True,
            'username': 'user',
            'password': 'pass',
            'port': '8080',
            'proxy': None
        }.get(key)

        instance = ArcSightLogger()
        user_session_id = "mock_user_session_id"
        search_session_id = 12345

        expected_body_args = {
            'search_session_id': search_session_id,
            'user_session_id': user_session_id
        }

        mock_response = {'status': 'success', 'data': 'mock_data'}
        mock_http_request.return_value = mock_response

        result = instance.get_search_status_request(user_session_id, search_session_id)

        mock_http_request.assert_called_once_with(
            "POST",
            'server/search/status',
            None,
            expected_body_args
        )
        self.assertEqual(result, mock_response)

    @patch('orenctl.getParam')
    @patch('ArcSightLogger.ArcSightLogger.logout')
    @patch('ArcSightLogger.ArcSightLogger.close_session_request')
    @patch('ArcSightLogger.get_events_request')
    @patch('ArcSightLogger.get_chart_request')
    @patch('ArcSightLogger.ArcSightLogger.get_search_status_request')
    @patch('ArcSightLogger.ArcSightLogger.start_search_session_request')
    @patch('time.sleep', return_value=None)
    def test_get_search_events_request(self, mock_sleep, mock_start_search, mock_get_status, mock_get_chart,
                                       mock_get_events, mock_close_session, mock_logout, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            'url': 'http://example.com',
            'insecure': True,
            'username': 'user',
            'password': 'pass',
            'port': '8080',
            'proxy': None
        }.get(key)

        instance = ArcSightLogger()

        args = {
            'user_session_id': 'mock_user_session_id',
            'length': 10,
            'offset': 0,
            'dir': 'asc',
            'fields': ['field1', 'field2']
        }

        mock_start_search.return_value = 'mock_search_session_id'

        mock_get_status.side_effect = [
            {'status': 'running', 'hit': 0},
            {'status': 'running', 'hit': 5},
            {'status': 'complete', 'hit': 10, 'result_type': 'events'}
        ]

        mock_get_events.return_value = ['event1', 'event2']

        events = instance.get_search_events_request(args)

        mock_start_search.assert_called_once_with(args)
        self.assertEqual(mock_get_status.call_count, 3)
        mock_get_events.assert_called_once_with(
            'mock_user_session_id',
            'mock_search_session_id',
            0,
            'asc',
            10,
            ['field1', 'field2']
        )
        mock_close_session.assert_called_once_with('mock_user_session_id', 'mock_search_session_id')
        mock_logout.assert_called_once_with('mock_user_session_id')
        self.assertEqual(events, ['event1', 'event2'])
