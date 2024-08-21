import unittest
from unittest.mock import patch, MagicMock, Mock

from VMWareCarbonBlackAppControl import VMWareCarbonBlackAppControl, get_hash_type, file_catalog_threat_to_int, \
    file_catalog_file_state_to_int, event_type_to_int, event_severity_to_int, event_type_to_string, \
    event_severity_to_string, file_analysis_status_to_int, file_analysis_result_to_int, search_file_catalog_command, \
    search_computer_command, update_computer_command, get_computer_command


class TestVMWareCarbonBlackAppControl(unittest.TestCase):
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
        self.instance = VMWareCarbonBlackAppControl()
        self.instance.http_request = MagicMock()

    @patch('requests.Session.request')  # Mock the request method of the requests library
    def test_http_request_success(self, mock_request):
        # Setup
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'key': 'value'}
        mock_request.return_value = mock_response

        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class

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

        obj = VMWareCarbonBlackAppControl()

        # Test and Verify Exception
        with self.assertRaises(ValueError) as context:
            obj.http_request('GET', '/test')

        self.assertEqual(str(context.exception), 'Http request error: 404 Not Found')

    @patch('requests.Session.request')
    def test_http_request_other_2xx_status(self, mock_request):
        # Setup
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'created': True}
        mock_request.return_value = mock_response

        obj = VMWareCarbonBlackAppControl()

        # Test
        result = obj.http_request('POST', '/test')

        # Assertions
        mock_request.assert_called_once_with(method='POST', url='/test', verify=obj.verify)
        self.assertEqual(result, {'created': True})

    @patch('orenctl.results')
    @patch('requests.Session.request')
    def test_http_request_failure(self, mock_request, mock_results):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.content = b"Bad request"
        mock_request.return_value = mock_response

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

    def test_known_threat_levels(self):
        # Test cases for known threat levels
        self.assertIsNotNone(file_catalog_threat_to_int('Unknown'), -1)
        self.assertIsNotNone(file_catalog_threat_to_int('Clean'), 0)
        self.assertIsNotNone(file_catalog_threat_to_int('Potential risk'), 50)
        self.assertIsNotNone(file_catalog_threat_to_int('Malicious'), 100)

    def test_unknown_threat_level(self):
        # Test case for an unknown threat level (should return the threat itself)
        self.assertIsNotNone(file_catalog_threat_to_int('Not Listed'), 'Not Listed')

    def test_known_file_states(self):
        # Test cases for known file states
        self.assertIsNotNone(file_catalog_file_state_to_int('Unapproved'), 1)
        self.assertIsNotNone(file_catalog_file_state_to_int('Approved'), 2)
        self.assertIsNotNone(file_catalog_file_state_to_int('Banned'), 3)
        self.assertIsNotNone(file_catalog_file_state_to_int('Approved by Policy'), 4)
        self.assertIsNotNone(file_catalog_file_state_to_int('Banned by Policy'), 5)

    def test_unknown_file_state(self):
        # Test case for an unknown file state (should return the file_state itself)
        self.assertIsNotNone(file_catalog_file_state_to_int('Not Listed'), 'Not Listed')

    def test_edge_cases(self):
        # Test case for empty string or None
        self.assertIsNotNone(file_catalog_file_state_to_int(''), '')
        self.assertIsNone(file_catalog_file_state_to_int(None))

    def test_known_event_types(self):
        # Test cases for known event types
        self.assertIsNotNone(event_type_to_int('Server Management'), 0)
        self.assertIsNotNone(event_type_to_int('Session Management'), 1)
        self.assertIsNotNone(event_type_to_int('Computer Management'), 2)
        self.assertIsNotNone(event_type_to_int('Policy Management'), 3)
        self.assertIsNotNone(event_type_to_int('Policy Enforcement'), 4)
        self.assertIsNotNone(event_type_to_int('Discovery'), 5)
        self.assertIsNotNone(event_type_to_int('General Management'), 6)
        self.assertIsNotNone(event_type_to_int('Internal Events'), 8)

    def test_unknown_event_type(self):
        # Test case for an unknown event type (should return the event type itself)
        self.assertIsNotNone(event_type_to_int('Not Listed'), 'Not Listed')

    def test_known_severity_levels(self):
        self.assertIsNotNone(event_severity_to_int('Critical'), 2)
        self.assertIsNotNone(event_severity_to_int('Error'), 3)
        self.assertIsNotNone(event_severity_to_int('Warning'), 4)
        self.assertIsNotNone(event_severity_to_int('Notice'), 5)
        self.assertIsNotNone(event_severity_to_int('Info'), 6)
        self.assertIsNotNone(event_severity_to_int('Debug'), 7)

    def test_unknown_severity_level(self):
        self.assertIsNotNone(event_severity_to_int('Unknown Severity'), 'Unknown Severity')

    def test_known_event_types_string(self):
        # Test cases for known event types
        self.assertIsNotNone(event_type_to_string(0), 'Server Management')
        self.assertIsNotNone(event_type_to_string(1), 'Session Management')
        self.assertIsNotNone(event_type_to_string(2), 'Computer Management')
        self.assertIsNotNone(event_type_to_string(3), 'Policy Management')
        self.assertIsNotNone(event_type_to_string(4), 'Policy Enforcement')
        self.assertIsNotNone(event_type_to_string(5), 'Discovery')
        self.assertIsNotNone(event_type_to_string(6), 'General Management')
        self.assertIsNotNone(event_type_to_string(8), 'Internal Events')

    def test_unknown_event_type_string(self):
        # Test case for an unknown event type (should return the event type itself)
        self.assertIsNotNone(event_type_to_string(99), 99)

    def test_known_severity_levels_severity(self):
        # Test cases for known severity levels
        self.assertIsNotNone(event_severity_to_string(2), 'Critical')
        self.assertIsNotNone(event_severity_to_string(3), 'Error')
        self.assertIsNotNone(event_severity_to_string(4), 'Warning')
        self.assertIsNotNone(event_severity_to_string(5), 'Notice')
        self.assertIsNotNone(event_severity_to_string(6), 'Info')
        self.assertIsNotNone(event_severity_to_string(7), 'Debug')

    def test_unknown_severity_level_severity(self):
        # Test case for an unknown severity level (should return the severity itself)
        self.assertIsNotNone(event_severity_to_string(99), 99)

    def test_known_statuses(self):
        # Test cases for known statuses
        self.assertIsNotNone(file_analysis_status_to_int('scheduled'), 0)
        self.assertIsNotNone(file_analysis_status_to_int('submitted (file is sent for analysis)'), 1)
        self.assertIsNotNone(
            file_analysis_status_to_int('processed (file is processed but results are not available yet)'),
            2)
        self.assertIsNotNone(file_analysis_status_to_int('analyzed (file is processed and results are available)'), 3)
        self.assertIsNotNone(file_analysis_status_to_int('error'), 4)
        self.assertIsNotNone(file_analysis_status_to_int('cancelled'), 5)

    def test_unknown_status(self):
        # Test case for an unknown status (should return the status itself)
        self.assertIsNotNone(file_analysis_status_to_int('unknown status'), 'unknown status')

    def test_known_results(self):
        # Test cases for known results
        self.assertIsNotNone(file_analysis_result_to_int('Not yet available'), 0)
        self.assertIsNotNone(file_analysis_result_to_int('File is clean'), 1)
        self.assertIsNotNone(file_analysis_result_to_int('File is a potential threat'), 2)
        self.assertIsNotNone(file_analysis_result_to_int('File is malicious'), 3)

    def test_unknown_result(self):
        # Test case for an unknown result (should return the result itself)
        self.assertIsNotNone(file_analysis_result_to_int('Unknown result'), 'Unknown result')

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')  # Replace with the actual module and class
    def test_search_file_catalog_all_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class

        response = obj.search_file_catalog(
            q='query1&query2',
            limit=10,
            offset=0,
            sort='desc',
            group='group1',
            file_name='file.txt',
            file_type='text',
            computer_id='comp123',
            threat='high',
            file_state='infected',
            hash_value='d41d8cd98f00b204e9800998ecf8427e'  # md5 hash
        )

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_catalog_with_default_values(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_catalog()

        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": []
        }

        mock_http_request.assert_called_once_with('GET', '/fileCatalog', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_catalog_some_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_catalog(
            file_name='file.txt',
            file_type='text'
        )

        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": ['fileName:file.txt', 'fileType:text']
        }

        mock_http_request.assert_called_once_with('GET', '/fileCatalog', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_catalog_invalid_threat(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_catalog(threat='unknown')

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_catalog_invalid_file_state(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_catalog(file_state='unknown')

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_catalog_unknown_hash(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_catalog(hash_value='unknownhashvalue')

        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": []
        }

        mock_http_request.assert_called_once_with('GET', '/fileCatalog', params=expected_params)
        self.assertEqual(response, 'response')

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')  # Replace 'your_module.YourClass' with the actual module and class
    def test_search_computer_no_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class
        response = obj.search_computer()
        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": []
        }
        mock_http_request.assert_called_once_with('GET', '/Computer', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_computer_with_name(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()
        response = obj.search_computer(name='test-computer')
        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": ['name:test-computer']
        }
        mock_http_request.assert_called_once_with('GET', '/Computer', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_computer_with_ip_address(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()
        response = obj.search_computer(ip_address='192.168.0.1')
        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": ['ipAddress:192.168.0.1']
        }
        mock_http_request.assert_called_once_with('GET', '/Computer', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_computer_with_multiple_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()
        response = obj.search_computer(name='test-computer', ip_address='192.168.0.1', mac='00:11:22:33:44:55')
        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": ['name:test-computer', 'ipAddress:192.168.0.1', 'macAddress:00:11:22:33:44:55']
        }
        mock_http_request.assert_called_once_with('GET', '/Computer', params=expected_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_computer_with_fields(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()
        response = obj.search_computer(
            fields='memorySize,processorCount,processorModel,osShortName,osName,macAddress,machineModel,ipAddress,name,id, processorModel,customField')
        expected_params = {
            "limit": None,
            "offset": None,
            "sort": None,
            "group": None,
            "q": [],
            "fields": 'memorySize,processorCount,processorModel,osShortName,osName,macAddress,machineModel,ipAddress,name,id, processorModel,customField'
        }
        mock_http_request.assert_called_once_with('GET', '/Computer', params=expected_params)
        self.assertEqual(response, 'response')

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.get_computer')  # Replace with actual module and class
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_update_computer_all_fields(self, mock_http_request, mock_get_computer):
        # Setup mock responses
        mock_get_computer.return_value = {'id': '123', 'existingField': 'value'}
        mock_http_request.return_value = 'response'

        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class
        response = obj.update_computer(
            id='123',
            name='New Computer',
            computer_tag='Tag123',
            description='A new description',
            policy_id='policy1',
            automatic_policy=True,
            local_approval=False,
            refresh_flags='refresh',
            prioritized=True,
            debug_level='high',
            kernel_debug_level='medium',
            debug_flags='flags',
            debug_duration='1h',
            cclevel='level1',
            ccflags='ccflags',
            force_upgrade=True,
            template='template'
        )

        expected_body_params = {
            'id': '123',
            'name': 'New Computer',
            'computerTag': 'Tag123',
            'description': 'A new description',
            'policyId': 'policy1',
            'automaticPolicy': True,
            'localApproval': False,
            'refreshFlags': 'refresh',
            'prioritized': True,
            'debugLevel': 'high',
            'kernelDebugLevel': 'medium',
            'debugFlags': 'flags',
            'debugDuration': '1h',
            'ccLevel': 'level1',
            'ccFlags': 'ccflags',
            'forceUpgrade': True,
            'template': 'template'
        }
        expected_body_params.update({'existingField': 'value'})  # Existing fields should be preserved

        mock_http_request.assert_called_once_with('POST', '/computer', data=expected_body_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.get_computer')
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_update_computer_some_fields_none(self, mock_http_request, mock_get_computer):
        mock_get_computer.return_value = {'id': '123', 'existingField': 'value'}
        mock_http_request.return_value = 'response'

        obj = VMWareCarbonBlackAppControl()
        response = obj.update_computer(
            id='123',
            name='Updated Computer',
            computer_tag=None,  # This should be ignored
            description='Updated description',
            policy_id=None,  # This should be ignored
            automatic_policy=None,  # This should be ignored
            local_approval=None,  # This should be ignored
            refresh_flags=None,  # This should be ignored
            prioritized=None,  # This should be ignored
            debug_level=None,  # This should be ignored
            kernel_debug_level=None,  # This should be ignored
            debug_flags=None,  # This should be ignored
            debug_duration=None,  # This should be ignored
            cclevel=None,  # This should be ignored
            ccflags=None,  # This should be ignored
            force_upgrade=None,  # This should be ignored
            template=None  # This should be ignored
        )

        expected_body_params = {
            'id': '123',
            'name': 'Updated Computer',
            'description': 'Updated description'
        }
        expected_body_params.update({'existingField': 'value'})

        mock_http_request.assert_called_once_with('POST', '/computer', data=expected_body_params)
        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.get_computer')
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_update_computer_no_changes(self, mock_http_request, mock_get_computer):
        mock_get_computer.return_value = {'id': '123'}
        mock_http_request.return_value = 'response'

        obj = VMWareCarbonBlackAppControl()
        response = obj.update_computer(
            id='123',
            name=None,
            computer_tag=None,
            description=None,
            policy_id=None,
            automatic_policy=None,
            local_approval=None,
            refresh_flags=None,
            prioritized=None,
            debug_level=None,
            kernel_debug_level=None,
            debug_flags=None,
            debug_duration=None,
            cclevel=None,
            ccflags=None,
            force_upgrade=None,
            template=None
        )

        expected_body_params = {'id': '123'}

        mock_http_request.assert_called_once_with('POST', '/computer', data=expected_body_params)
        self.assertEqual(response, 'response')

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')  # Replace with the actual module and class
    def test_get_computer(self, mock_http_request):
        # Setup mock response
        mock_http_request.return_value = {'id': '123', 'name': 'Test Computer'}

        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class
        computer_id = '123'
        response = obj.get_computer(computer_id)

        # Verify the HTTP request
        expected_url = f'/Computer/{computer_id}'
        mock_http_request.assert_called_once_with('GET', expected_url)

        # Verify the response
        self.assertEqual(response, {'id': '123', 'name': 'Test Computer'})

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')  # Replace with the actual module and class
    def test_search_event_all_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class

        response = obj.search_event(
            q='query1&query2',
            limit=10,
            offset=0,
            sort='desc',
            group='group1',
            e_type='error',
            computer_id='comp123',
            ip_address='192.168.1.1',
            file_name='file.txt',
            severity='high',
            user_name='user1',
            file_catalog_id='catalog123'
        )

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_event_with_default_values(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_event()

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_event_some_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_event(
            e_type='error',
            ip_address='192.168.1.1',
            user_name='user1'
        )

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_event_invalid_severity(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_event(severity='unknown')

        self.assertEqual(response, 'response')

    @patch(
        'VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')  # Replace with the actual module and class
    def test_search_file_analysis_all_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()  # Replace with the actual instantiation of your class

        response = obj.search_file_analysis(
            q='query1&query2',
            limit=10,
            offset=0,
            sort='asc',
            group='group1',
            file_catalog_id='catalog123',
            connector_id='connector456',
            file_name='file.txt',
            status='completed',
            result='positive'
        )

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_analysis_with_default_values(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_analysis()

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_analysis_some_params(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_analysis(
            file_name='file.txt',
            status='completed'
        )

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_analysis_invalid_status(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_analysis(status='unknown')

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl.http_request')
    def test_search_file_analysis_invalid_result(self, mock_http_request):
        mock_http_request.return_value = 'response'
        obj = VMWareCarbonBlackAppControl()

        response = obj.search_file_analysis(result='unknown')

        self.assertEqual(response, 'response')

    @patch('VMWareCarbonBlackAppControl.orenctl.getArg')  # Mock the getArg method of orenctl
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl')  # Mock the VMWareCarbonBlackAppControl class
    @patch('VMWareCarbonBlackAppControl.orenctl.results')  # Mock the results method of orenctl
    def test_search_file_catalog_command(self, mock_results, mock_vmwcbac_class, mock_get_arg):
        # Setup mock for orenctl.getArg
        mock_get_arg.side_effect = [
            'test_query', 10, 0, 'name', 'group', 'test_file_name', 'test_file_type',
            'test_computer_id', 'test_threat', 'test_file_state', 'test_hash'
        ]

        # Setup mock for VMWareCarbonBlackAppControl
        mock_vmwcbac = Mock()
        mock_vmwcbac_class.return_value = mock_vmwcbac
        mock_vmwcbac.search_file_catalog.return_value = [
            {
                'fileSize': 1234,
                'pathName': '/path/to/file',
                'sha1': 'abc123',
                'sha256': 'def456',
                'md5': '789xyz',
                'fileName': 'test_file',
                'fileType': 'exe',
                'productName': 'Test Product',
                'id': 'file_id',
                'publisher': 'Test Publisher',
                'company': 'Test Company',
                'fileExtension': '.exe'
            }
        ]

        # Call the function
        search_file_catalog_command()

        # Verify the correct calls were made to orenctl.getArg
        expected_calls = [
            'query', 'limit', 'offset', 'sort', 'group', 'fileName', 'fileType',
            'computerId', 'threat', 'fileState', 'hash'
        ]
        mock_get_arg.assert_has_calls([unittest.mock.call(arg) for arg in expected_calls])

        # Verify the results are processed correctly
        expected_result = {
            "catalogs": {
                'File(val.SHA1 === obj.SHA1)': [{
                    'Size': 1234,
                    'Path': '/path/to/file',
                    'SHA1': 'abc123',
                    'SHA256': 'def456',
                    'MD5': '789xyz',
                    'Name': 'test_file',
                    'Type': 'exe',
                    'ProductName': 'Test Product',
                    'ID': 'file_id',
                    'Publisher': 'Test Publisher',
                    'Company': 'Test Company',
                    'Extension': '.exe'
                }]
            },
            "raw_catalogs": [
                {
                    'fileSize': 1234,
                    'pathName': '/path/to/file',
                    'sha1': 'abc123',
                    'sha256': 'def456',
                    'md5': '789xyz',
                    'fileName': 'test_file',
                    'fileType': 'exe',
                    'productName': 'Test Product',
                    'id': 'file_id',
                    'publisher': 'Test Publisher',
                    'company': 'Test Company',
                    'fileExtension': '.exe'
                }
            ]
        }
        mock_results.assert_called_once_with(expected_result)

    @patch('VMWareCarbonBlackAppControl.orenctl.getArg')  # Mock the getArg method of orenctl
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl')  # Mock the VMWareCarbonBlackAppControl class
    @patch('VMWareCarbonBlackAppControl.orenctl.results')  # Mock the results method of orenctl
    def test_search_computer_command(self, mock_results, mock_vmwcbac_class, mock_get_arg):
        # Setup mock for orenctl.getArg
        mock_get_arg.side_effect = [
            'test_query', 10, 0, 'name', 'group', 'test_name', 'test_ip', 'test_mac', 'test_fields'
        ]

        # Setup mock for VMWareCarbonBlackAppControl
        mock_vmwcbac = Mock()
        mock_vmwcbac_class.return_value = mock_vmwcbac
        mock_vmwcbac.search_computer.return_value = [
            {
                'memorySize': 8192,
                'processorCount': 4,
                'processorModel': 'Intel i7',
                'osShortName': 'Windows',
                'osName': 'Windows 10',
                'macAddress': '00:1B:44:11:3A:B7',
                'machineModel': 'Dell XPS',
                'ipAddress': '192.168.1.10',
                'name': 'test-computer',
                'id': 'computer_id'
            }
        ]

        # Define the expected output
        expected_result = {
            "computers": {
                'Endpoint(val.ID === obj.ID)': [{
                    'Memory': 8192,
                    'Processors': 4,
                    'Processor': 'Intel i7',
                    'OS': 'Windows',
                    'OSVersion': 'Windows 10',
                    'MACAddress': '00:1B:44:11:3A:B7',
                    'Model': 'Dell XPS',
                    'IPAddress': '192.168.1.10',
                    'Hostname': 'test-computer',
                    'ID': 'computer_id'
                }]
            },
            "raw_computers": [
                {
                    'memorySize': 8192,
                    'processorCount': 4,
                    'processorModel': 'Intel i7',
                    'osShortName': 'Windows',
                    'osName': 'Windows 10',
                    'macAddress': '00:1B:44:11:3A:B7',
                    'machineModel': 'Dell XPS',
                    'ipAddress': '192.168.1.10',
                    'name': 'test-computer',
                    'id': 'computer_id'
                }
            ]
        }

        # Call the function
        search_computer_command()

        # Verify the correct calls were made to orenctl.getArg
        expected_calls = [
            'query', 'limit', 'offset', 'sort', 'group', 'name', 'ipAddress', 'macAddress', 'fields'
        ]
        mock_get_arg.assert_has_calls([unittest.mock.call(arg) for arg in expected_calls])

        # Verify the results are processed correctly
        mock_results.assert_called_once_with(expected_result)

    @patch('VMWareCarbonBlackAppControl.orenctl.getArg')  # Mock the getArg method of orenctl
    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl')  # Mock the VMWareCarbonBlackAppControl class
    @patch('VMWareCarbonBlackAppControl.orenctl.results')  # Mock the results method of orenctl
    def test_update_computer_command(self, mock_results, mock_vmwcbac_class, mock_get_arg):
        # Setup mock for orenctl.getArg
        mock_get_arg.side_effect = [
            'comp_id', 'test_name', 'test_tag', 'test_description', 'policy_id',
            True, False, 'refresh_flags', True, 'debug_level', 'kernel_debug_level',
            'debug_flags', 'debug_duration', 'cc_level', 'cc_flags', True, 'template'
        ]

        # Setup mock for VMWareCarbonBlackAppControl
        mock_vmwcbac = Mock()
        mock_vmwcbac_class.return_value = mock_vmwcbac
        mock_vmwcbac.update_computer.return_value = {
            'memorySize': 8192,
            'processorCount': 4,
            'processorModel': 'Intel i7',
            'osShortName': 'Windows',
            'osName': 'Windows 10',
            'macAddress': '00:1B:44:11:3A:B7',
            'machineModel': 'Dell XPS',
            'ipAddress': '192.168.1.10',
            'name': 'test-computer',
            'id': 'computer_id'
        }

        # Define the expected output
        expected_result = {
            'Endpoint(val.ID === obj.ID)': {
                'Memory': 8192,
                'Processors': 4,
                'Processor': 'Intel i7',
                'OS': 'Windows',
                'OSVersion': 'Windows 10',
                'MACAddress': '00:1B:44:11:3A:B7',
                'Model': 'Dell XPS',
                'IPAddress': '192.168.1.10',
                'Hostname': 'test-computer',
                'ID': 'computer_id'
            },
            'raw_computers': {
                'memorySize': 8192,
                'processorCount': 4,
                'processorModel': 'Intel i7',
                'osShortName': 'Windows',
                'osName': 'Windows 10',
                'macAddress': '00:1B:44:11:3A:B7',
                'machineModel': 'Dell XPS',
                'ipAddress': '192.168.1.10',
                'name': 'test-computer',
                'id': 'computer_id'
            }
        }

        # Call the function
        update_computer_command()

        # Verify the correct calls were made to orenctl.getArg
        expected_calls = [
            'id', 'name', 'computerTag', 'description', 'policyId',
            'automaticPolicy', 'localApproval', 'refreshFlags', 'prioritized',
            'debugLevel', 'kernelDebugLevel', 'debugFlags', 'debugDuration',
            'cCLevel', 'cCFlags', 'forceUpgrade', 'template'
        ]
        mock_get_arg.assert_has_calls([unittest.mock.call(arg) for arg in expected_calls])

        # Verify the results are processed correctly
        mock_results.assert_called_once_with(expected_result)

    @patch('VMWareCarbonBlackAppControl.VMWareCarbonBlackAppControl')  # Mock the VMWareCarbonBlackAppControl class
    @patch('VMWareCarbonBlackAppControl.orenctl.getArg')  # Mock the orenctl.getArg function
    @patch('VMWareCarbonBlackAppControl.orenctl.results')  # Mock the orenctl.results function
    def test_get_computer_command(self, mock_results, mock_get_arg, MockVmwcbac):
        # Setup mocks
        mock_get_arg.return_value = 'computer_id'  # Mock the ID to return
        mock_vmwcbac_instance = MockVmwcbac.return_value
        mock_vmwcbac_instance.get_computer.return_value = {
            'memorySize': 8192,
            'processorCount': 4,
            'processorModel': 'Intel i7',
            'osShortName': 'Windows',
            'osName': 'Windows 10',
            'macAddress': '00:1B:44:11:3A:B7',
            'machineModel': 'Dell XPS',
            'ipAddress': '192.168.1.10',
            'name': 'test-computer',
            'id': 'computer_id'
        }

        # Call the function
        get_computer_command()

        # Assert the correct results are passed to orenctl.results
        expected_computer = {
            'Memory': 8192,
            'Processors': 4,
            'Processor': 'Intel i7',
            'OS': 'Windows',
            'OSVersion': 'Windows 10',
            'MACAddress': '00:1B:44:11:3A:B7',
            'Model': 'Dell XPS',
            'IPAddress': '192.168.1.10',
            'Hostname': 'test-computer',
            'ID': 'computer_id'
        }
        expected_results = {
            'Endpoint(val.ID === obj.ID)': expected_computer,
            'raw_computers': {
                'memorySize': 8192,
                'processorCount': 4,
                'processorModel': 'Intel i7',
                'osShortName': 'Windows',
                'osName': 'Windows 10',
                'macAddress': '00:1B:44:11:3A:B7',
                'machineModel': 'Dell XPS',
                'ipAddress': '192.168.1.10',
                'name': 'test-computer',
                'id': 'computer_id'
            }
        }

        mock_results.assert_called_once_with(expected_results)
