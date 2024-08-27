import unittest
from unittest.mock import MagicMock, patch

import requests
from requests import HTTPError
import orenctl

from Endace import Endace, arg_to_list, endace_create_search_command, endace_get_search_status_command, \
    endace_create_archive_command, endace_get_archive_status_command, endace_download_pcap_command


def mock_getArg_side_effect(key):
    return {
        'start': "2020-04-15T14:48:12",
        'end': "2020-04-16T14:48:12",
        'ip': '1.1.1.1',
        'port': '8080',
        'src_host_list': ['1.1.1.1', '1.1.1.2', '1.1.1'],
        'dest_host_list': ['1.1.1.1', '1.1.1.2', '1.1'],
        'src_port_list': ['80', '8080', '8080', ''],
        'dest_port_list': ['80', '8080', '8080', ''],
        'protocol': 'TCP',
        'timeframe': '1hour'
    }.get(key)


class TestEndace(unittest.TestCase):
    def setUp(self):
        self.app = MagicMock()

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request, mock_getParam):
        mock_getParam.return_value = 'http://example.com'
        mock_request.return_value = MagicMock(status_code=200, content=b'{"key": "value"}')
        mock_request.return_value.json.return_value = {"key": "value"}

        endace = Endace()

        result = endace.http_request('GET', '/test_url')

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

        endace = Endace()

        with self.assertRaises(HTTPError):
            endace.http_request('GET', '/test_url')

    @patch('orenctl.getParam')
    def test_initialization(self, mock_getParam):
        mock_getParam.side_effect = lambda param: {
            'url': 'http://example.com',
            'username': 'admin',
            'password': '123',
            'insecure': 'true',
            'hostname': 'test_host_name'
        }.get(param)

        endace = Endace()

        self.assertEqual(endace.url, 'http://example.com')
        self.assertTrue(endace.insecure)
        self.assertEqual(endace.username, 'admin')
        self.assertIsInstance(endace.session, requests.Session)

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

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_create_search_command_success(self, mock_error, mock_results, mock_arg_data, MockEndace):
        mock_endace_instance = MagicMock()
        MockEndace.return_value = mock_endace_instance

        mock_endace_instance.endace_get_input_arguments.return_value = {
            'start': '2020-04-15T14:48:12',
            'end': '2020-04-16T14:48:12',
            'ip': '1.1.1.1'
        }
        mock_endace_instance.create_search_task.return_value = {
            "Task": "CreateSearchTask",
            "Status": "Started",
            "Error": "NoError",
            "JobID": "12345"
        }

        mock_arg_data.return_value = {
            'start': '2020-04-15T14:48:12',
            'end': '2020-04-16T14:48:12'
        }

        endace_create_search_command()

        expected_result = {
            "output": {'Endace.Search.Task(val.JobID == obj.JobID)': {
                "Task": "CreateSearchTask",
                "Status": "Started",
                "Error": "NoError",
                "JobID": "12345"
            }},
            "raw_response": {
                "Task": "CreateSearchTask",
                "Status": "Started",
                "Error": "NoError",
                "JobID": "12345"
            }
        }

        mock_results.assert_called_once_with(expected_result)
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_get_search_status_command_success(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_endace_instance = MagicMock()
        MockEndace.return_value = mock_endace_instance

        orenctl.set_input_args(
            {'jobid': 'c944a329-bf16-4e51-ac58-900f17fa1a52'})
        mock_endace_instance.get_search_status.return_value = {
            "jobid": "abc123",
            "Status": "Completed",
            "Details": "Search completed successfully."
        }

        endace_get_search_status_command()

        expected_result = {'output': {
            'Endace.Search.Response(val.JobID == obj.JobID)': {'jobid': 'abc123', 'Status': 'Completed',
                                                               'Details': 'Search completed successfully.'}},
            'raw_response': {'jobid': 'abc123', 'Status': 'Completed',
                             'Details': 'Search completed successfully.'}}

        mock_results.assert_called_once_with(expected_result)
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('orenctl.getArg')
    def test_endace_get_search_status_command_invalid_jobid(self, mock_getArg, MockEndace):
        MockEndace.return_value = MagicMock()

        mock_getArg.return_value = 'invalid_job_id'

        with self.assertRaises(ValueError) as context:
            endace_get_search_status_command()

        self.assertEqual(str(context.exception), "Wrong JOB ID provided")

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    def test_endace_create_archive_command_invalid_filename(self, mock_getArg, MockEndace):
        MockEndace.return_value = MagicMock()

        mock_getArg.return_value = {
            'archive_filename': 'invalid/filename',
            'start': '2024-01-01T00:00:00',
            'end': '2024-01-01T01:00:00'
        }

        with self.assertRaises(ValueError) as context:
            endace_create_archive_command()

        self.assertEqual(str(context.exception),
                         "Wrong format of archive_filename. text, numbers, underscore or dash is supported")

    @patch('Endace.Endace')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_get_search_status_command_invalid_jobid(self, mock_error, mock_results, mock_getArg, MockEndace):
        MockEndace.return_value = MagicMock()

        mock_getArg.return_value = 'invalid_jobid'

        endace_get_search_status_command()

        er = orenctl.get_errors()
        self.assertEqual(er, {})

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_create_archive_command_success(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_endace_instance = MagicMock()
        MockEndace.return_value = mock_endace_instance

        mock_getArg.return_value = {
            'archive_filename': 'event'
        }
        mock_endace_instance.endace_get_input_arguments.return_value = {
            'archive_filename': 'valid-archive_name',
            'start': '2024-01-01T00:00:00',
            'end': '2024-01-01T01:00:00'
        }
        mock_endace_instance.create_archive_task.return_value = {
            "JobID": "job123",
            "Status": "Started",
            "Error": "NoError"
        }

        endace_create_archive_command()

        expected_result = {
            "output": {'Endace.Archive.Task(val.JobID == obj.JobID)': {
                "JobID": "job123",
                "Status": "Started",
                "Error": "NoError"
            }},
            "raw_response": {
                "JobID": "job123",
                "Status": "Started",
                "Error": "NoError"
            }
        }

        mock_results.assert_called_once_with(expected_result)
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_get_archive_status_command_success(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_endace_instance = MagicMock()
        MockEndace.return_value = mock_endace_instance

        mock_getArg.return_value = {
            'archive_filename': 'valid-archive_name'
        }

        mock_endace_instance.get_archive_status.return_value = {
            "FileName": "valid-archive_name",
            "Status": "Completed",
            "Error": "NoError"
        }

        endace_get_archive_status_command()

        expected_result = {
            "output": {'Endace.Archive.Response(val.FileName == obj.FileName)': {
                "FileName": "valid-archive_name",
                "Status": "Completed",
                "Error": "NoError"
            }},
            "raw_response": {
                "FileName": "valid-archive_name",
                "Status": "Completed",
                "Error": "NoError"
            }
        }

        mock_results.assert_called_once_with(expected_result)
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_get_archive_status_command_invalid_filename(self, mock_error, mock_results, mock_getArg,
                                                                MockEndace):
        mock_getArg.return_value = {
            'archive_filename': 'invalid filename!'
        }

        with self.assertRaises(ValueError) as context:
            endace_get_archive_status_command()

        self.assertEqual(str(context.exception),
                         "Wrong format of archive_filename. text, numbers, underscore or dash is supported")
        mock_results.assert_not_called()
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_download_pcap_command_success(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_endace_instance = MagicMock()
        MockEndace.return_value = mock_endace_instance

        mock_getArg.return_value = {
            'filename': 'testfile.pcap',
            'filesizelimit': '10'
        }

        mock_endace_instance.download_pcap.return_value = {
            "FileName": "testfile.pcap",
            "Status": "Downloaded",
            "Error": "NoError"
        }

        endace_download_pcap_command()

        expected_result = {
            "output": {'Endace.Download.PCAP(val.FileName == obj.FileName)': {
                "FileName": "testfile.pcap",
                "Status": "Downloaded",
                "Error": "NoError"
            }},
            "raw_response": {
                "FileName": "testfile.pcap",
                "Status": "Downloaded",
                "Error": "NoError"
            }
        }

        mock_results.assert_called_once_with(expected_result)
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_download_pcap_command_invalid_filesize(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_getArg.return_value = {
            'filename': 'testfile.pcap',
            'filesizelimit': '0'
        }

        with self.assertRaises(ValueError) as context:
            endace_download_pcap_command()

        self.assertEqual(str(context.exception), "Filesize Limit value is incorrect, must be an integer 1  or greater")
        mock_results.assert_not_called()
        mock_error.assert_not_called()

    @patch('Endace.Endace')
    @patch('Endace.arg_data')
    @patch('orenctl.results')
    @patch('orenctl.error')
    def test_endace_download_pcap_command_no_filename(self, mock_error, mock_results, mock_getArg, MockEndace):
        mock_getArg.return_value = {}

        endace_download_pcap_command()

        mock_error.assert_called_once_with("FileName must be provided")
        mock_results.assert_called_once_with(mock_error())
