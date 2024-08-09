import unittest
from unittest.mock import patch, MagicMock
import json
from TheHiveProject import TheHiveProject, list_cases_command, get_case_command, update_case_command, \
    create_case_command, create_task_command, update_task_command  # Update import to match your actual module name


class TestTheHiveProject(unittest.TestCase):

    @patch('orenctl.getParam')
    def setUp(self, mock_get_param):
        mock_get_param.side_effect = lambda key: {
            "url": "http://example.com",
            "domain": "example.com",
            "insecure": "false",
            "api_key": "api_key",
            "proxy": "http://proxy.com"
        }[key]
        self.client = TheHiveProject()

    @patch('requests.Session.request')
    def test_http_request_success(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"key": "value"}'
        mock_response.json.return_value = {"key": "value"}
        mock_request.return_value = mock_response

        response = self.client.http_request('GET', '/test')
        self.assertEqual(response, {"key": "value"})

    @patch('requests.Session.request')
    @patch('orenctl.results')
    def test_http_request_error(self, mock_results, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.content = b'Error'
        mock_request.return_value = mock_response

        with self.assertRaises(Exception):
            self.client.http_request('GET', '/test')

    @patch('requests.Session.request')
    def test_get_version(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'versions': {'TheHive': '4.0'}}
        mock_request.return_value = mock_response

        version = self.client.get_version()
        self.assertEqual(version, '4.0')

    @patch('requests.Session.request')
    def test_get_cases(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"cases": []}
        mock_request.return_value = mock_response

        response = self.client.get_cases()
        self.assertEqual(response, {"cases": []})

    @patch('requests.Session.request')
    def test_get_case(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"case": {"id": "1"}}
        mock_request.return_value = mock_response

        response = self.client.get_case("1")
        self.assertEqual(response, {"case": {"id": "1"}})

    @patch('requests.Session.request')
    def test_update_case(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"updated_case": True}
        mock_request.return_value = mock_response

        response = self.client.update_case("1", {"title": "Updated"})
        self.assertEqual(response, {"updated_case": True})

    @patch('requests.Session.request')
    def test_create_case(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"created_case": True}
        mock_request.return_value = mock_response

        response = self.client.create_case({"title": "New Case"})
        self.assertEqual(response, {"created_case": True})

    @patch('requests.Session.request')
    def test_create_task(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"created_task": True}
        mock_request.return_value = mock_response

        response = self.client.create_task("1", {"title": "New Task"})
        self.assertEqual(response, {"created_task": True})

    @patch('requests.Session.request')
    def test_update_task(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"updated_task": True}
        mock_request.return_value = mock_response

        response = self.client.update_task("1", {"title": "Updated Task"})
        self.assertEqual(response, {"updated_task": True})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')  # Update to match your actual module
    def test_list_cases_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: 10 if key == "limit" else None
        mock_client.return_value.get_cases.return_value = {"cases": []}

        list_cases_command()
        mock_client.return_value.get_cases.assert_called_once_with(limit=10)
        mock_results.assert_called_once_with({"cases": []})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')
    def test_get_case_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: "1" if key == "case_id" else None
        mock_client.return_value.get_case.return_value = {"case": {"id": "1"}}

        get_case_command()
        mock_client.return_value.get_case.assert_called_once_with(case_id="1")
        mock_results.assert_called_once_with({"case": {"id": "1"}})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')
    def test_update_case_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: "1" if key == "case_id" else "Updated" if key == "title" else None
        mock_client.return_value.get_case.return_value = {"id": "1"}
        mock_client.return_value.update_case.return_value = {"updated_case": True}

        update_case_command()
        mock_client.return_value.get_case.assert_called_once_with(case_id="1")
        mock_client.return_value.update_case.assert_called_once_with("1", {"title": "Updated"})
        mock_results.assert_called_once_with({"updated_case": {"updated_case": True}, "command_status": "Success"})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')
    def test_create_case_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: "New Case" if key == "title" else None
        mock_client.return_value.create_case.return_value = {"created_case": True}

        create_case_command()
        mock_client.return_value.create_case.assert_called_once_with({"title": "New Case"})
        mock_results.assert_called_once_with({"created_case": {"created_case": True}, "command_status": "Success"})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')
    def test_create_task_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: "1" if key == "case_id" else "New Task" if key == "title" else None
        mock_client.return_value.create_task.return_value = {"created_task": True}

        create_task_command()
        mock_client.return_value.create_task.assert_called_once_with("1", {"title": "New Task"})
        mock_results.assert_called_once_with({"created_task": {"created_task": True}, "command_status": "Success"})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('the_hive_module.TheHiveProject')
    def test_update_task_command(self, mock_client, mock_results, mock_get_arg):
        mock_get_arg.side_effect = lambda key: "1" if key == "task_id" else "Updated Task" if key == "title" else None
        mock_client.return_value.get_task.return_value = {"task": {"id": "1"}}
        mock_client.return_value.update_task.return_value = {"updated_task": True}

        update_task_command()
        mock_client.return_value.get_task.assert_called_once_with("1")
        mock_client.return_value.update_task.assert_called_once_with("1", {"title": "Updated Task"})
        mock_results.assert_called_once_with({"updated_task": {"updated_task": True}, "command_status": "Success"})


if __name__ == '__main__':
    unittest.main()
