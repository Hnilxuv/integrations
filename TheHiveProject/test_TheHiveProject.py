import unittest
from unittest.mock import patch, MagicMock
import orenctl

# Giả sử rằng các hàm command đã được import từ module của bạn
from TheHiveProject import (
    list_cases_command, get_case_command, update_case_command,
    create_case_command, create_task_command, update_task_command, TheHiveProject
)

def mock_getArg_side_effect(key):
    return {
        "limit": 50,
        "case_id": "12345",
        "title": "Test Case",
        "description": "Test Description",
        "severity": "High",
        "startdate": "2023-01-01T00:00:00Z",
        "owner": "test_owner",
        "flag": True,
        "tlp": 2,
        "tags": ["tag1", "tag2"],
        "resolutionstatus": "Resolved",
        "impactstatus": "High",
        "summary": "Test Summary",
        "enddate": "2023-01-02T00:00:00Z",
        "metrics": {"metric1": "value1"},
        "status": "Open",
        "task_id": "67890"
    }.get(key)

class TestTheHiveProjectCommands(unittest.TestCase):

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_list_cases_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_cases.return_value = {"cases": ["case1", "case2"]}

        list_cases_command()

        mock_instance.get_cases.assert_called_once_with(limit=50)
        mock_results.assert_called_once_with({"cases": {"cases": ["case1", "case2"]}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_list_cases_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_cases.side_effect = Exception("error")

        with self.assertRaises(Exception):
            list_cases_command()

        mock_instance.get_cases.assert_called_once_with(limit=50)
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_get_case_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_case.return_value = {"case": "case_details"}

        get_case_command()

        mock_instance.get_case.assert_called_once_with(case_id="12345")
        mock_results.assert_called_once_with({"case": {"case": "case_details"}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_get_case_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_case.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_case_command()

        mock_instance.get_case.assert_called_once_with(case_id="12345")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_update_case_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_case.return_value = {"case": "original_case"}
        mock_instance.update_case.return_value = {"case": "updated_case"}

        update_case_command()

        mock_instance.update_case.assert_called_once()
        mock_results.assert_called_once_with({
            "updated_case": {"case": "updated_case"},
            "command_status": "Success"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_update_case_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_case.return_value = None

        update_case_command()

        mock_instance.update_case.assert_not_called()
        mock_results.assert_called_once_with({
            "updated_case": "Could not find case ID 12345.",
            "command_status": "Fail"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_create_case_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.create_case.return_value = {"case": "created_case"}

        create_case_command()

        mock_instance.create_case.assert_called_once()
        mock_results.assert_called_once_with({
            "created_case": {"case": "created_case"},
            "command_status": "Success"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_create_case_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.create_case.side_effect = Exception("error")

        with self.assertRaises(Exception):
            create_case_command()

        mock_instance.create_case.assert_called_once()
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_create_task_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.create_task.return_value = {"task": "created_task"}

        create_task_command()

        mock_results.assert_called_once_with({
            "created_task": {"task": "created_task"},
            "command_status": "Success"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_create_task_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.create_task.side_effect = Exception("error")

        with self.assertRaises(Exception):
            create_task_command()

        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_update_task_command_success(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_task.return_value = {"task": "original_task"}
        mock_instance.update_task.return_value = {"task": "updated_task"}

        update_task_command()

        mock_instance.update_task.assert_called_once()
        mock_results.assert_called_once_with({
            "updated_task": {"task": "updated_task"},
            "command_status": "Success"
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('TheHiveProject.TheHiveProject')
    def test_update_task_command_failure(self, mock_TheHiveProject, mock_results, mock_getArg):
        mock_instance = mock_TheHiveProject.return_value
        mock_instance.get_task.return_value = None

        update_task_command()

        mock_instance.update_task.assert_not_called()
        mock_results.assert_called_once_with({
            "updated_task": "No task found with id: 67890.",
            "command_status": "Fail"
        })

class TestTheHiveProjectMethods(unittest.TestCase):

    @patch('orenctl.getParam')
    @patch('requests.Session')
    def setUp(self, mock_Session, mock_getParam):
        self.mock_session = mock_Session.return_value
        mock_getParam.side_effect = lambda key: {
            "url": "https://thehive.test",
            "domain": "test_domain",
            "insecure": True,
            "api_key": "test_api_key",
            "proxy": "http://proxy.test"
        }.get(key)
        self.client = TheHiveProject()

    @patch('TheHiveProject.requests.Session.request')
    def test_http_request_success(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"key": "value"}
        mock_request.return_value = mock_response

        response = self.client.http_request("GET", "/test")

        self.assertEqual(response, {"key": "value"})
        mock_request.assert_called_once_with(
            method="GET",
            url="https://thehive.test/api/test",
            verify=False
        )

    @patch('TheHiveProject.requests.Session.request')
    @patch('orenctl.results')
    def test_http_request_failure(self, mock_results, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.content = b"Bad Request"
        mock_request.return_value = mock_response

        with self.assertRaises(Exception):
            self.client.http_request("GET", "/test")

        mock_request.assert_called_once_with(
            method="GET",
            url="https://thehive.test/api/test",
            verify=False
        )
        mock_results.assert_called_once_with(
            orenctl.error("Http request error: 400 b'Bad Request'")
        )

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_version_success(self, mock_http_request):
        mock_http_request.return_value = {
            "versions": {
                "TheHive": "4.1.0"
            }
        }

        version = self.client.get_version()

        self.assertEqual(version, "4.1.0")
        mock_http_request.assert_called_once_with('GET', '/status')

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_version_unknown(self, mock_http_request):
        mock_http_request.return_value = {
            "versions": {
                "Other": "1.0.0"
            }
        }

        version = self.client.get_version()

        self.assertEqual(version, "Unknown")
        mock_http_request.assert_called_once_with('GET', '/status')

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_cases(self, mock_http_request):
        mock_http_request.return_value = {"cases": ["case1", "case2"]}

        cases = self.client.get_cases(limit=10, start_time=0)

        self.assertEqual(cases, {"cases": ["case1", "case2"]})
        mock_http_request.assert_called_once_with(
            "POST",
            "/v1/query",
            json={
                "query": [
                    {"_name": "listCase"},
                    {"_name": "filter", "_gte": {"_field": "_createdAt", "_value": 0}},
                    {"_name": "sort", "_fields": [{"_createdAt": "asc"}]},
                    {"_name": "page", "from": 0, "to": 10}
                ]
            },
            params={"name": "list-cases"}
        )

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_case(self, mock_http_request):
        mock_http_request.return_value = {"case": "details"}

        case = self.client.get_case(case_id="12345")

        self.assertEqual(case, {"case": "details"})
        mock_http_request.assert_called_once_with("GET", "/case/12345")

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_update_case(self, mock_http_request):
        mock_http_request.return_value = {"case": "updated"}

        case = self.client.update_case(case_id="12345", updates={"key": "value"})

        self.assertEqual(case, {"case": "updated"})
        mock_http_request.assert_called_once_with("PATCH", "/case/12345", json={"key": "value"})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_create_case(self, mock_http_request):
        mock_http_request.return_value = {"case": "created"}

        case = self.client.create_case(details={"key": "value"})

        self.assertEqual(case, {"case": "created"})
        mock_http_request.assert_called_once_with("POST", "/case", json={"key": "value"})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_create_task(self, mock_http_request):
        mock_http_request.return_value = {"task": "created"}

        task = self.client.create_task(case_id="12345", data={"key": "value"})

        self.assertEqual(task, {"task": "created"})
        mock_http_request.assert_called_once_with("POST", "/case/12345/task", data={"key": "value"})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_update_task(self, mock_http_request):
        mock_http_request.return_value = {"task": "updated"}

        task = self.client.update_task(task_id="67890", updates={"key": "value"})

        self.assertEqual(task, {"task": "updated"})
        mock_http_request.assert_called_once_with("PATCH", "/case/task/67890", data={"key": "value"})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_task_v4(self, mock_http_request):
        self.client.version = "4.1.0"
        mock_http_request.return_value = {"task": "details"}

        task = self.client.get_task(task_id="67890")

        self.assertEqual(task, {"task": "details"})
        mock_http_request.assert_called_once_with(
            "POST",
            "/v1/query",
            params={"name": "get-task-67890"},
            json={
                "query": [
                    {"_name": "getTask", "idOrName": "67890"},
                    {"_name": "page", "from": 0, "to": 1}
                ]
            }
        )

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_task_other_version(self, mock_http_request):
        self.client.version = "3.4.0"
        mock_http_request.return_value = {"task": "details"}

        task = self.client.get_task(task_id="67890")

        self.assertEqual(task, {"task": "details"})
        mock_http_request.assert_called_once_with("GET", "/case/task/67890")

class TestTheHiveProjectMethods(unittest.TestCase):

    @patch('orenctl.getParam')
    @patch('requests.Session')
    @patch('TheHiveProject.TheHiveProject.get_version')
    def setUp(self, mock_get_version, mock_Session, mock_getParam):
        self.mock_session = mock_Session.return_value
        mock_getParam.side_effect = lambda key: {
            "url": "https://thehive.test",
            "domain": "test_domain",
            "insecure": True,
            "api_key": "test_api_key",
            "proxy": "http://proxy.test"
        }.get(key)
        self.client = TheHiveProject()

        # Set up the default mock response for `get_version`
        mock_get_version.return_value = "4.1.0"

    @patch('TheHiveProject.requests.Session.request')
    def test_http_request_put(self, mock_request):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"key": "value"}
        mock_request.return_value = mock_response

        response = self.client.http_request("PUT", "/test")

        self.assertEqual(response, {"key": "value"})
        mock_request.assert_called_once_with(
            method="PUT",
            url="https://thehive.test/api/test",
            verify=False
        )

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_version_other_versions(self, mock_http_request):
        # Mock response for other versions
        mock_http_request.return_value = {
            "versions": {
                "SomeOtherService": "1.0.0"
            }
        }

        version = self.client.get_version()

        self.assertEqual(version, "Unknown")
        mock_http_request.assert_called_once_with('GET', '/status')

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_create_case_with_different_data(self, mock_http_request):
        # Mock response for creating case
        mock_http_request.return_value = {"case": "created_with_data"}

        case = self.client.create_case(details={"key": "different_value"})

        self.assertEqual(case, {"case": "created_with_data"})
        mock_http_request.assert_called_once_with("POST", "/case", json={"key": "different_value"})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_update_case_with_minimal_data(self, mock_http_request):
        # Mock response for updating case with minimal data
        mock_http_request.return_value = {"case": "updated_minimal"}

        case = self.client.update_case(case_id="12345", updates={})

        self.assertEqual(case, {"case": "updated_minimal"})
        mock_http_request.assert_called_once_with("PATCH", "/case/12345", json={})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_update_case_with_large_data(self, mock_http_request):
        # Mock response for updating case with large data
        mock_http_request.return_value = {"case": "updated_large"}

        case = self.client.update_case(case_id="12345", updates={"key": "x" * 1000})

        self.assertEqual(case, {"case": "updated_large"})
        mock_http_request.assert_called_once_with("PATCH", "/case/12345", json={"key": "x" * 1000})

    @patch('TheHiveProject.TheHiveProject.http_request')
    def test_get_task_with_invalid_id(self, mock_http_request):
        # Mock response for getting a task with an invalid ID
        mock_http_request.return_value = {"error": "Task not found"}

        task = self.client.get_task(task_id="invalid_id")

        self.assertEqual(task, {"error": "Task not found"})
        mock_http_request.assert_called_once_with("GET", "/case/task/invalid_id")


if __name__ == '__main__':
    unittest.main()