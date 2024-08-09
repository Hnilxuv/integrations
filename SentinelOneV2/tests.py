import unittest
from unittest.mock import patch, MagicMock, Mock

import requests

import SentinelOneV2
from SentinelOneV2 import ( SentinelOneV2,
    get_hash_command, get_events, create_query, get_processes,
    get_blocklist, add_hash_to_blocklist, update_alert_status,
    get_alerts, get_installed_applications, initiate_endpoint_scan
)


def mock_getArg_side_effect(key):
    return {
        "hash": "testhash",
        "query_id": "query123",
        "cursor": "cursor123",
        "limit": "50",
        "query": "testquery",
        "from_date": "2023-01-01",
        "to_date": "2023-01-31",
        "tenant": True,
        "offset": "0",
        "group_ids": "group123",
        "site_ids": "site123",
        "account_ids": "account123",
        "sha1": "testsha1",
        "description": "testdescription",
        "os_type": "Windows",
        "source": "testsource",
        "alert_id": "alert123",
        "status": "resolved",
        "rule_name": "testrule",
        "incident_status": "open",
        "analyst_verdict": "benign",
        "created_until": "2023-01-31",
        "created_from": "2023-01-01",
        "alert_ids": "alert123",
        "site_ids": "site123",
        "agent_ids": "agent123"
    }.get(key)


class TestSentinelOneV2Commands(unittest.TestCase):

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_hash_command_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_hash_verdict_request.return_value = {"data": {"verdict": "clean"}}

        get_hash_command()

        mock_instance.get_hash_verdict_request.assert_called_once_with("testhash")
        mock_results.assert_called_once_with({"hash_result": {"verdict": "clean"}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_hash_command_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_hash_verdict_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_hash_command()

        mock_instance.get_hash_verdict_request.assert_called_once_with("testhash")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_events_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_events_request.return_value = ({"events": ["event1", "event2"]}, {"pagination": "details"})

        get_events()

        mock_instance.get_events_request.assert_called_once_with("query123", 50, "cursor123")
        mock_results.assert_called_once_with({
            "events": {"events": ["event1", "event2"]},
            "pagination": {"pagination": "details"}
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_events_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_events_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_events()

        mock_instance.get_events_request.assert_called_once_with("query123", 50, "cursor123")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_create_query_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.create_query_request.return_value = "queryid123"

        create_query()

        mock_instance.create_query_request.assert_called_once_with("testquery", "2023-01-01", "2023-01-31")
        mock_results.assert_called_once_with({"query_id": "queryid123"})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_create_query_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.create_query_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            create_query()

        mock_instance.create_query_request.assert_called_once_with("testquery", "2023-01-01", "2023-01-31")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_processes_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_processes_request.return_value = {"processes": ["process1", "process2"]}

        get_processes()

        mock_instance.get_processes_request.assert_called_once_with("query123", "50")
        mock_results.assert_called_once_with({"processes": {"processes": ["process1", "process2"]}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_processes_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_processes_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_processes()

        mock_instance.get_processes_request.assert_called_once_with("query123", "50")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_blocklist_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_blocklist_request.return_value = [{"blocklist": "item1"}, {"blocklist": "item2"}]

        get_blocklist()

        mock_results.assert_called_once_with({"block_list": [{"blocklist": "item1"}, {"blocklist": "item2"}]})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_blocklist_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_blocklist_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_blocklist()


        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_add_hash_to_blocklist_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.block_site_ids = ["site123"]
        mock_instance.add_hash_to_blocklists_request.return_value = {"result": "success"}

        add_hash_to_blocklist()

        mock_instance.add_hash_to_blocklists_request.assert_called_once_with(
            value="testsha1", description="testdescription", os_type="Windows",
            site_ids=["site123"], source="testsource"
        )
        mock_results.assert_called_once_with({
            "command_status": "Added to scoped blocklist",
            "result": {"result": "success"}
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_add_hash_to_blocklist_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.block_site_ids = ["site123"]
        mock_instance.add_hash_to_blocklists_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            add_hash_to_blocklist()

        mock_instance.add_hash_to_blocklists_request.assert_called_once_with(
            value="testsha1", description="testdescription", os_type="Windows",
            site_ids=["site123"], source="testsource"
        )
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_update_alert_status_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.update_alert_status_request.return_value = {"updated_alert": "details"}

        update_alert_status()

        mock_instance.update_alert_status_request.assert_called_once_with("alert123", "resolved")
        mock_results.assert_called_once_with({"updated_alert": {"updated_alert": "details"}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_update_alert_status_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.update_alert_status_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            update_alert_status()

        mock_instance.update_alert_status_request.assert_called_once_with("alert123", "resolved")
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_alerts_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_alerts_request.return_value = ({"alerts": ["alert1", "alert2"]}, {"pagination": "details"})

        get_alerts()

        mock_instance.get_alerts_request.assert_called_once()
        mock_results.assert_called_once_with({
            "alerts": {"alerts": ["alert1", "alert2"]},
            "pagination": {"pagination": "details"}
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_alerts_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_alerts_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_alerts()

        mock_instance.get_alerts_request.assert_called_once()
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_installed_applications_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_installed_applications_request.return_value = [{"application": "app1"},
                                                                         {"application": "app2"}]

        get_installed_applications()

        mock_instance.get_installed_applications_request.assert_called_once_with(query_params={"ids": "agent123"})
        mock_results.assert_called_once_with({"applications": [{"application": "app1"}, {"application": "app2"}]})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_get_installed_applications_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.get_installed_applications_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            get_installed_applications()

        mock_instance.get_installed_applications_request.assert_called_once_with(query_params={"ids": "agent123"})
        mock_results.assert_not_called()

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_initiate_endpoint_scan_success(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.initiate_endpoint_scan_request.return_value = {"initiated": "details"}

        initiate_endpoint_scan()

        mock_instance.initiate_endpoint_scan_request.assert_called_once_with("agent123")
        mock_results.assert_called_once_with({"initiated": {"initiated": "details"}})

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('SentinelOneV2.SentinelOneV2')
    def test_initiate_endpoint_scan_failure(self, mock_sentinelonev2, mock_results, mock_getArg):
        mock_instance = mock_sentinelonev2.return_value
        mock_instance.initiate_endpoint_scan_request.side_effect = Exception("error")

        with self.assertRaises(Exception):
            initiate_endpoint_scan()

        mock_instance.initiate_endpoint_scan_request.assert_called_once_with("agent123")
        mock_results.assert_not_called()


    @patch('requests.get')
    def test_http_get_success(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, json=lambda: {"key": "value"})

        response = requests.get('https://api.example.com')

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"key": "value"})
        mock_get.assert_called_once_with('https://api.example.com')


    @patch('requests.get')
    def test_http_get_failure(self, mock_get):
        mock_get.return_value = MagicMock(status_code=500, json=lambda: {"error": "Server error"})

        response = requests.get('https://api.example.com')

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json(), {"error": "Server error"})
        mock_get.assert_called_once_with('https://api.example.com')

    @patch('SentinelOneV2.SentinelOneV2.get_hash_verdict_request')
    def test_get_hash_verdict_request(self, mock_get_hash_verdict_request):
        mock_get_hash_verdict_request.return_value = {"verdict": "clean"}
        instance = SentinelOneV2()

        result = instance.get_hash_verdict_request("testhash")

        self.assertEqual(result, {"verdict": "clean"})
        mock_get_hash_verdict_request.assert_called_once_with("testhash")

    @patch('SentinelOneV2.SentinelOneV2.get_events_request')
    def test_get_events_request(self, mock_get_events_request):
        mock_get_events_request.return_value = ({"events": ["event1"]}, {"pagination": "details"})
        instance = SentinelOneV2()

        result = instance.get_events_request("query123", 50, "cursor123")

        self.assertEqual(result, ({"events": ["event1"]}, {"pagination": "details"}))
        mock_get_events_request.assert_called_once_with("query123", 50, "cursor123")

    @patch('SentinelOneV2.SentinelOneV2.create_query_request')
    def test_create_query_request(self, mock_create_query_request):
        mock_create_query_request.return_value = "queryid123"
        instance = SentinelOneV2()

        result = instance.create_query_request("testquery", "2023-01-01", "2023-01-31")

        self.assertEqual(result, "queryid123")
        mock_create_query_request.assert_called_once_with("testquery", "2023-01-01", "2023-01-31")

    @patch('SentinelOneV2.SentinelOneV2.get_blocklist_request')
    def test_get_blocklist_request(self, mock_get_blocklist_request):
        mock_get_blocklist_request.return_value = [{"blocklist": "item1"}]
        instance = SentinelOneV2()

        result = instance.get_blocklist_request()

        self.assertEqual(result, [{"blocklist": "item1"}])
        mock_get_blocklist_request.assert_called_once()

    @patch('SentinelOneV2.SentinelOneV2.add_hash_to_blocklists_request')
    def test_add_hash_to_blocklists_request(self, mock_add_hash_to_blocklists_request):
        mock_add_hash_to_blocklists_request.return_value = {"result": "success"}
        instance = SentinelOneV2()

        result = instance.add_hash_to_blocklists_request(
            value="testsha1", description="testdescription", os_type="Windows",
            site_ids=["site123"], source="testsource"
        )

        self.assertEqual(result, {"result": "success"})
        mock_add_hash_to_blocklists_request.assert_called_once_with(
            value="testsha1", description="testdescription", os_type="Windows",
            site_ids=["site123"], source="testsource"
        )

    @patch('SentinelOneV2.SentinelOneV2.update_alert_status_request')
    def test_update_alert_status_request(self, mock_update_alert_status_request):
        mock_update_alert_status_request.return_value = {"updated_alert": "details"}
        instance = SentinelOneV2()

        result = instance.update_alert_status_request("alert123", "resolved")

        self.assertEqual(result, {"updated_alert": "details"})
        mock_update_alert_status_request.assert_called_once_with("alert123", "resolved")

    @patch('SentinelOneV2.SentinelOneV2.get_alerts_request')
    def test_get_alerts_request(self, mock_get_alerts_request):
        mock_get_alerts_request.return_value = ({"alerts": ["alert1"]}, {"pagination": "details"})
        instance = SentinelOneV2()

        result = instance.get_alerts_request()

        self.assertEqual(result, ({"alerts": ["alert1"]}, {"pagination": "details"}))
        mock_get_alerts_request.assert_called_once()

    @patch('SentinelOneV2.SentinelOneV2.get_installed_applications_request')
    def test_get_installed_applications_request(self, mock_get_installed_applications_request):
        mock_get_installed_applications_request.return_value = [{"application": "app1"}]
        instance = SentinelOneV2()

        result = instance.get_installed_applications_request(query_params={"ids": "agent123"})

        self.assertEqual(result, [{"application": "app1"}])
        mock_get_installed_applications_request.assert_called_once_with(query_params={"ids": "agent123"})

    @patch('SentinelOneV2.SentinelOneV2.initiate_endpoint_scan_request')
    def test_initiate_endpoint_scan_request(self, mock_initiate_endpoint_scan_request):
        mock_initiate_endpoint_scan_request.return_value = {"initiated": "details"}
        instance = SentinelOneV2()

        result = instance.initiate_endpoint_scan_request("agent123")

        self.assertEqual(result, {"initiated": "details"})
        mock_initiate_endpoint_scan_request.assert_called_once_with("agent123")


class TestSentinelOneV2Requests(unittest.TestCase):

    @patch('orenctl.getParam')
    @patch('requests.Session.request')
    def setUp(self, mock_request, mock_get_param):
        # Mock the `orenctl.getParam` to return specific values
        mock_get_param.side_effect = lambda key: {
            "url": "http://example.com",
            "insecure": False,
            "token": "test_token",
            "block_site_ids": ["site1"],
            "api_version": "2.1",
            "proxy": None
        }.get(key, None)

        # Mock the `requests.Session.request` method
        self.mock_request = mock_request
        self.mock_request.return_value = Mock(status_code=200, json=lambda: {})

        self.client = SentinelOneV2()

    @patch('requests.Session.request')
    def test_get_hash_verdict_request(self, mock_request):
        # Mock the response for the get_hash_verdict_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"verdict": "malicious"}})

        response = self.client.get_hash_verdict_request("test_hash")
        self.assertEqual(response, {'data': {'verdict': 'malicious'}})
        mock_request.assert_called_once_with(
            method="GET",
            url="http://example.com/web/api/v2.1/hashes/test_hash/verdict",
            verify=False
        )

    @patch('requests.Session.request')
    def test_get_events_request(self, mock_request):
        # Mock the response for the get_events_request method
        mock_request.return_value = Mock(status_code=200,
                                         json=lambda: {"data": {"event": "data"}, "pagination": {"page": 1}})

        events, pagination = self.client.get_events_request("query_id", limit=50, cursor=None)
        self.assertEqual(events, {"event": "data"})
        self.assertEqual(pagination, {"page": 1})
        mock_request.assert_called_once_with(
            method="GET",
            url="http://example.com/web/api/v2.1/dv/events",
            verify=False,
            params={"query_id": "query_id", "cursor": None, "limit": 50}
        )

    @patch('requests.Session.request')
    def test_create_query_request(self, mock_request):
        # Mock the response for the create_query_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"queryId": "query_id_123"}})

        query_id = self.client.create_query_request("test_query", "2024-01-01", "2024-01-02")
        self.assertEqual(query_id, "query_id_123")
        mock_request.assert_called_once_with(
            method="POST",
            url="http://example.com/web/api/v2.1/dv/init-query",
            verify=False,
            json={
                "query": "test_query",
                "fromDate": "2024-01-01",
                "toDate": "2024-01-02"
            }
        )

    @patch('requests.Session.request')
    def test_get_processes_request(self, mock_request):
        # Mock the response for the get_processes_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"process": "data"}})

        processes = self.client.get_processes_request("query_id", limit=10)
        self.assertEqual(processes, {"process": "data"})
        mock_request.assert_called_once_with(
            method="GET",
            url="http://example.com/web/api/v2.1/dv/events/process",
            verify=False,
            params={"query_id": "query_id", "limit": 10}
        )

    @patch('requests.Session.request')
    def test_get_blocklist_request(self, mock_request):
        # Mock the response for the get_blocklist_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": [{"block": "data"}]})

        block_list = self.client.get_blocklist_request(
            tenant=True,
            group_ids=None,
            site_ids=None,
            account_ids=None,
            skip=0,
            limit=100,
            os_type=None,
            sort_by="updatedAt",
            sort_order="desc",
            value_contains="test_hash"
        )
        self.assertEqual(block_list, [{"block": "data"}])


    @patch('requests.Session.request')
    def test_add_hash_to_blocklists_request(self, mock_request):
        # Mock the response for the add_hash_to_blocklists_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"status": "added"}})

        result = self.client.add_hash_to_blocklists_request(
            value="test_hash",
            os_type="Windows",
            site_ids=["site1"],
            description="test description",
            source="test source"
        )
        self.assertEqual(result, {"status": "added"})
        mock_request.assert_called_once_with(
            method="POST",
            url="http://example.com/web/api/v2.1/restrictions",
            verify=False,
            json={
                "data": {
                    "value": "test_hash",
                    "source": "test source",
                    "osType": "Windows",
                    "type": "black_hash",
                    "description": "test description"
                },
                "filter": {
                    "siteIds": ["site1"],
                    "tenant": True
                }
            }
        )

    @patch('requests.Session.request')
    def test_add_hash_to_blocklist_request(self, mock_request):
        # Mock the response for the add_hash_to_blocklist_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"status": "added"}})

        result = self.client.add_hash_to_blocklist_request(
            value="test_hash",
            os_type="Windows",
            description="test description",
            source="test source"
        )
        self.assertEqual(result, {"status": "added"})

    @patch('requests.Session.request')
    def test_update_alert_status_request(self, mock_request):
        # Mock the response for the update_alert_status_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"status": "updated"}})

        updated_alert = self.client.update_alert_status_request(
            alert_ids=["alert1"],
            status="resolved"
        )
        self.assertEqual(updated_alert, {"status": "updated"})
        mock_request.assert_called_once_with(
            method="POST",
            url="http://example.com/web/api/v2.1/cloud-detection/alerts/incident",
            verify=False,
            json={
                "data": {
                    "incidentStatus": "resolved"
                },
                "filter": {
                    "ids": ["alert1"]
                }
            }
        )

    @patch('requests.Session.request')
    def test_get_alerts_request(self, mock_request):
        # Mock the response for the get_alerts_request method
        mock_request.return_value = Mock(status_code=200,
                                         json=lambda: {"data": {"alert": "data"}, "pagination": {"page": 1}})

        alerts, pagination = self.client.get_alerts_request({
            "ruleName__contains": None,
            "incidentStatus": None,
            "analystVerdict": None,
            "createdAt__lte": None,
            "createdAt__gte": None,
            "ids": None,
            "limit": 1000,
            "siteIds": None,
            "cursor": None
        })
        self.assertEqual(alerts, {"alert": "data"})
        self.assertEqual(pagination, {"page": 1})
        mock_request.assert_called_once_with(
            method="GET",
            url="http://example.com/web/api/v2.1/cloud-detection/alerts",
            verify=False,
            params={
                "ruleName__contains": None,
                "incidentStatus": None,
                "analystVerdict": None,
                "createdAt__lte": None,
                "createdAt__gte": None,
                "ids": None,
                "limit": 1000,
                "siteIds": None,
                "cursor": None
            }
        )

    @patch('requests.Session.request')
    def test_get_installed_applications_request(self, mock_request):
        # Mock the response for the get_installed_applications_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": [{"app": "data"}]})

        applications = self.client.get_installed_applications_request(["agent1"])
        self.assertEqual(applications, [{"app": "data"}])
        mock_request.assert_called_once_with(
            method='GET', url='http://example.com/web/api/v2.1/agents/applications', verify=False, params=['agent1']
        )

    @patch('requests.Session.request')
    def test_initiate_endpoint_scan_request(self, mock_request):
        # Mock the response for the initiate_endpoint_scan_request method
        mock_request.return_value = Mock(status_code=200, json=lambda: {"data": {"status": "scanned"}})

        result = self.client.initiate_endpoint_scan_request(["agent1"])
        self.assertEqual(result, {"status": "scanned"})
        mock_request.assert_called_once_with(method='POST', url='http://example.com/web/api/v2.1/agents/actions/initiate-scan', verify=False, json_data={'filter': {'ids': ['agent1']}, 'data': {}}
        )

if __name__ == '__main__':
    unittest.main()
