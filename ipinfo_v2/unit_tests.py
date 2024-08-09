import json
import os
import unittest

import requests
import requests_mock
import orenctl
from ipinfo_v2 import IPInfoV2, ipinfo_command


class TestIPInfo(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mock_data_file = os.path.join(os.path.dirname(__file__), "test_data", "test_data.json")
        with open(mock_data_file, 'r') as f:
            cls.mock_data = json.load(f)

        orenctl.set_params({
            "url": "https://ipinfo.io",
            "api_key": "test",
            "insecure": False,
            "proxy": None
        })
        cls.mocker = requests_mock.Mocker()
        cls.mocker.start()

    @classmethod
    def tearDownClass(cls):
        cls.mocker.stop()

    def setUp(self):
        self.mock_ipinfo = IPInfoV2()

    def test_ipinfo_ip_success(self):
        ip_address = "1.1.1.1"
        orenctl.set_input_args({
            "ip_address": ip_address,
        })
        expected_result = self.mock_data
        self.mocker.get(f"{self.mock_ipinfo.url}/{ip_address}/json",
                        json=expected_result)
        ipinfo_command()
        result = orenctl.get_results().get("results")[0].get("Contents")
        if isinstance(result, str):
            result = json.loads(result)
        self.assertEqual(result.get("ip_info"), expected_result)

    def test_ipinfo_ip_no_ip_address(self):
        orenctl.set_input_args({
            "ip_address": None,
        })
        ipinfo_command()
        result = orenctl.get_results().get("results")[0].get("Contents")
        self.assertIn("IP address is required", result)

    def test_ipinfo_ip_http_error(self):
        ip_address = "1.1.1.1"
        orenctl.set_input_args({
            "ip_address": ip_address,
        })
        self.mocker.get(f"{self.mock_ipinfo.url}/{ip_address}/json",
                        status_code=404,
                        json={"error": "Not Found"})
        with self.assertRaises(Exception):
            ipinfo_command()

class TestIPInfoV2HttpRequest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        orenctl.set_params({
            "url": "https://ipinfo.io",
            "api_key": "test",
            "insecure": False,
            "proxy": None
        })
        cls.mocker = requests_mock.Mocker()
        cls.mocker.start()

    @classmethod
    def tearDownClass(cls):
        cls.mocker.stop()

    def setUp(self):
        self.ipinfo = IPInfoV2()

    def test_http_request_success(self):
        url_suffix = "/1.1.1.1/json"
        mock_response = {"ip": "1.1.1.1", "city": "Test City"}
        self.mocker.get(f"{self.ipinfo.url}{url_suffix}",
                        json=mock_response,
                        status_code=200)
        result = self.ipinfo.http_request("GET", url_suffix, params={"token": "test"})
        self.assertEqual(result, mock_response)

    def test_http_request_http_error(self):
        url_suffix = "/1.1.1.1/json"
        self.mocker.get(f"{self.ipinfo.url}{url_suffix}",
                        status_code=404,
                        json={"error": "Not Found"})
        with self.assertRaises(Exception):
            self.ipinfo.http_request("GET", url_suffix, params={"token": "test"})

    def test_http_request_invalid_url(self):
        url_suffix = "/invalid/url"
        self.mocker.get(f"{self.ipinfo.url}{url_suffix}",
                        status_code=400,
                        json={"error": "Bad Request"})
        with self.assertRaises(Exception):
            self.ipinfo.http_request("GET", url_suffix, params={"token": "test"})

    def test_http_request_invalid_method(self):
        url_suffix = "/1.1.1.1/json"
        self.mocker.post(f"{self.ipinfo.url}{url_suffix}",
                         status_code=405,
                         json={"error": "Method Not Allowed"})
        with self.assertRaises(Exception):
            self.ipinfo.http_request("POST", url_suffix, params={"token": "test"})

    def test_http_request_timeout(self):
        url_suffix = "/1.1.1.1/json"
        self.mocker.get(f"{self.ipinfo.url}{url_suffix}",
                        exc=requests.exceptions.RequestException("Request Timeout"))
        with self.assertRaises(Exception):
            self.ipinfo.http_request("GET", url_suffix, params={"token": "test"})

if __name__ == "__main__":
    unittest.main()
