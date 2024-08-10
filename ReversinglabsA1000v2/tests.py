import unittest
from unittest.mock import patch, MagicMock, mock_open

from ReversingLabs.SDK.a1000 import A1000

import orenctl

from ReversinglabsA1000v2 import get_results, upload_sample, advanced_search, get_url_report, get_domain_report, \
    get_ip_report, get_files_from_ip, get_urls_from_ip, A1000V2

orenctl.download_file = MagicMock()


def mock_getParam_side_effect(key):
    return {
        "host": "http://test-host",
        "token": "test-token",
        "verify": True,
        "user_agent": "test-agent",
        "wait_time_seconds": 10,
        "retries": 3,
        "proxy": "http://test-proxy"
    }.get(key)


def mock_getArg_side_effect(key):
    return {
        "hash": "5d41402abc4b2a76b9719d911017c592",  # Example MD5 hash
        "file_name": "test_file.exe",
        "location": "http://example.com/test_file.exe",
        "tags": "test_tag",
        "comment": "test_comment",
        "query": "test_query",
        "ticloud": "test_ticloud",
        "limit": "5000",
        "url": "http://example.com",
        "domain": "example.com",
        "ip_address": "192.168.1.1",
        "extended": "true",
        "classification": "test_classification",
        "page_size": "100",
        "max_results": "200"
    }.get(key)


class TestReversingLabsA1000Commands(unittest.TestCase):

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_results_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "summary": "test_summary",
            "details": {
                "file_type": "exe",
                "file_size": "123456",
                "status": "processed"
            }
        }
        mock_A1000_instance.get_summary_report_v2.return_value = mock_response

        get_results()

        mock_A1000V2_instance.a1000v2.get_summary_report_v2.assert_called_once_with("5d41402abc4b2a76b9719d911017c592")
        mock_results.assert_called_once_with({
            "results": {
                "summary": "test_summary",
                "details": {
                    "file_type": "exe",
                    "file_size": "123456",
                    "status": "processed"
                }
            }
        })

    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')  # Replace with your module path
    @patch('builtins.open', new_callable=mock_open, read_data=b'sample_data')
    @patch('tempfile.mkdtemp', return_value='/mocked/tempdir')
    @patch('os.remove')  # Mock os.remove
    def test_upload_sample_success(self, mock_os_remove, mock_tempdir, mock_open, mock_A1000V2,
                                   mock_results, mock_getArg):
        # Mock the A1000V2 instance and its method
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance

        # Mock the response for the upload_sample_from_file method
        mock_response = MagicMock()
        mock_response.json.return_value = {"sample_id": 1234}
        mock_A1000_instance.upload_sample_from_file.return_value = mock_response

        # Execute the function
        upload_sample()

        # Assertions
        mock_getArg.assert_any_call("file_name")
        mock_getArg.assert_any_call("location")
        mock_getArg.assert_any_call("tags")
        mock_getArg.assert_any_call("comment")

        mock_A1000_instance.upload_sample_from_file.assert_called_once_with(
            mock_open(), custom_filename="test_file.exe", tags="test_tag", comment="test_comment"
        )
        mock_results.assert_called_once_with({
            "upload_sample": {"sample_id": 1234},
            "status_comment": "success"
        })

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_advanced_search_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_result_list = {"result": "test_result"}
        mock_A1000_instance.advanced_search_v2_aggregated.return_value = mock_result_list

        advanced_search()

        mock_A1000V2_instance.a1000v2.advanced_search_v2_aggregated.assert_called_once_with(
            query_string="test_query", ticloud="test_ticloud", max_results=5000
        )
        mock_results.assert_called_once_with({"advanced_search_results": mock_result_list})

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_url_report_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_response = MagicMock()
        mock_response.json.return_value = {"url_report": "test_url_report"}
        mock_A1000_instance.network_url_report.return_value = mock_response

        get_url_report()

        mock_A1000V2_instance.a1000v2.network_url_report.assert_called_once_with(requested_url="http://example.com")
        mock_results.assert_called_once_with({'url_report': {'url_report': 'test_url_report'}})

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_domain_report_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_response = MagicMock()
        mock_response.json.return_value = {"domain_report": "test_domain_report"}
        mock_A1000_instance.network_domain_report.return_value = mock_response

        get_domain_report()

        mock_A1000V2_instance.a1000v2.network_domain_report.assert_called_once_with(domain="example.com")
        mock_results.assert_called_once_with({'domain_report': {'domain_report': 'test_domain_report'}})

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_ip_report_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_response = MagicMock()
        mock_response.json.return_value = {"ip_report": "test_ip_report"}
        mock_A1000_instance.network_ip_addr_report.return_value = mock_response

        get_ip_report()

        mock_A1000V2_instance.a1000v2.network_ip_addr_report.assert_called_once_with(ip_addr="192.168.1.1")
        mock_results.assert_called_once_with({'ip_report': {'ip_report': 'test_ip_report'}})

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_files_from_ip_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_result = {"files_from_ip": "test_files_from_ip"}
        mock_A1000_instance.network_files_from_ip_aggregated.return_value = mock_result

        get_files_from_ip()

        mock_A1000V2_instance.a1000v2.network_files_from_ip_aggregated.assert_called_once_with(
            ip_addr="192.168.1.1",
            extended_results="true",
            classification="test_classification",
            page_size="100",
            max_results="200"
        )
        mock_results.assert_called_once_with({'files_from_ip': {'files_from_ip': 'test_files_from_ip'}})

    @patch('orenctl.getParam', side_effect=mock_getParam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getArg_side_effect)
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_urls_from_ip_success(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_result = {"urls_from_ip": "test_urls_from_ip"}
        mock_A1000_instance.network_urls_from_ip_aggregated.return_value = mock_result

        get_urls_from_ip()

        mock_A1000V2_instance.a1000v2.network_urls_from_ip_aggregated.assert_called_once_with(
            ip_addr="192.168.1.1",
            page_size="100",
            max_results="200"
        )
        mock_results.assert_called_once_with({'files_from_ip': {'urls_from_ip': 'test_urls_from_ip'}})


    @patch('orenctl.getParam')
    def test_init_success(self, mock_getParam):
        # Setup mocks to return expected values
        mock_getParam.side_effect = {
            "host": "http://mocked-host",
            "token": "mocked-token",
            "user_agent": "mocked-user-agent",
            "verify": "True",
            "wait_time_seconds": 10,
            "retries": 3,
            "proxy": "http://mocked-proxy"
        }.get

        # Initialize A1000V2
        a1000v2_instance = A1000V2()

        # Check if the A1000 instance is created with the correct parameters
        self.assertIsInstance(a1000v2_instance.a1000v2, A1000)
        self.assertEqual(a1000v2_instance.host, "http://mocked-host")
        self.assertEqual(a1000v2_instance.token, "mocked-token")
        self.assertEqual(a1000v2_instance.user_agent, "mocked-user-agent")
        self.assertTrue(a1000v2_instance.verify)
        self.assertEqual(a1000v2_instance.wait_time_seconds, 10)
        self.assertEqual(a1000v2_instance.retries, 3)
        self.assertEqual(a1000v2_instance.proxies, {"http": "http://mocked-proxy", "https": "http://mocked-proxy"})

    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_results_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.return_value = "5d41402abc4b2a76b9719d911017c592"  # Example MD5 hash

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.get_summary_report_v2.side_effect = Exception("API Error")

        get_results()

        mock_results.assert_called_once_with(orenctl.error("Exception get_results: API Error"))

    # Test exception in upload_sample function
    @patch('orenctl.getArg')
    @patch('orenctl.download_file')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    @patch('builtins.open', new_callable=mock_open, read_data=b'sample_data')
    @patch('tempfile.mkdtemp', return_value='/mocked/tempdir')
    @patch('os.remove')
    def test_upload_sample_exception(self, mock_os_remove, mock_tempdir, mock_open, mock_A1000V2, mock_results,
                                     mock_download_file, mock_getArg):
        mock_getArg.side_effect = mock_getArg_side_effect

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.upload_sample_from_file.side_effect = Exception("Upload Error")

        upload_sample()

        mock_results.assert_called_once_with(orenctl.error("Exception upload_sample: Upload Error"))

    # Test exception in advanced_search function
    @patch('orenctl.getParam')
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_advanced_search_exception(self, mock_A1000V2, mock_results, mock_getArg, mock_getParam):
        mock_getArg.side_effect = mock_getArg_side_effect

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.advanced_search_v2_aggregated.side_effect = Exception("Search Error")

        advanced_search()

        mock_results.assert_called_once_with(orenctl.error("Exception advanced_search: Search Error"))

    # Test exception in get_url_report function
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_url_report_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.return_value = "http://example.com"

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.network_url_report.side_effect = Exception("URL Report Error")

        get_url_report()

        mock_results.assert_called_once_with(orenctl.error("Exception get_url_report: URL Report Error"))

    # Test exception in get_domain_report function
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_domain_report_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.return_value = "example.com"

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.network_domain_report.side_effect = Exception("Domain Report Error")

        get_domain_report()

        mock_results.assert_called_once_with(orenctl.error("Exception get_domain_report: Domain Report Error"))

    # Test exception in get_ip_report function
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_ip_report_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.return_value = "192.168.1.1"

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.network_ip_addr_report.side_effect = Exception("IP Report Error")

        get_ip_report()

        mock_results.assert_called_once_with(orenctl.error("Exception get_ip_report: IP Report Error"))

    # Test exception in get_files_from_ip function
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_files_from_ip_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.side_effect = mock_getArg_side_effect

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.network_files_from_ip_aggregated.side_effect = Exception("Files From IP Error")

        get_files_from_ip()

        mock_results.assert_called_once_with(orenctl.error("Exception get_files_from_ip: Files From IP Error"))

    # Test exception in get_urls_from_ip function
    @patch('orenctl.getArg')
    @patch('orenctl.results')
    @patch('ReversinglabsA1000v2.A1000V2')
    def test_get_urls_from_ip_exception(self, mock_A1000V2, mock_results, mock_getArg):
        mock_getArg.side_effect = mock_getArg_side_effect

        # Mock the A1000V2 instance and its method to raise an exception
        mock_A1000_instance = MagicMock()
        mock_A1000V2_instance = mock_A1000V2.return_value
        mock_A1000V2_instance.a1000v2 = mock_A1000_instance
        mock_A1000_instance.network_urls_from_ip_aggregated.side_effect = Exception("URLs From IP Error")

        get_urls_from_ip()

        mock_results.assert_called_once_with(orenctl.error("Exception get_urls_from_ip: URLs From IP Error"))


if __name__ == '__main__':
    unittest.main()
