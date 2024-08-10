import unittest
from unittest.mock import patch, MagicMock
import json
from ReversingLabs.SDK.ticloud import (FileReputation, AVScanners, FileAnalysis, AdvancedSearch,
                                       URLThreatIntelligence, AnalyzeURL, DomainThreatIntelligence,
                                       IPThreatIntelligence, NetworkReputation)
from ReversingLabsTitaniumCloudv2 import (
    file_reputation_command, av_scanners_command, file_analysis_command,
    advanced_search_command, url_report_command, analyze_url_command,
    domain_report_command, domain_urls_command, domain_to_ip_command,
    ip_report_command, ip_urls_command, ip_to_domain_command,
    network_reputation_command
)


def mock_getparam_side_effect(key):
    return {
        "url": "https://api.reversinglabs.com",
        "username": "test_user",
        "password": "test_pass",
        "insecure": False,
        "user_agent": "test_agent",
        "proxy": "http://test_proxy"
    }.get(key)


def mock_getarg_side_effect(key):
    return {
        "hash": "test_hash",
        "file_name": "test_file.txt",
        "query": "test_query",
        "limit": "10",
        "url": "http://example.com",
        "domain": "example.com",
        "per_page": "10",
        "max_results": "100",
        "ip_address": "192.168.1.1",
        "network_locations": ["192.168.1.1"]
    }.get(key)


class TestReversingLabsCommands(unittest.TestCase):

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(FileReputation, 'get_file_reputation')
    def test_file_reputation_command(self, mock_get_file_reputation, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_file_reputation.return_value = mock_client
        mock_client.json.return_value = {"reputation": "good"}

        file_reputation_command()

        mock_get_file_reputation.assert_called_once_with(hash_input="test_hash")
        mock_results.assert_called_once_with({
            "file_reputation": {"reputation": "good"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AVScanners, 'get_scan_results')
    def test_av_scanners_command(self, mock_get_scan_results, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_scan_results.return_value = mock_client
        mock_client.json.return_value = {"scan_results": "clean"}

        av_scanners_command()

        mock_get_scan_results.assert_called_once_with(hash_input="test_hash")
        mock_results.assert_called_once_with({
            "av_scanners": {"scan_results": "clean"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    @patch("tempfile.mkdtemp", return_value="/mocked/tempdir")
    @patch("os.remove")
    @patch("os.rmdir")
    @patch("orenctl.upload_file", return_value="mocked_location")
    @patch.object(FileAnalysis, 'get_analysis_results')
    def test_file_analysis_command(self, mock_get_analysis_results, mock_upload_file, mock_os_rmdir, mock_os_remove,
                                   mock_mkdtemp, mock_open, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_analysis_results.return_value = mock_client
        mock_client.json.return_value = {"analysis": "detailed"}

        file_analysis_command()

        mock_results.assert_called_once_with({
            "location": "mocked_location",
            "file_name": "test_file.txt",
            "file_analysis": json.dumps({"analysis": "detailed"}, indent=4)
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AdvancedSearch, 'search_aggregated')
    def test_advanced_search_command(self, mock_search_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_search_aggregated.return_value = {"search_results": "found"}

        advanced_search_command()

        mock_search_aggregated.assert_called_once_with(query_string="test_query", max_results=10)
        mock_results.assert_called_once_with({
            "advanced_search": {"search_results": "found"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(URLThreatIntelligence, 'get_url_report')
    def test_url_report_command(self, mock_get_url_report, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_url_report.return_value = mock_client
        mock_client.json.return_value = {"url_report": "safe"}

        url_report_command()

        mock_get_url_report.assert_called_once_with(url_input="http://example.com")
        mock_results.assert_called_once_with({
            "url_report": {"url_report": "safe"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AnalyzeURL, 'submit_url')
    def test_analyze_url_command(self, mock_submit_url, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_submit_url.return_value = mock_client
        mock_client.json.return_value = {"analysis": "pending"}

        analyze_url_command()

        mock_submit_url.assert_called_once_with(url_input="http://example.com")
        mock_results.assert_called_once_with({
            "analyze_url": {"analysis": "pending"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'get_domain_report')
    def test_domain_report_command(self, mock_get_domain_report, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_domain_report.return_value = mock_client
        mock_client.json.return_value = {"domain_report": "clean"}

        domain_report_command()

        mock_get_domain_report.assert_called_once_with(domain="example.com")
        mock_results.assert_called_once_with({
            "domain_report": {"domain_report": "clean"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'urls_from_domain_aggregated')
    def test_domain_urls_command(self, mock_urls_from_domain_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_urls_from_domain_aggregated.return_value = {"urls": ["url1", "url2"]}

        domain_urls_command()

        mock_urls_from_domain_aggregated.assert_called_once_with(
            domain="example.com",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "domain_urls": {"urls": ["url1", "url2"]}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'domain_to_ip_resolutions_aggregated')
    def test_domain_to_ip_command(self, mock_domain_to_ip_resolutions_aggregated, mock_results, mock_getarg,
                                  mock_getparam):
        mock_client = MagicMock()
        mock_domain_to_ip_resolutions_aggregated.return_value = {"ips": ["192.168.1.1", "192.168.1.2"]}

        domain_to_ip_command()

        mock_domain_to_ip_resolutions_aggregated.assert_called_once_with(
            domain="example.com",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "domain_to_ip": {"ips": ["192.168.1.1", "192.168.1.2"]}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'get_ip_report')
    def test_ip_report_command(self, mock_get_ip_report, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_ip_report.return_value = mock_client
        mock_client.json.return_value = {"ip_report": "clean"}

        ip_report_command()

        mock_get_ip_report.assert_called_once_with(ip_address="192.168.1.1")
        mock_results.assert_called_once_with({
            "ip_report": {"ip_report": "clean"}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'urls_from_ip_aggregated')
    def test_ip_urls_command(self, mock_urls_from_ip_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_urls_from_ip_aggregated.return_value = {"urls": ["url1", "url2"]}

        ip_urls_command()

        mock_urls_from_ip_aggregated.assert_called_once_with(
            ip_address="192.168.1.1",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "ip_urls": {"urls": ["url1", "url2"]}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'ip_to_domain_resolutions_aggregated')
    def test_ip_to_domain_command(self, mock_ip_to_domain_resolutions_aggregated, mock_results, mock_getarg,
                                  mock_getparam):
        mock_client = MagicMock()
        mock_ip_to_domain_resolutions_aggregated.return_value = {"domains": ["example.com"]}

        ip_to_domain_command()

        mock_ip_to_domain_resolutions_aggregated.assert_called_once_with(
            ip_address="192.168.1.1",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "ip_to_domain": {"domains": ["example.com"]}
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(NetworkReputation, 'get_network_reputation')
    def test_network_reputation_command(self, mock_get_network_reputation, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_get_network_reputation.return_value = mock_client
        mock_client.json.return_value = {"network_reputation": "reputable"}

        network_reputation_command()

        mock_get_network_reputation.assert_called_once_with(network_locations=["192.168.1.1"])
        mock_results.assert_called_once_with({
            "network_reputation": {"network_reputation": "reputable"}
        })


    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(FileReputation, 'get_file_reputation')
    def test_file_reputation_command_exception(self, mock_get_file_reputation, mock_results, mock_getarg, mock_getparam):
        mock_get_file_reputation.side_effect = Exception("Error occurred")

        file_reputation_command()

        mock_get_file_reputation.assert_called_once_with(hash_input="test_hash")
        mock_results.assert_called_once_with({
            "file_reputation": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AVScanners, 'get_scan_results')
    def test_av_scanners_command_exception(self, mock_get_scan_results, mock_results, mock_getarg, mock_getparam):
        mock_get_scan_results.side_effect = Exception("Error occurred")

        av_scanners_command()

        mock_get_scan_results.assert_called_once_with(hash_input="test_hash")
        mock_results.assert_called_once_with({
            "av_scanners": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch("builtins.open", new_callable=unittest.mock.mock_open)
    @patch("tempfile.mkdtemp", return_value="/mocked/tempdir")
    @patch("os.remove")
    @patch("os.rmdir")
    @patch("orenctl.upload_file", return_value="mocked_location")
    @patch.object(FileAnalysis, 'get_analysis_results')
    def test_file_analysis_command_exception(self, mock_get_analysis_results, mock_upload_file, mock_os_rmdir, mock_os_remove,
                                             mock_mkdtemp, mock_open, mock_results, mock_getarg, mock_getparam):
        mock_get_analysis_results.side_effect = Exception("Error occurred")

        file_analysis_command()

        mock_results.assert_called_once_with({
            "location": None,
            "file_name": "test_file.txt",
            "file_analysis": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AdvancedSearch, 'search_aggregated')
    def test_advanced_search_command_exception(self, mock_search_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_search_aggregated.side_effect = Exception("Error occurred")

        advanced_search_command()

        mock_search_aggregated.assert_called_once_with(query_string="test_query", max_results=10)
        mock_results.assert_called_once_with({
            "advanced_search": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(URLThreatIntelligence, 'get_url_report')
    def test_url_report_command_exception(self, mock_get_url_report, mock_results, mock_getarg, mock_getparam):
        mock_get_url_report.side_effect = Exception("Error occurred")

        url_report_command()

        mock_get_url_report.assert_called_once_with(url_input="http://example.com")
        mock_results.assert_called_once_with({
            "url_report": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(AnalyzeURL, 'submit_url')
    def test_analyze_url_command_exception(self, mock_submit_url, mock_results, mock_getarg, mock_getparam):
        mock_submit_url.side_effect = Exception("Error occurred")

        analyze_url_command()

        mock_submit_url.assert_called_once_with(url_input="http://example.com")
        mock_results.assert_called_once_with({
            "analyze_url": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'get_domain_report')
    def test_domain_report_command_exception(self, mock_get_domain_report, mock_results, mock_getarg, mock_getparam):
        mock_get_domain_report.side_effect = Exception("Error occurred")

        domain_report_command()

        mock_get_domain_report.assert_called_once_with(domain="example.com")
        mock_results.assert_called_once_with({
            "domain_report": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'urls_from_domain_aggregated')
    def test_domain_urls_command_exception(self, mock_urls_from_domain_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_urls_from_domain_aggregated.side_effect = Exception("Error occurred")

        domain_urls_command()

        mock_urls_from_domain_aggregated.assert_called_once_with(
            domain="example.com",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "domain_urls": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(DomainThreatIntelligence, 'domain_to_ip_resolutions_aggregated')
    def test_domain_to_ip_command_exception(self, mock_domain_to_ip_resolutions_aggregated, mock_results, mock_getarg,
                                            mock_getparam):
        mock_domain_to_ip_resolutions_aggregated.side_effect = Exception("Error occurred")

        domain_to_ip_command()

        mock_domain_to_ip_resolutions_aggregated.assert_called_once_with(
            domain="example.com",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "domain_to_ip": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'get_ip_report')
    def test_ip_report_command_exception(self, mock_get_ip_report, mock_results, mock_getarg, mock_getparam):
        mock_get_ip_report.side_effect = Exception("Error occurred")

        ip_report_command()

        mock_get_ip_report.assert_called_once_with(ip_address="192.168.1.1")
        mock_results.assert_called_once_with({
            "ip_report": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'urls_from_ip_aggregated')
    def test_ip_urls_command_exception(self, mock_urls_from_ip_aggregated, mock_results, mock_getarg, mock_getparam):
        mock_urls_from_ip_aggregated.side_effect = Exception("Error occurred")

        ip_urls_command()

        mock_urls_from_ip_aggregated.assert_called_once_with(
            ip_address="192.168.1.1",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "ip_urls": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(IPThreatIntelligence, 'ip_to_domain_resolutions_aggregated')
    def test_ip_to_domain_command_exception(self, mock_ip_to_domain_resolutions_aggregated, mock_results, mock_getarg,
                                            mock_getparam):
        mock_ip_to_domain_resolutions_aggregated.side_effect = Exception("Error occurred")

        ip_to_domain_command()

        mock_ip_to_domain_resolutions_aggregated.assert_called_once_with(
            ip_address="192.168.1.1",
            results_per_page="10",
            max_results="100"
        )
        mock_results.assert_called_once_with({
            "ip_to_domain": None
        })

    @patch("orenctl.getParam", side_effect=mock_getparam_side_effect)
    @patch("orenctl.getArg", side_effect=mock_getarg_side_effect)
    @patch("orenctl.results")
    @patch.object(NetworkReputation, 'get_network_reputation')
    def test_network_reputation_command_exception(self, mock_get_network_reputation, mock_results, mock_getarg, mock_getparam):
        mock_get_network_reputation.side_effect = Exception("Error occurred")

        network_reputation_command()

        mock_results.assert_called_once_with({
            "network_reputation": None
        })


if __name__ == "__main__":
    unittest.main()
