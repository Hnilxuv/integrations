import unittest
from unittest.mock import patch, MagicMock

from aws_access_analyzer import (
    list_analyzers_command, list_analyzed_resource_command,
    list_findings_command, get_analyzed_resource_command, get_finding_command,
    start_resource_scan_command, update_findings_command
)


def mock_getparam_side_effect(key):
    return {
        "access_key": "test_access_key",
        "secret_key": "test_secret_key",
        "region": "us-west-2",
        "proxy": "http://test-proxy",
        "insecure": False,
        "retries": 5,
        "timeout": 10
    }.get(key)


def mock_getarg_side_effect(key):
    return {
        "analyzer_arn": "test_analyzer_arn",
        "max_results": "100",
        "resource_type": "s3bucket",
        "resource_arn": "arn:aws:s3:::example_bucket",
        "finding_id": "test_finding_id",
        "status": "active",
        "finding_ids": ["test_finding_id_1", "test_finding_id_2"]
    }.get(key)


class TestAWSAccessAnalyzerCommands(unittest.TestCase):

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_analyzers_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_analyzers.return_value = {"analyzers": ["analyzer1", "analyzer2"]}

        list_analyzers_command()

        mock_client.list_analyzers.assert_called_once()
        mock_results.assert_called_once_with({"analyzers": ["analyzer1", "analyzer2"]})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_analyzers_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_analyzers.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            list_analyzers_command()

        mock_client.list_analyzers.assert_called_once()
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Error listing analyzers: test exception', 'ContentsFormat': 'text'})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_analyzed_resource_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_analyzed_resources.return_value = {"analyzedResources": ["resource1", "resource2"]}

        list_analyzed_resource_command()

        mock_client.list_analyzed_resources.assert_called_once_with(analyzerArn="test_analyzer_arn", maxResults=100,
                                                                    resourceType="s3bucket")
        mock_results.assert_called_once_with({"analyzed_resources": ["resource1", "resource2"]})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_analyzed_resource_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_analyzed_resources.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            list_analyzed_resource_command()

        mock_client.list_analyzed_resources.assert_called_once_with(
            analyzerArn="test_analyzer_arn", maxResults=100, resourceType="s3bucket")
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Error listing analyzed resources: test exception', 'ContentsFormat': 'text'})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_findings_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_findings.return_value = {"findings": ["finding1", "finding2"]}

        list_findings_command()

        mock_client.list_findings.assert_called_once_with(analyzerArn="test_analyzer_arn", maxResults=100,
                                                          resourceType="s3bucket", status="active")
        mock_results.assert_called_once_with({"findings": ["finding1", "finding2"]})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_list_findings_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.list_findings.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            list_findings_command()

        mock_client.list_findings.assert_called_once_with(
            analyzerArn="test_analyzer_arn", maxResults=100, resourceType="s3bucket", status="active")
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Could not list findings: test exception', 'ContentsFormat': 'text'}
        )

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_get_analyzed_resource_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_analyzed_resource.return_value = {"resource": "resource_details"}

        get_analyzed_resource_command()

        mock_client.get_analyzed_resource.assert_called_once_with(analyzerArn="test_analyzer_arn",
                                                                  resourceArn="arn:aws:s3:::example_bucket")
        mock_results.assert_called_once_with({"analyzed_resource": "resource_details"})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_get_analyzed_resource_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_analyzed_resource.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            get_analyzed_resource_command()

        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Could not get analyzed resource: test exception', 'ContentsFormat': 'text'})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_get_finding_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_finding.return_value = {"finding": "finding_details"}

        get_finding_command()

        mock_client.get_finding.assert_called_once_with(analyzerArn="test_analyzer_arn", id="test_finding_id")
        mock_results.assert_called_once_with({"finding": "finding_details"})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_get_finding_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.get_finding.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            get_finding_command()

        mock_client.get_finding.assert_called_once_with(analyzerArn="test_analyzer_arn", id="test_finding_id")
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Could not get finding: test exception', 'ContentsFormat': 'text'})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_start_resource_scan_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.start_resource_scan.return_value = {"result": "scan_started"}

        start_resource_scan_command()

        mock_client.start_resource_scan.assert_called_once_with(
            analyzerArn="test_analyzer_arn", resourceArn="arn:aws:s3:::example_bucket")
        mock_results.assert_called_once_with(
            {"command_status": "Resource scan request sent.", "result": {"result": "scan_started"}})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_start_resource_scan_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.start_resource_scan.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            start_resource_scan_command()

        mock_client.start_resource_scan.assert_called_once_with(
            analyzerArn="test_analyzer_arn", resourceArn="arn:aws:s3:::example_bucket")
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Could not start resource scan: test exception', 'ContentsFormat': 'text'}
        )

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_update_findings_command_success(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.update_findings.return_value = {"result": "findings_updated"}

        update_findings_command()

        mock_client.update_findings.assert_called_once_with(
            analyzerArn="test_analyzer_arn", ids=["test_finding_id_1", "test_finding_id_2"], status="active")
        mock_results.assert_called_once_with(
            {"command_status": "Findings updated.", "result": {"result": "findings_updated"}})

    @patch('orenctl.getParam', side_effect=mock_getparam_side_effect)
    @patch('orenctl.getArg', side_effect=mock_getarg_side_effect)
    @patch('orenctl.results')
    @patch('boto3.client')
    def test_update_findings_command_failure(self, mock_boto_client, mock_results, mock_getarg, mock_getparam):
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client
        mock_client.update_findings.side_effect = Exception("test exception")

        with self.assertRaises(Exception):
            update_findings_command()

        mock_client.update_findings.assert_called_once_with(
            analyzerArn="test_analyzer_arn", ids=["test_finding_id_1", "test_finding_id_2"], status="active")
        mock_results.assert_called_once_with(
            {'Type': 2, 'Contents': 'Could not update findings: test exception', 'ContentsFormat': 'text'})


if __name__ == '__main__':
    unittest.main()
