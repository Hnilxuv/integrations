import boto3
from botocore.config import Config
import urllib3
import orenctl

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
SERVICE_NAME = "accessanalyzer"


class AwsAccessanAlyzer(object):
    def __init__(self):
        self.access_key = orenctl.getParam("access_key")
        self.secret_key = orenctl.getParam("secret_key")
        self.region = orenctl.getParam("region")
        self.proxy = orenctl.getParam("proxy")
        self.verify = True if orenctl.getParam("insecure") else False
        self.retries = orenctl.getParam("retries") or 5
        self.timeout = orenctl.getParam("timeout")
        self.proxy_dict = {}
        if self.proxy:
            self.proxy_dict = {
                "http": self.proxy,
                "https": self.proxy
            }
        if int(self.retries) > 10:
            self.retries = 10
        self.client = self.create_client()

    def create_client(self):
        try:
            boto_config = Config(retries=dict(
                max_attempts=int(self.retries)
            ))
            if self.proxy_dict:
                boto_config.merge(Config(proxies=self.proxy_dict))

            if self.timeout:
                boto_config.merge(Config(connect_timeout=int(self.timeout)))

            client = boto3.client(service_name=SERVICE_NAME,
                                  region_name=self.region,
                                  aws_access_key_id=self.access_key,
                                  aws_secret_access_key=self.secret_key,
                                  verify=self.verify,
                                  config=boto_config)
            return client
        except Exception as e:
            orenctl.results(orenctl.error("Could not create boto3 client: {0}".format(e)))
            raise


def list_analyzers_command():
    client = AwsAccessanAlyzer().client
    try:
        response = client.list_analyzers()
        analyzers = response.get("analyzers")
        orenctl.results({
            "analyzers": analyzers
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Error listing analyzers: {0}".format(e)))
        raise 


def list_analyzed_resource_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    kwargs = {
        'analyzerArn': analyzer_arn,
    }
    if orenctl.getArg('max_results'):
        kwargs['maxResults'] = int(orenctl.getArg('max_results'))
    if orenctl.getArg('resource_type'):
        kwargs['resourceType'] = orenctl.getArg('resource_type')
    try:
        response = client.list_analyzed_resources(**kwargs)
        orenctl.results({
            "analyzed_resources": response.get("analyzedResources")
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Error listing analyzed resources: {0}".format(e)))
        raise


def list_findings_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    kwargs = {
        'analyzerArn': analyzer_arn,
    }
    if orenctl.getArg('max_results'):
        kwargs['maxResults'] = int(orenctl.getArg('max_results'))
    if orenctl.getArg('resource_type'):
        kwargs['resourceType'] = orenctl.getArg('resource_type')
    if orenctl.getArg('status'):
        kwargs['status'] = orenctl.getArg('status')
    try:
        response = client.list_findings(**kwargs)
        orenctl.results({
            "findings": response.get("findings")
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Could not list findings: {0}".format(e)))
        raise


def get_analyzed_resource_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    resource_arn = orenctl.getArg('resource_arn')
    kwargs = {
        'analyzerArn': analyzer_arn,
        'resourceArn': resource_arn,
    }
    try:
        response = client.get_analyzed_resource(**kwargs)
        orenctl.results({
            "analyzed_resource": response.get("resource")
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Could not get analyzed resource: {0}".format(e)))
        raise


def get_finding_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    finding_id = orenctl.getArg('finding_id')
    kwargs = {
        'analyzerArn': analyzer_arn,
        'id': finding_id,
    }
    try:
        response = client.get_finding(**kwargs)
        orenctl.results({
            "finding": response.get("finding")
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Could not get finding: {0}".format(e)))
        raise


def start_resource_scan_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    resource_arn = orenctl.getArg('resource_arn')
    kwargs = {
        'analyzerArn': analyzer_arn,
        'resourceArn': resource_arn,
    }
    try:
        response = client.start_resource_scan(**kwargs)
        orenctl.results({
            "command_status": "Resource scan request sent.",
            "result": response
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Could not start resource scan: {0}".format(e)))
        raise


def update_findings_command():
    client = AwsAccessanAlyzer().client
    analyzer_arn = orenctl.getArg('analyzer_arn')
    status = orenctl.getArg('status')
    finding_ids = orenctl.getArg('finding_ids')
    kwargs = {
        'analyzerArn': analyzer_arn,
        'ids': finding_ids,
        'status': status,
    }
    try:
        response = client.update_findings(**kwargs)
        orenctl.results({
            "command_status": "Findings updated.",
            "result": response
        })
        return
    except Exception as e:
        orenctl.results(orenctl.error("Could not update findings: {0}".format(e)))
        raise


if orenctl.command() == "aws_list_findings":
    list_findings_command()
if orenctl.command() == "aws_list_analyzers":
    list_analyzers_command()
if orenctl.command() == "aws_list_analyzed_resource":
    list_analyzed_resource_command()
if orenctl.command() == "aws_get_analyzed_resource":
    get_analyzed_resource_command()
if orenctl.command() == "aws_get_finding":
    get_finding_command()
if orenctl.command() == "aws_start_resource_scan":
    start_resource_scan_command()
if orenctl.command() == "aws_update_findings":
    update_findings_command()
