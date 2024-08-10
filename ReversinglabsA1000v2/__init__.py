import os
import tempfile
from ReversingLabs.SDK.a1000 import A1000
import orenctl


class A1000V2(object):
    def __init__(self):
        self.host = orenctl.getParam("host")
        self.token = orenctl.getParam("token")
        self.user_agent = orenctl.getParam("user_agent")
        self.verify = True if orenctl.getParam("verify") else False
        self.wait_time_seconds = orenctl.getParam("wait_time_seconds")
        self.retries = orenctl.getParam("retries")
        self.proxy = orenctl.getParam("proxy")
        self.proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.a1000v2 = A1000(
            host=self.host,
            token=self.token,
            verify=self.verify,
            user_agent=self.user_agent,
            wait_time_seconds=self.wait_time_seconds,
            retries=self.retries,
            proxies=self.proxies)


def get_results():
    hash_value = orenctl.getArg("hash")
    try:
        a1000v2 = A1000V2().a1000v2
        response_json = a1000v2.get_summary_report_v2(hash_value).json()
        orenctl.results({"results": response_json})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_results: {e}"))


def upload_sample():
    file_name = orenctl.getArg("file_name")
    location = orenctl.getArg("location")
    tags = orenctl.getArg("tags")
    comment = orenctl.getArg("comment")

    try:
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, file_name)
        orenctl.download_file(location, path)
        a1000v2 = A1000V2().a1000v2
        with open(path, 'rb') as f:
            response_json = a1000v2.upload_sample_from_file(f, custom_filename=file_name, tags=tags,
                                                          comment=comment).json()
        orenctl.results({"upload_sample": response_json, "status_comment": "success"})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception upload_sample: {e}"))


def advanced_search():
    query = orenctl.getArg("query")
    ticloud = orenctl.getArg("ticloud")
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 5000

    try:
        a1000v2 = A1000V2().a1000v2
        result_list = a1000v2.advanced_search_v2_aggregated(query_string=query, ticloud=ticloud, max_results=limit)
        orenctl.results({"advanced_search_results": result_list})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception advanced_search: {e}"))


def get_url_report():
    url = orenctl.getArg("url")
    try:
        a1000v2 = A1000V2().a1000v2
        result = a1000v2.network_url_report(requested_url=url).json()
        orenctl.results({"url_report": result})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_url_report: {e}"))


def get_domain_report():
    domain = orenctl.getArg("domain")
    try:
        a1000v2 = A1000V2().a1000v2
        result = a1000v2.network_domain_report(domain=domain).json()
        orenctl.results({"domain_report": result})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_domain_report: {e}"))


def get_ip_report():
    ip_addr = orenctl.getArg("ip_address")

    try:
        a1000v2 = A1000V2().a1000v2
        result = a1000v2.network_ip_addr_report(ip_addr=ip_addr).json()
        orenctl.results({"ip_report": result})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_ip_report: {e}"))


def get_files_from_ip():
    ip_addr = orenctl.getArg("ip_address")
    extended = orenctl.getArg("extended")
    classification = orenctl.getArg("classification")
    page_size = orenctl.getArg("page_size")
    max_results = orenctl.getArg("max_results")

    try:
        a1000v2 = A1000V2().a1000v2
        result = a1000v2.network_files_from_ip_aggregated(
            ip_addr=ip_addr,
            extended_results=extended,
            classification=classification,
            page_size=page_size,
            max_results=max_results
        )
        orenctl.results({"files_from_ip": result})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_files_from_ip: {e}"))


def get_urls_from_ip():
    ip_addr = orenctl.getArg("ip_address")
    page_size = orenctl.getArg("page_size")
    max_results = orenctl.getArg("max_results")

    try:
        a1000v2 = A1000V2().a1000v2
        result = a1000v2.network_urls_from_ip_aggregated(
            ip_addr=ip_addr,
            page_size=page_size,
            max_results=max_results
        )
        orenctl.results({"files_from_ip": result})
    except Exception as e:
        orenctl.results(orenctl.error(f"Exception get_urls_from_ip: {e}"))


# Command Dispatcher
command_mapping = {
    "reversinglabs_a1000_get_results": get_results,
    "reversinglabs_a1000_upload_sample": upload_sample,
    "reversinglabs_a1000_advanced_search": advanced_search,
    "reversinglabs_a1000_url_report": get_url_report,
    "reversinglabs_a1000_domain_report": get_domain_report,
    "reversinglabs_a1000_ip_address_report": get_ip_report,
    "reversinglabs_a1000_ip_downloaded_files": get_files_from_ip,
    "reversinglabs_a1000_ip_urls": get_urls_from_ip
}

command = orenctl.command()
if command in command_mapping:
    command_mapping[command]()
