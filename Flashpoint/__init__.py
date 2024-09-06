import urllib.parse

import requests
from requests import HTTPError

import orenctl

QUERY = r'+type:("ip-src","ip-dst","ip-dst|port") +value.\*:"'
URL_SUFFIX_V1 = {
    'ALERTS': '/api/alerting/v1/alerts'
}
URL_SUFFIX = {
    'COMPROMISED_CREDENTIALS': '/all/search'
}


def get_url_suffix(query):
    return r'/indicators/simple?query=' + urllib.parse.quote(query.encode('utf8'))


class Flashpoint(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.api_key = orenctl.getParam("api_key")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.create_relationships = orenctl.getParam("create_relationships")
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()


def ip_lookup_command():
    client = Flashpoint()
    ip = orenctl.getArg("ip")

    query = QUERY + urllib.parse.quote(ip.encode('utf-8')) + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"ip_looked_up": resp})


def get_reports_command():
    client = Flashpoint()
    args = {"domain": orenctl.getArg("domain")}
    report_search = args.get('report_search')
    url_suffix = '/reports/?query=' + urllib.parse.quote(report_search) + '&limit=5'
    resp = client.http_request("GET", url_suffix=url_suffix)
    reports = resp.get("data", [])
    results = {
        "reports": reports
    }

    return orenctl.results(results)


def get_events_command():
    client = Flashpoint()
    args = {
        "time_period": orenctl.getArg("time_period"),
        "report_fpid": orenctl.getArg("report_fpid"),
        "limit": orenctl.getArg("limit"),
        "attack_ids": orenctl.getArg("attack_ids"),
    }
    limit = args.get('limit', 10)
    report_fpid = args.get('report_fpid')
    attack_ids = args.get('attack_ids')
    time_period = args.get('time_period')
    url_suffix = '/indicators/event?sort_timestamp=desc&'
    getvars = {}
    if limit:
        getvars['limit'] = limit

    if report_fpid:
        getvars['report'] = report_fpid

    if attack_ids:
        getvars['attack_ids'] = attack_ids

    if time_period:
        getvars['time_period'] = time_period

    url_suffix = url_suffix + urllib.parse.urlencode(getvars)

    resp = client.http_request("GET", url_suffix=url_suffix)
    results = {
        "events": resp
    }

    return orenctl.results(results)


def flashpoint_alert_list_command():
    client = Flashpoint()
    args = {
        "since": orenctl.getArg('since'),
        "until": orenctl.getArg('until'),
        "scroll_id": orenctl.getArg('scroll_id'),
        "size": orenctl.getArg('size')
    }
    response = client.http_request("GET", url_suffix=URL_SUFFIX_V1['ALERTS'], params=args)

    alerts = response.get('data', [])

    return orenctl.results({'alert_list': alerts})


def flashpoint_compromised_credentials_list_command():
    client = Flashpoint()
    args = {
        "start_date": orenctl.getArg('start_date'),
        "end_date": orenctl.getArg('end_date'),
        "filter_date": orenctl.getArg('filter_date'),
        "page_size": orenctl.getArg('page_size'),
        "page_number": orenctl.getArg('page_number'),
        "sort_date": orenctl.getArg('sort_date'),
        "sort_order": orenctl.getArg('sort_order'),
        "is_fresh": orenctl.getArg('is_fresh')
    }
    response = client.http_request("GET", url_suffix=URL_SUFFIX['COMPROMISED_CREDENTIALS'], params=args)

    return orenctl.results({"compromised_credentials_list": response})


def domain_lookup_command():
    client = Flashpoint()
    domain = orenctl.getArg('domain')
    query = r'+type:("domain") +value.\*.keyword:"' + domain + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"domain_looked_up": resp})


def filename_lookup_command():
    client = Flashpoint()
    filename = orenctl.getArg('filename')
    query = r'+type:("filename") +value.\*.keyword:"' + filename.replace('\\', '\\\\') + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"filename_looked_up": resp})


def url_lookup_command():
    client = Flashpoint()
    url = orenctl.getArg('url')
    query = r'+type:("url") +value.\*:"' + url + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"url_looked_up": resp})


def file_lookup_command():
    client = Flashpoint()
    file = orenctl.getArg('file')
    query = r'+type:("md5", "sha1", "sha256", "sha512") +value.\*.keyword:"' + file + '"'
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"file_looked_up": resp})


def email_lookup_command():
    client = Flashpoint()
    email = orenctl.getArg('email')
    query = r'+type:("email-dst", "email-src", "email-src-display-name", "email-subject", "email") +value.\*.keyword:"' \
            + email + '" '
    resp = client.http_request("GET", url_suffix=get_url_suffix(query))

    return orenctl.results({"email_looked_up": resp})


command_mapping = {
    "ip": ip_lookup_command,
    "domain": domain_lookup_command,
    "filename": filename_lookup_command,
    "url": url_lookup_command,
    "file": file_lookup_command,
    "email": email_lookup_command,
    "flashpoint_search_intelligence_reports": get_reports_command,
    "flashpoint_get_events": get_events_command,
    "flashpoint_alert_list": flashpoint_alert_list_command,
    "flashpoint_compromised_credentials_list": flashpoint_compromised_credentials_list_command,
}

command = orenctl.command()
if command in command_mapping:
    command_mapping[command]()
