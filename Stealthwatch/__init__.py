import logging
from datetime import datetime, timezone

import dateparser
import requests
from requests import HTTPError

import orenctl

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
OUTPUT_PREFIX = 'CiscoStealthwatch.FlowStatus'
ERROR = 'Must provide start_time, time_range, or start_time and end_time'


def utcfromtimestamp(timestamp):
    return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def times_handler(start_time=None, end_time=None, time_range=None):
    start_time_obj = dateparser.parse(time_range) if time_range else dateparser.parse(start_time)
    end_time_obj = dateparser.parse(end_time) if end_time else datetime.now(timezone.utc)

    if start_time_obj is None:
        orenctl.results(orenctl.error("Invalid start time or time range"))

    if start_time_obj.tzinfo is None:
        start_time_obj = start_time_obj.replace(tzinfo=timezone.utc)
    else:
        start_time_obj = start_time_obj.astimezone(timezone.utc)

    if end_time_obj.tzinfo is None:
        end_time_obj = end_time_obj.replace(tzinfo=timezone.utc)
    else:
        end_time_obj = end_time_obj.astimezone(timezone.utc)

    return start_time_obj.strftime(DATE_FORMAT), end_time_obj.strftime(DATE_FORMAT)


def remove_empty_elements(d):
    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


def dict_safe_get(dict_object, keys, default_return_value=None, return_type=None, raise_return_type=True):
    return_value = dict_object
    for key in keys:
        try:
            return_value = return_value[key]
        except (KeyError, TypeError, IndexError, AttributeError):
            return_value = default_return_value
            break

    if return_type and not isinstance(return_value, return_type):
        if raise_return_type:
            orenctl.results(orenctl.error("Safe get Error:\nDetails: Return Type Error Excepted return type {0},"
                                          " but actual type from nested dict/list is {1} with value {2}.\n"
                                          "Query: {3}\nQueried object: {4}".format(return_type, type(return_value),
                                                                                   return_value, keys, dict_object)))
        return_value = default_return_value

    return return_value


class Stealthwatch(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def initialize_flow_search(self, tenant_id, data):
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries'
        return self.prepare_request(method='POST', url_suffix=url, json_data=data)

    def prepare_request(self, url_suffix, method='GET', data=None, json_data=None,
                        resp_type='json'):
        if data is None:
            data = {}
        if json_data is None:
            json_data = {}
        cookies = self.get_cookies()
        headers = {}
        if token := cookies.get('XSRF-TOKEN'):
            logging.debug('Received XSRF-TOKEN cookie from Cisco Secure Network, creating an X-XSRF-TOKEN header.')
            headers.update({'X-XSRF-TOKEN': token})
        return self.http_request(method=method, url_suffix=url_suffix, json_data=json_data, data=data, cookies=cookies,
                                 headers=headers, resp_type=resp_type)

    def get_cookies(self):
        data = {
            'username': self.username,
            'password': self.password
        }

        response = self.http_request(method='POST',
                                     url_suffix='/token/v2/authenticate',
                                     data=data,
                                     resp_type='response')
        return response.cookies

    def get_flow_search_results(self, tenant_id, search_id):
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{search_id}/results'
        return self.prepare_request(method='GET', url_suffix=url)

    def check_flow_search_progress(self, tenant_id: str, search_id: str):
        url = f'/sw-reporting/v2/tenants/{tenant_id}/flows/queries/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_tag(self, tenant_id: str, tag_id: str):
        url = f'/smc-configuration/rest/v1/tenants/{tenant_id}/tags/{tag_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def tag_hourly_traffic(self, tenant_id: str, tag_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/internalHosts/tags/{tag_id}/traffic/hourly'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_top_alarms(self, tenant_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/internalHosts/alarms/topHosts'
        return self.prepare_request(method='GET', url_suffix=url)

    def initialize_security_events_search(self, tenant_id: str, data) -> dict:
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/queries'
        return self.prepare_request(method='POST', url_suffix=url, json_data=data)

    def check_security_events_search_progress(self, tenant_id: str, search_id: str):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/queries/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)

    def get_security_events_search_results(self, tenant_id, search_id):
        url = f'/sw-reporting/v1/tenants/{tenant_id}/security-events/results/{search_id}'
        return self.prepare_request(method='GET', url_suffix=url)


def cisco_stealthwatch_query_flows_initialize_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    start_time = orenctl.getArg("start_time")
    end_time = orenctl.getArg("end_time")
    time_range = orenctl.getArg("time_range")
    limit = orenctl.getArg("limit")
    ip_addresses = orenctl.getArg("ip_addresses")

    if not (start_time or end_time or time_range):
        orenctl.results(orenctl.error(ERROR))
    if not (time_range or start_time) and end_time:
        orenctl.results(orenctl.error(ERROR))

    start_time, end_time = times_handler(start_time, end_time, time_range)
    if not start_time:
        orenctl.results(orenctl.error('Invalid time format. Check: start_time, time_range, and end_time'))

    data = remove_empty_elements({
        "startDateTime": start_time,
        "endDateTime": end_time,
        "recordLimit": limit,
        "subject": {
            "ipAddresses": {
                "includes": ip_addresses if isinstance(ip_addresses, list) else [ip_addresses]
            }
        }
    })
    response = client.initialize_flow_search(tenant_id, data)
    outputs = dict_safe_get(response, ['data', 'query'])

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_query_flows_status_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    search_id = orenctl.getArg("search_id")
    response = client.check_flow_search_progress(tenant_id, search_id)
    outputs = dict_safe_get(response, ['data', 'query'])
    outputs['id'] = search_id

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_query_flows_results_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    search_id = orenctl.getArg("search_id")
    response = client.get_flow_search_results(tenant_id, search_id)
    outputs = []
    for data in dict_safe_get(response, ['data', 'flows']):
        outputs.append(data)
    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_get_tag_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    tag_id = orenctl.getArg("tag_id")

    response = client.get_tag(tenant_id, tag_id)
    outputs = response.get('data', {})

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_get_tag_hourly_traffic_report_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    tag_id = orenctl.getArg("tag_id")
    response = client.tag_hourly_traffic(tenant_id, tag_id)
    outputs = []
    if response.get('data'):
        for report in response['data'].get('data', []):
            report['tag_id'] = tag_id
            report['tenant_id'] = tenant_id
            value = report.get('value')
            report.pop('value')
            report.update(value)
            outputs.append(report)

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_get_top_alarming_tags_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    response = client.get_top_alarms(tenant_id)

    outputs = []
    for alarm in dict_safe_get(response, ['data', 'data'], []):
        alarm['tenant_id'] = tenant_id
        outputs.append(alarm)

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_list_security_events_initialize_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    end_time = orenctl.getArg("end_time")
    time_range = orenctl.getArg("time_range")
    start_time = orenctl.getArg("start_time")
    if not (start_time or end_time or time_range):
        orenctl.results(orenctl.error(ERROR))
    if not (time_range or start_time) and end_time:
        orenctl.results(orenctl.error(ERROR))

    start_time, end_time = times_handler(start_time, end_time, time_range)
    if not start_time:
        orenctl.results(orenctl.error('Invalid time format. Check: start_time, time_range, and end_time'))
    data = {
        "timeRange": {
            "from": start_time,
            "to": end_time
        }
    }
    response = client.initialize_security_events_search(tenant_id, data)
    outputs = dict_safe_get(response, ['data', 'searchJob'])

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_list_security_events_status_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    search_id = orenctl.getArg("search_id")
    response = client.check_security_events_search_progress(tenant_id, search_id)
    outputs = response.get('data', {})
    outputs['id'] = search_id

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


def cisco_stealthwatch_list_security_events_results_command():
    client = Stealthwatch()
    tenant_id = orenctl.getArg("tenant_id")
    search_id = orenctl.getArg("search_id")
    limit = orenctl.getArg("limit")
    response = client.get_security_events_search_results(tenant_id, search_id)

    outputs = []
    if response.get('data'):
        for security_event in dict_safe_get(response, ['data', 'results'], []):
            outputs.append(security_event)

    outputs = outputs[:int(limit)]

    results = {
        "outputs_prefix": OUTPUT_PREFIX,
        "outputs_key_field": 'id',
        "raw_response": response,
        "outputs": outputs
    }
    orenctl.results(results)


if orenctl.command() == "cisco_stealthwatch_query_flows_initialize":
    cisco_stealthwatch_query_flows_initialize_command()
elif orenctl.command() == "cisco_stealthwatch_query_flows_status":
    cisco_stealthwatch_query_flows_status_command()
elif orenctl.command() == "cisco_stealthwatch_query_flows_results":
    cisco_stealthwatch_query_flows_results_command()
elif orenctl.command() == "cisco_stealthwatch_get_tag":
    cisco_stealthwatch_get_tag_command()
elif orenctl.command() == "cisco_stealthwatch_get_tag_hourly_traffic_report_command":
    cisco_stealthwatch_get_tag_hourly_traffic_report_command()
elif orenctl.command() == "cisco_stealthwatch_get_top_alarming_tags":
    cisco_stealthwatch_get_top_alarming_tags_command()
elif orenctl.command() == "cisco_stealthwatch_list_security_events_initialize":
    cisco_stealthwatch_list_security_events_initialize_command()
elif orenctl.command() == "cisco_stealthwatch_list_security_events_status":
    cisco_stealthwatch_list_security_events_status_command()
elif orenctl.command() == "cisco_stealthwatch_list_security_events_results":
    cisco_stealthwatch_list_security_events_results_command()
