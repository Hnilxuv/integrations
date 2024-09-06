import copy
import json
import urllib.parse
from datetime import datetime, timezone

import requests
from requests import HTTPError

import orenctl


def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    if values_to_ignore is None:
        values_to_ignore = (None, '', [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }


def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=False):
    dt = datetime.fromtimestamp(int(timestamp) / 1000.0)
    if is_utc or date_format.endswith('Z'):
        dt = dt.astimezone(timezone.utc)
    return dt.strftime(date_format)


def normalize_api_response(raw_response):
    return raw_response.get('data', raw_response) if type(raw_response) is dict else raw_response


def are_filters_match_response_content(all_filter_arguments, api_response):
    for arguments in all_filter_arguments:
        command_args, resp_key = arguments
        for arg in command_args:
            if arg == api_response.get(resp_key):
                return True
    return False


class TaniumThreatResponseV2(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.api_key = orenctl.getParam("api_key")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.api_token = orenctl.getParam("api_token")
        self.proxy = self.password if "_token" in self.username else None
        self.api_version = orenctl.getParam("api_version") if orenctl.getParam("api_version") else "3.x"
        self.insecure = True if orenctl.getParam("insecure") else False
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def update_session(self):
        if self.api_token:
            res = self.http_request('GET', 'api/v2/session/current', headers={'session': self.api_token},
                                    ok_codes=(200,))
            if res.get('data'):
                self.session = self.api_token
        elif self.username and self.password:
            body = {
                'username': self.username,
                'password': self.password
            }

            res = self.http_request('POST', '/api/v2/session/login', json_data=body, ok_codes=(200,))

            self.session = res.get('data').get('session')
        else:
            return orenctl.results(orenctl.error('Please provide either an API Token or Username & Password.'))
        return self.session

    def do_request(self, method, url_suffix, data=None, params=None, resp_type='json', headers=None, body=None):
        if headers is None:
            headers = {}
        if not self.session:
            self.update_session()
        headers['session'] = self.session

        res = self.make_http_request(method, url_suffix, headers, data, body, params)

        if res.status_code == 401:
            return self.handle_unauthorized(res)

        if res.status_code == 403:
            self.update_session()
            res = self.make_http_request(method, url_suffix, headers, data, body, params, ok_codes=(200, 400, 404))
            return res

        if res.status_code in (400, 404):
            self.handle_error(res)

        return self.process_response(res, resp_type)

    def make_http_request(self, method, url_suffix, headers, data, body, params,
                          ok_codes=(200, 201, 202, 204, 400, 401, 403, 404)):
        return self.http_request(method, url_suffix, headers=headers, json_data=data, data=body,
                                 params=params, resp_type='response', ok_codes=ok_codes)

    def handle_unauthorized(self, res):
        err_msg = 'Unauthorized Error: please verify that the given API token is valid and that the IP of the client is listed in the api_token_trusted_ip_address_list global setting.\n' if self.api_token else ''
        try:
            err_msg += str(res.json())
        except ValueError:
            err_msg += str(res)
        return orenctl.results(orenctl.error(err_msg))

    def handle_error(self, res):
        if res.content:
            raise requests.HTTPError(str(res.content))
        if res.reason:
            raise requests.HTTPError(str(res.reason))
        raise requests.HTTPError(res.json().get('text'))

    def process_response(self, res, resp_type):
        if resp_type == 'json':
            try:
                return res.json()
            except json.JSONDecodeError:
                return res.content
        elif resp_type == 'text':
            return res.text, res.headers.get('Content-Disposition')
        elif resp_type == 'content':
            return res.content, res.headers.get('Content-Disposition')
        return res

    def get_threat_response_endpoint(self):
        return "threat-response" if self.api_version == "4.x" else "detect3"


def get_alerts():
    client = TaniumThreatResponseV2()
    data_args = {
        "limit": orenctl.getArg("limit"),
        "offset": orenctl.getArg("offset"),
        "computer_ip_address": orenctl.getArg("computer_ip_address"),
        "computer_name": orenctl.getArg("computer_name"),
        "scan_config_id": orenctl.getArg("scan_config_id"),
        "intel_doc_id": orenctl.getArg("intel_doc_id"),
        "severity": orenctl.getArg("severity"),
        "priority": orenctl.getArg("priority"),
        "type": orenctl.getArg("type"),
        "state": orenctl.getArg("state")
    }

    params = assign_params(type=data_args.get("type"),
                           priority=data_args.get("priority"),
                           severity=data_args.get("severity"),
                           intelDocId=data_args.get("intel_doc_id"),
                           scanConfigId=data_args.get("scan_config_id"),
                           computerName=data_args.get("computer_name"),
                           computerIpAddress=data_args.get("computer_ip_address"),
                           limit=data_args.get("limit"),
                           offset=data_args.get("offset"),
                           state=data_args.get("state").lower() if data_args.get("state") else None)

    raw_response = client.do_request('GET', '/plugin/products/'
                                            f'{client.get_threat_response_endpoint()}'
                                            f'/api/v1/alerts/', params=params)

    return orenctl.results({"alerts": raw_response})


def get_alert():
    client = TaniumThreatResponseV2()

    alert_id = orenctl.getArg('alert_id')
    raw_response = client.do_request('GET', '/plugin/products/'
                                            f'{client.get_threat_response_endpoint()}'
                                            f'/api/v1/alerts/{alert_id}')
    raw_response_data = raw_response.get("data", raw_response)

    return orenctl.results({"alert": raw_response_data})


def alert_update_state():
    client = TaniumThreatResponseV2()
    alert_ids = orenctl.getArg('alert_ids')
    state = orenctl.getArg('state')

    body = {
        'state': state.lower()
    }
    if client.api_version == "4.x":
        if len(alert_ids) == 1:
            client.do_request('PUT', f'/plugin/products/threat-response/api/v1/alerts/{alert_ids[0]}', data=body)
        else:
            client.do_request('PUT', '/plugin/products/threat-response/api/v1/alerts/',
                              data=body, params={'id': alert_ids})

    else:
        body.update({'id': alert_ids})
        client.do_request('PUT', '/plugin/products/detect3/api/v1/alerts/', data=body)

    return orenctl.results({"alert_updated_state": f'Alert state updated to {state}.'})


def create_snapshot():
    client = TaniumThreatResponseV2()
    connection_id = orenctl.getArg('connection_id')
    raw_response = client.do_request('POST', f'/plugin/products/threat-response/api/v1/conns/{connection_id}/snapshot')

    return orenctl.results({"created_snapshot": raw_response})


def get_process_info():
    client = TaniumThreatResponseV2()
    connection_id = orenctl.getArg('connection_id')
    ptid = orenctl.getArg('ptid')
    raw_response = client.do_request(
        'GET',
        f'/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}',
        params={'context': 'node'})

    return orenctl.results({"process_info": raw_response})


def get_events_by_process():
    client = TaniumThreatResponseV2()
    limit = orenctl.getArg('limit')
    offset = orenctl.getArg('offset')
    cid = orenctl.getArg('connection_id')
    ptid = orenctl.getArg('ptid')
    event_type = orenctl.getArg('type').lower()
    params = {'limit': limit, 'offset': offset}
    if client.api_version == "4.x":
        params.update({"cid": cid, "ptid": ptid, "type": event_type})

    raw_response = client.do_request('GET',
                                     f'plugin/products/threat-response/api/v1/conns/{cid}/processevents/{ptid}/{event_type}',
                                     params={'limit': limit, 'offset': offset})

    return orenctl.results({"events_by_process": raw_response})


def get_process_children():
    client = TaniumThreatResponseV2()
    limit = orenctl.getArg('limit')
    offset = orenctl.getArg('offset')
    connection_id = orenctl.getArg('connection_id')
    ptid = orenctl.getArg('ptid')
    raw_response = client.do_request(
        'GET',
        f'/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}',
        params={'context': 'children', 'limit': limit, 'offset': offset})

    return orenctl.results({"process_children": raw_response})


def get_parent_process():
    client = TaniumThreatResponseV2()
    connection_id = orenctl.getArg('connection_id')
    ptid = orenctl.getArg('ptid')
    raw_response = client.do_request(
        'GET',
        f'/plugin/products/threat-response/api/v1/conns/{connection_id}/processtrees/{ptid}',
        params={'context': 'parent'})

    return orenctl.results({"parent_process": raw_response})


def get_process_tree():
    client = TaniumThreatResponseV2()
    limit = orenctl.getArg('limit')
    offset = orenctl.getArg('offset')
    cid = orenctl.getArg('connection_id')
    ptid = orenctl.getArg('ptid')
    context = orenctl.getArg('context')
    params = assign_params(context=context, limit=limit, offset=offset)
    raw_response = client.do_request('GET', f'plugin/products/threat-response/api/v1/conns/{cid}/processtrees/{ptid}',
                                     params=params)

    return orenctl.results({"process_tree": raw_response})


def list_files_in_dir():
    client = TaniumThreatResponseV2()
    connection_id = orenctl.getArg('connection_id')
    dir_path_name = orenctl.getArg('path')
    dir_path = urllib.parse.quote(dir_path_name, safe='')
    limit = int(orenctl.getArg('limit'))
    offset = int(orenctl.getArg('offset'))

    raw_response = client.do_request(
        'GET',
        f'/plugin/products/threat-response/api/v1/conns/{connection_id}/file/list/{dir_path}'
    )

    files = raw_response.get('entries', [])
    from_idx = min(offset, len(files))
    to_idx = min(offset + limit, len(files))
    files = files[from_idx:to_idx]

    for file in files:
        file['connectionId'] = connection_id
        file['path'] = dir_path_name
        if created := file.get('createdDate'):
            file['createdDate'] = timestamp_to_datestring(created)
        if created := file.get('modifiedDate'):
            file['modifiedDate'] = timestamp_to_datestring(created)

    return raw_response


def get_file_info():
    client = TaniumThreatResponseV2()
    cid = orenctl.getArg('connection_id')
    path_name = orenctl.getArg('path')
    path = urllib.parse.quote(path_name, safe='')

    raw_response = client.do_request('GET', f'/plugin/products/threat-response/api/v1/conns/{cid}/file/info/{path}')

    context = copy.deepcopy(raw_response)
    info = context.get('info')
    context['connectionId'] = cid
    try:
        if created := info.get('createdDate'):
            info['createdDate'] = timestamp_to_datestring(created)
        if modified := info.get('modifiedDate'):
            info['modifiedDate'] = timestamp_to_datestring(modified)
    except ValueError:
        pass
    context.update(info)
    if info:
        del context['info']

    return orenctl.results({"file_info": raw_response})


def delete_file_from_endpoint():
    client = TaniumThreatResponseV2()
    cid = orenctl.getArg('connection_id')
    full_path = orenctl.getArg('path')
    path = urllib.parse.quote(full_path)
    client.do_request('DELETE', f'/plugin/products/threat-response/api/v1/conns/{cid}/file/delete/{path}')
    return orenctl.results({
        "deleted_file_from_endpoint": f'Delete request of file {full_path} from endpoint {cid} has been sent successfully.'})


def start_quick_scan():
    client = TaniumThreatResponseV2()
    computer_group_name = orenctl.getArg('computer_group_name')
    raw_response = client.do_request('GET', f"/api/v2/groups/by-name/{computer_group_name}")
    raw_response_data = normalize_api_response(raw_response)
    if not raw_response_data:
        msg = f'No group exists with name {computer_group_name} or' \
              f' your account does not have sufficient permissions to access the groups'
        raise ValueError(msg)

    data = {
        'intelDocId': int(orenctl.getArg('intel_doc_id')),
        'computerGroupId': int(raw_response_data.get('id'))
    }
    if client.api_version == "4.x":
        url_suffix = '/plugin/products/threat-response/api/v1/on-demand-scans/'
    else:
        url_suffix = '/plugin/products/detect3/api/v1/quick-scans/'
    raw_response = client.do_request('POST', url_suffix, data=data)

    return raw_response


def get_task_by_id():
    client = TaniumThreatResponseV2()
    task_id = orenctl.getArg('task_id')
    raw_response = client.do_request('GET', f'/plugin/products/threat-response/api/v1/tasks/{task_id}')

    data = raw_response.get('data')
    context = copy.deepcopy(raw_response)
    context.update(data)
    if data:
        del context['data']
    return orenctl.results({"task_by_id": data})


def get_system_status():
    client = TaniumThreatResponseV2()
    limit = orenctl.getArg('limit') if orenctl.getArg('limit') else 50
    offset = orenctl.getArg('offset') if orenctl.getArg('offset') else 0
    statuses = orenctl.getArg('status')
    hostnames = orenctl.getArg('hostname')
    ipaddrs_client = orenctl.getArg('ip_client')
    ipaddrs_server = orenctl.getArg('ip_server')
    port = orenctl.getArg('port')

    is_resp_filtering_required = statuses or hostnames or ipaddrs_client or ipaddrs_client or ipaddrs_server or port
    filter_arguments = [
        (statuses, 'status'),
        (hostnames, 'host_name'),
        (ipaddrs_client, 'ipaddress_client'),
        (ipaddrs_server, 'ipaddress_server'),
        ([port], 'port_number')
    ]

    raw_response = client.do_request('GET', '/api/v2/system_status')
    data = raw_response.get('data', [{}])
    active_computers = []
    assert offset is not None
    from_idx = min(offset, len(data))
    to_idx = min(offset + limit, len(data))

    for item in data[from_idx:to_idx]:
        if client_id := item.get('computer_id'):
            item['client_id'] = client_id
            if is_resp_filtering_required:
                if are_filters_match_response_content(all_filter_arguments=filter_arguments, api_response=item):
                    active_computers.append(item)
            else:
                active_computers.append(item)

    return orenctl.results({"system_status": data})


if orenctl.command() == "tanium_tr_list_alerts":
    get_alerts()
elif orenctl.command() == "tanium_tr_get_alert_by_id":
    get_alert()
elif orenctl.command() == "tanium_tr_alert_update_state":
    alert_update_state()
elif orenctl.command() == "tanium_tr_create_snapshot":
    create_snapshot()
elif orenctl.command() == "tanium_tr_get_process_info":
    get_process_info()
elif orenctl.command() == "tanium_tr_get_events_by_process":
    get_events_by_process()
elif orenctl.command() == "tanium_tr_get_process_children":
    get_process_children()
elif orenctl.command() == "tanium_tr_get_parent_process":
    get_parent_process()
elif orenctl.command() == "tanium_tr_get_process_tree":
    get_process_tree()
elif orenctl.command() == "tanium_tr_list_files_in_directory":
    list_files_in_dir()
elif orenctl.command() == "tanium_tr_get_file_info":
    get_file_info()
elif orenctl.command() == "tanium_tr_delete_file_from_endpoint":
    delete_file_from_endpoint()
elif orenctl.command() == "tanium_tr_start_quick_scan":
    start_quick_scan()
elif orenctl.command() == "tanium_tr_get_task_by_id":
    get_task_by_id()
elif orenctl.command() == "tanium_tr_get_system_status":
    get_system_status()
