import json
import logging
import os
import sys
import tempfile
from datetime import datetime

import dateparser
import requests
from requests import HTTPError

import orenctl

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
INTEGRATION_CONTEXT_NAME = 'FireEyeEX'
FE_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'
INTEGRATION_NAME = 'FireEye Email Security'
entryTypes = {
    'note': 1,
    'downloadAgent': 2,
    'file': 3,
    'error': 4,
    'pinned': 5,
    'userManagement': 6,
    'image': 7,
    'playgroundError': 8,
    'entryInfoFile': 9,
    'warning': 11,
    'map': 15,
    'debug': 16,
    'widget': 17
}
IS_PY3 = sys.version_info[0] == 3
formats = {
    'html': 'html',
    'table': 'table',
    'json': 'json',
    'text': 'text',
    'dbotResponse': 'dbotCommandResponse',
    'markdown': 'markdown'
}


def urljoin(url, suffix=""):
    if not url.endswith("/"):
        url += "/"

    if suffix.startswith("/"):
        suffix = suffix[1:]

    return url + suffix


def arg_to_boolean(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, STRING_OBJ_TYPES):
        if value.lower() in ['true', 'yes']:
            return True
        elif value.lower() in ['false', 'no']:
            return False
        else:
            raise ValueError('Argument does not contain a valid boolean-like value')
    else:
        raise ValueError('Argument is neither a string nor a boolean')


def to_fe_datetime_converter(time_given='now'):
    date_obj = dateparser.parse(time_given)
    assert date_obj is not None, f'failed parsing {time_given}'
    fe_time = date_obj.strftime(FE_DATE_FORMAT)
    fe_time += f'.{date_obj.strftime("%f")[:3]}'
    if not date_obj.tzinfo:
        given_timezone = '+00:00'
    else:
        given_timezone = f'{date_obj.strftime("%z")[:3]}:{date_obj.strftime("%z")[3:]}'
    fe_time += given_timezone
    return fe_time


def arg_get_alerts():
    alert_id = orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else ''
    start_time = orenctl.getArg('start_time') if orenctl.getArg('start_time') else ''
    if start_time:
        start_time = to_fe_datetime_converter(start_time)
    end_time = orenctl.getArg('end_time')
    if end_time:
        end_time = to_fe_datetime_converter(end_time)
    duration = orenctl.getArg('duration')
    callback_domain = orenctl.getArg('callback_domain') if orenctl.getArg('callback_domain') else ''
    dst_ip = orenctl.getArg('dst_ip') if orenctl.getArg('dst_ip') else ''
    src_ip = orenctl.getArg('src_ip') if orenctl.getArg('src_ip') else ''
    file_name = orenctl.getArg('file_name') if orenctl.getArg('file_name') else ''
    file_type = orenctl.getArg('file_type') if orenctl.getArg('file_type') else ''
    malware_name = orenctl.getArg('malware_name') if orenctl.getArg('malware_name') else ''
    malware_type = orenctl.getArg('malware_type') if orenctl.getArg('malware_type') else ''
    recipient_email = orenctl.getArg('recipient_email') if orenctl.getArg('recipient_email') else ''
    sender_email = orenctl.getArg('sender_email') if orenctl.getArg('sender_email') else ''
    url_ = orenctl.getArg('url') if orenctl.getArg('url') else ''
    return alert_id, callback_domain, dst_ip, duration, end_time, file_name, file_type, malware_name, malware_type, recipient_email, sender_email, src_ip, start_time, url_


def get_data_from_rq_param(alert_id, callback_domain, dst_ip, duration, end_time, file_name, file_type,
                           malware_name, request_param, src_ip, start_time):
    if start_time:
        request_param['start_time'] = start_time
    if end_time:
        request_param['end_time'] = end_time
    if duration:
        request_param['duration'] = duration
    if alert_id:
        request_param['alert_id'] = alert_id
    if callback_domain:
        request_param['callback_domain'] = callback_domain
    if dst_ip:
        request_param['dst_ip'] = dst_ip
    if src_ip:
        request_param['src_ip'] = src_ip
    if file_name:
        request_param['file_name'] = file_name
    if file_type:
        request_param['file_type'] = file_type
    if malware_name:
        request_param['malware_name'] = malware_name


def arg_to_list(arg, separator=',', transform=None):
    if not arg:
        return []

    result = []
    if isinstance(arg, list):
        result = arg
    elif isinstance(arg, STRING_TYPES):
        is_comma_separated = True
        if arg[0] == '[' and arg[-1] == ']':
            try:
                result = json.loads(arg)
                is_comma_separated = False
            except Exception:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result


def write_data_to_file(investigation_id, temp, data):
    file_name = f"{investigation_id}_{temp}"
    with open(file_name, 'wb') as f:
        f.write(data)


def file_result(filename, data, file_type=None):
    if file_type is None:
        file_type = entryTypes['file']
    temp = tempfile.mkdtemp()
    if isinstance(data, str):
        data = data.encode('utf-8')

    file_path = os.path.join(temp, filename)

    with open(file_path, 'wb') as f:
        f.write(data)

    if isinstance(filename, str):
        replaced_filename = filename.replace("../", "")
        if filename != replaced_filename:
            filename = replaced_filename
            logging.debug(
                "replaced {filename} with new file name {replaced_file_name}".format(
                    filename=filename, replaced_file_name=replaced_filename
                )
            )

    return {'Contents': '', 'ContentsFormat': formats['text'], 'Type': file_type, 'File': filename, 'FileID': temp}


def arg_get_reports():
    report_type = orenctl.getArg('report_type') if orenctl.getArg('report_type') else ''
    start_time = to_fe_datetime_converter(orenctl.getArg('start_time') if orenctl.getArg('start_time') else '1 week')
    end_time = to_fe_datetime_converter(orenctl.getArg('end_time') if orenctl.getArg('end_time') else 'now')
    limit = orenctl.getArg('limit') if orenctl.getArg('limit') else '100'
    interface = orenctl.getArg('interface') if orenctl.getArg('interface') else ''
    alert_id = orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else ''
    infection_id = orenctl.getArg('infection_id') if orenctl.getArg('infection_id') else ''
    infection_type = orenctl.getArg('infection_type') if orenctl.getArg('infection_type') else ''
    timeout = int(orenctl.getArg('timeout') if orenctl.getArg('timeout') else '120')
    return alert_id, end_time, infection_id, infection_type, interface, limit, report_type, start_time, timeout


def check_alert_id(alert_id, err_str, infection_id, infection_type):
    if alert_id:
        if infection_id or infection_type:
            raise ValueError(err_str)
    else:
        if not infection_id and not infection_type:
            raise ValueError(err_str)


class FireEyeEX(object):
    def __init__(self):
        self.url = urljoin(orenctl.getParam("url"), '/wsapis/v2.0.0/')
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.insecure = not arg_to_boolean(orenctl.getParam('insecure') if orenctl.getParam('insecure') else 'false')
        self.proxy = arg_to_boolean(orenctl.getParam("proxy"))
        self.max_fetch = orenctl.getParam("max_fetch") if orenctl.getParam("max_fetch") else "50"
        self.first_fetch = (orenctl.getParam("first_fetch") if orenctl.getParam("first_fetch") else "3 days").strip()
        self.info_level = orenctl.getParam("info_level") if orenctl.getParam("info_level") else "concise"
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_alerts_request(self, request_params):
        return self.http_request(method='GET', url_suffix='alerts', params=request_params, resp_type='json')

    def get_alert_details_request(self, alert_id, timeout: int):
        return self.http_request(method='GET', url_suffix=f'alerts/alert/{alert_id}', resp_type='json',
                                 timeout=timeout)

    def release_quarantined_emails_request(self, queue_ids):
        return self.http_request(method='POST',
                                 url_suffix='emailmgmt/quarantine/release',
                                 json_data={"queue_ids": queue_ids},
                                 resp_type='resp')

    def get_reports_request(self, report_type, start_time, end_time, limit, interface, alert_id, infection_type,
                            infection_id, timeout):
        params = {
            'report_type': report_type,
            'start_time': start_time,
            'end_time': end_time
        }
        if limit:
            params['limit'] = limit
        if interface:
            params['interface'] = interface
        if alert_id:
            params['id'] = alert_id
        if infection_type:
            params['infection_type'] = infection_type
        if infection_id:
            params['infection_id'] = infection_id

        return self.http_request(method='GET',
                                 url_suffix='reports/report',
                                 params=params,
                                 resp_type='content',
                                 timeout=timeout)

    def list_allowedlist_request(self, type_):
        return self.http_request(method='GET', url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}',
                                 resp_type='json')

    def update_allowedlist_request(self, type_, entry_value, matches):
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/allowed_lists/{type_}/{entry_value}',
                                 json_data={"matches": matches},
                                 resp_type='resp')

    def list_blockedlist_request(self, type_):
        return self.http_request(method='GET', url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}',
                                 resp_type='json')

    def update_blockedlist_request(self, type_, entry_value, matches):
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}/{entry_value}',
                                 json_data={"matches": matches},
                                 resp_type='resp')

    def delete_blockedlist_request(self, type_, entry_value):
        return self.http_request(method='POST',
                                 url_suffix=f'devicemgmt/emlconfig/policy/blocked_lists/{type_}/{entry_value}',
                                 params={'operation': 'delete'},
                                 resp_type='resp')


def get_alerts():
    client = FireEyeEX()

    def parse_request_params():
        alert_id, callback_domain, dst_ip, duration, end_time, file_name, file_type, malware_name, malware_type, recipient_email, sender_email, src_ip, start_time, url_ = arg_get_alerts()

        request_param = {
            'info_level': orenctl.getArg('info_level') if orenctl.getArg('info_level') else 'concise'
        }
        get_data_from_rq_param(alert_id, callback_domain, dst_ip, duration, end_time, file_name, file_type,
                               malware_name, request_param, src_ip, start_time)
        if malware_type:
            request_param['malware_type'] = malware_type
        if recipient_email:
            request_param['recipient_email'] = recipient_email
        if sender_email:
            request_param['sender_email'] = sender_email
        if url_:
            request_param['url'] = url_
        return request_param

    request_params = parse_request_params()
    limit = int(orenctl.getArg('limit') if orenctl.getArg('limit') else '20')

    raw_response = client.get_alerts_request(request_params)

    alerts = raw_response.get('alert')
    if alerts:
        alerts = alerts[:limit]

    results = dict(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Alerts',
        outputs_key_field='uuid',
        outputs=alerts,
        raw_response=raw_response
    )
    orenctl.results(results)


def get_alert_details():
    client = FireEyeEX()
    alert_ids = arg_to_list(orenctl.getArg('alert_id'))
    timeout = int(orenctl.getArg('timeout') if orenctl.getArg('timeout') else '30')

    command_results = []

    for alert_id in alert_ids:
        raw_response = client.get_alert_details_request(alert_id, timeout)

        alert_details = raw_response.get('alert')

        command_results.append(dict(
            outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Alerts',
            outputs_key_field='uuid',
            outputs=alert_details,
            raw_response=raw_response
        ))

    orenctl.results(command_results)


def release_quarantined_emails():
    client = FireEyeEX()
    queue_ids = arg_to_list(orenctl.getArg('queue_ids') if orenctl.getArg('queue_ids') else '')

    raw_response = client.release_quarantined_emails_request(queue_ids)

    if raw_response.text:
        raise ValueError(raw_response.json())
    else:
        md_ = f'{INTEGRATION_NAME} released emails successfully.'
    results = dict(
        readable_output=md_,
        raw_response=raw_response
    )
    orenctl.results(results)


def get_reports():
    client = FireEyeEX()
    alert_id, end_time, infection_id, infection_type, interface, limit, report_type, start_time, timeout = arg_get_reports()

    if report_type == 'alertDetailsReport':
        err_str = 'The alertDetailsReport can be retrieved using alert_id argument alone, ' \
                  'or by infection_type and infection_id'
        check_alert_id(alert_id, err_str, infection_id, infection_type)

    try:
        raw_response = client.get_reports_request(report_type, start_time, end_time, limit, interface,
                                                  alert_id, infection_type, infection_id, timeout)
        csv_reports = {'empsEmailAVReport', 'empsEmailHourlyStat', 'mpsCallBackServer', 'mpsInfectedHostsTrend',
                       'mpsWebAVReport'}
        prefix = 'csv' if report_type in csv_reports else 'pdf'
        results = file_result(f'report_{report_type}_{datetime.now().timestamp()}.{prefix}', data=raw_response)
        orenctl.results(results)
    except Exception as err:
        if 'WSAPI_REPORT_ALERT_NOT_FOUND' in str(err):
            results = dict(readable_output=f'Report {report_type} was not found with the given arguments.')
            orenctl.results(results)
        else:
            raise


def list_allowedlist():
    client = FireEyeEX()
    type_ = orenctl.getArg('type') if orenctl.getArg('type') else ''
    limit = int(orenctl.getArg('limit') if orenctl.getArg('limit') else '20')

    raw_response = client.list_allowedlist_request(type_)
    allowed_list = []
    if raw_response:
        allowed_list = raw_response[:limit]

    results = dict(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Allowedlists',
        outputs_key_field='name',
        outputs=allowed_list,
        raw_response=raw_response
    )
    orenctl.results(results)


def update_allowedlist():
    client = FireEyeEX()
    type_ = orenctl.getArg('type') if orenctl.getArg('type') else ''
    entry_value = orenctl.getArg('entry_value') if orenctl.getArg('entry_value') else ''
    matches = int(orenctl.getArg('matches') if orenctl.getArg('matches') else '0')

    exist = False
    current_allowed_list = client.list_allowedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise ValueError(str(f'Cannot update the entry_value {entry_value} as it does not exist in the '
                             f'Allowedlist of type {type_}.'))

    client.update_allowedlist_request(type_, entry_value, matches)

    results = dict(
        readable_output=f'Allowedlist entry {entry_value} of type {type_} was updated.'
    )
    orenctl.results(results)


def list_blockedlist():
    client = FireEyeEX()
    type_ = orenctl.getArg('type') if orenctl.getArg('type') else ''
    limit = int(orenctl.getArg('limit') if orenctl.getArg('limit') else '20')

    raw_response = client.list_blockedlist_request(type_)
    blocked_list = []
    if raw_response:
        blocked_list = raw_response[:limit]

    results = dict(
        outputs_prefix=f'{INTEGRATION_CONTEXT_NAME}.Blockedlists',
        outputs_key_field='name',
        outputs=blocked_list,
        raw_response=raw_response
    )
    orenctl.results(results)


def update_blockedlist():
    client = FireEyeEX()
    type_ = orenctl.getArg('type') if orenctl.getArg('type') else ''
    entry_value = orenctl.getArg('entry_value') if orenctl.getArg('entry_value') else ''
    matches = int(orenctl.getArg('matches') if orenctl.getArg('matches') else '0')

    exist = False
    current_allowed_list = client.list_blockedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise ValueError(str(f'Cannot update the entry_value {entry_value} as it does not exist in the '
                             f'Blockedlist of type {type_}.'))

    client.update_blockedlist_request(type_, entry_value, matches)

    results = dict(
        readable_output=f'Blockedlist entry {entry_value} of type {type_} was updated.'
    )
    orenctl.results(results)


def delete_blockedlist():
    client = FireEyeEX()
    type_ = orenctl.getArg('type') if orenctl.getArg('type') else ''
    entry_value = orenctl.getArg('entry_value') if orenctl.getArg('entry_value') else ''

    exist = False
    current_allowed_list = client.list_blockedlist_request(type_)
    for entry in current_allowed_list:
        if entry_value == entry.get('name'):
            exist = True
    if not exist:
        raise ValueError(str(f'Cannot delete the entry_value {entry_value} as it does not exist in the '
                             f'Blockedlist of type {type_}.'))

    client.delete_blockedlist_request(type_, entry_value)

    results = dict(
        readable_output=f'Blockedlist entry {entry_value} of type {type_} was deleted.'
    )
    orenctl.results(results)


if orenctl.command() == "fireeye_ex_get_alerts":
    get_alerts()
elif orenctl.command() == "fireeye_ex_get_alert_details":
    get_alert_details()
elif orenctl.command() == "fireeye_ex_release_quarantined_emails":
    release_quarantined_emails()
elif orenctl.command() == "fireeye_ex_get_reports":
    get_reports()
elif orenctl.command() == "fireeye_ex_list_allowedlist":
    list_allowedlist()
elif orenctl.command() == "fireeye_ex_update_allowedlist":
    update_allowedlist()
elif orenctl.command() == "fireeye_ex_list_blockedlist":
    list_blockedlist()
elif orenctl.command() == "fireeye_ex_update_blockedlist":
    update_blockedlist()
elif orenctl.command() == "fireeye_ex_delete_blockedlist":
    delete_blockedlist()
