import json
import re
import time
import urllib.parse
from datetime import timedelta, datetime

import requests
import xmltodict
from requests import HTTPError

import orenctl

entryTypes = {'note': 1, 'error': 2, 'pending': 3}
formats = {'html': 'html', 'table': 'table', 'json': 'json', 'text': 'text', 'markdown': 'markdown'}
DAY_IN_MILLIS = 86400000


def parse_xml(http_response_body):
    body = re.sub(r'&#x.*?;', '', http_response_body)

    parsed = xmltodict.parse(body)

    return parsed


def encode_to_url_query(params):
    return urllib.parse.urlencode(params)


def parse_bool(val):
    return val.lower() == 'true'


def parse_array(comma_sep_list):
    return comma_sep_list.split(',')


def generate_search_session_id():
    sess_id = int(time.time() * 1000)
    return sess_id


def xml_object_to_json(xml_object):
    context = []
    if xml_object and 'fields' in xml_object and 'results' in xml_object:
        keys = []
        fields = xml_object['fields']
        entries = xml_object['results']
        is_date_field = []

        for field in fields:
            if 'name' in field:
                keys.append(field['name'].replace(' ', '').lstrip('_'))
                is_date_field.append(field.get('type') == 'date')

        entry_object_xml_to_json(context, entries, is_date_field, keys)

    return context


def entry_object_xml_to_json(context, entries, is_date_field, keys):
    for entry in entries:
        if isinstance(entry, dict) and len(entry) == len(keys):
            new_entry = {}
            for i, key in enumerate(keys):
                value = entry.get(key, '')
                if is_date_field[i] and isinstance(value, str) and value.isdigit():
                    timestamp = int(value) / 1000
                    seconds = int(timestamp)
                    milliseconds = int((timestamp - seconds) * 1000)
                    date_entry = f"{seconds}.{milliseconds:03d}Z"
                    value = date_entry
                new_entry[key] = value
            context.append(new_entry)



def get_chart_request(user_session_id, search_session_id):
    body_args = {
        'search_session_id': int(search_session_id),
        'user_session_id': user_session_id,
        'offset': 0,
        'length': 100
    }

    res_body = ArcSightLogger().http_request('POST', '/server/search/chart_data', None, body_args)
    events = xml_object_to_json(res_body)
    return events


def get_events_request(user_session_id, search_session_id, offset=None, dir=None, length=None, fields=None):
    body_args = {
        'search_session_id': int(search_session_id),
        'user_session_id': user_session_id
    }

    if offset is not None:
        try:
            body_args['offset'] = int(offset)
        except ValueError:
            raise ValueError('Offset must be a valid integer')

    if dir is not None:
        if dir not in ['asc', 'desc']:
            raise ValueError('Dir must be "asc" or "desc"')
        body_args['dir'] = dir

    if length is not None:
        if not str(length).isdigit():
            raise ValueError('Length must be a number')
        body_args['length'] = int(length)

    if fields is not None:
        if not isinstance(fields, str):
            raise TypeError('Fields must be a comma-separated string')
        body_args['fields'] = fields.split(",")

    res_body = ArcSightLogger().http_request('POST', '/server/search/events', None, body_args)
    events = xml_object_to_json(res_body)

    return events



def create_entry(data, mapping):
    entry = {
        'Type': 'note',
        'Contents': data,
        'ContentsFormat': 'json',
        'ReadableContentsFormat': 'text',
        'HumanReadable': mapping.get('title', 'Search Status'),
        'EntryContext': {}
    }

    if 'data' in mapping:
        context = {}
        for mapping_entry in mapping['data']:
            to_field = mapping_entry['to']
            from_field = mapping_entry['from']
            if from_field in data:
                context[to_field] = data[from_field]
        entry['EntryContext'][mapping['contextPath']] = context

    return entry


class ArcSightLogger(object):
    def __init__(self):
        self.url = orenctl.getParam('url')
        self.insecure = True if orenctl.getParam("insecure") else False
        self.username = orenctl.getParam('username')
        self.password = orenctl.getParam('password')
        self.port = orenctl.getParam('port')
        self.proxy = orenctl.getParam('proxy')
        self.session = requests.session()

        if self.url is None:
            raise ValueError("The 'url' parameter is missing or is None.")

        if self.url[-1] == '/':
            self.url = self.url[:-1]

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def login(self, username, password):
        SERVER_URL = self.url + ':' + self.port + '/'

        full_url = f"{SERVER_URL}core-service/rest/LoginService/login"

        body_obj = {
            'login': username,
            'password': password
        }

        body_string = encode_to_url_query(body_obj)[1:]

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(full_url, data=body_string, headers=headers, verify=not self.insecure,
                                 proxies=self.proxy if self.proxy else {})

        if response.status_code != 200:
            error_message = f'Login failed. StatusCode: {response.status_code}'
            if response.text:
                error_message += f'. Error: {response.text}'
            raise ValueError(error_message)

        res_body = parse_xml(response.text)
        if 'loginResponse' not in res_body or 'return' not in res_body['loginResponse']:
            raise ValueError('Login to ArcSight Logger has failed - Session id is missing from response')

        user_session_id = res_body['loginResponse']['return']

        return user_session_id

    def logout(self, user_session_id):
        if not user_session_id:
            raise ValueError('Unable to perform logout from ArcSight Logger. Session id is missing')

        full_url = self.url + 'core-service/rest/LoginService/logout'
        body_obj = {
            'authToken': user_session_id
        }
        body_string = encode_to_url_query(body_obj)[1:]

        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        response = requests.post(full_url, data=body_string, headers=headers, verify=not self.insecure,
                                 proxies=self.proxy)

        if response.status_code not in [200, 204]:
            error_message = f'Logout failed. StatusCode: {response.status_code}'
            if response.text:
                error_message += f'. Error: {response.text}'
            raise ValueError(error_message)

    def start_search_session_request(self, args):
        search_session_id = generate_search_session_id()

        body_args = {
            'search_session_id': search_session_id,
            'user_session_id': args.get('user_session_id')
        }

        if 'query' in args:
            body_args['query'] = args.get('query')

        if 'timeout' in args:
            body_args['timeout'] = int(args.get('timeout'))

        if 'last_days' in args:
            if not str(args.get('last_days')).isdigit():
                raise ValueError('LastDays must be a number')
            ld = int(args.get('last_days'))
            now = time.gmtime()
            end_time = time.strftime('%Y-%m-%dT%H:%M:%SZ', now)
            body_args['end_time'] = end_time
            start_time = time.gmtime(time.mktime(now) - ld * 86400)
            body_args['start_time'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', start_time)

        elif 'start_time' in args and 'end_time' in args:
            body_args['end_time'] = args.get('end_time')
            body_args['start_time'] = args.get('start_time')

        if 'discover_fields' in args:
            body_args['discover_fields'] = parse_bool(args.get('discover_fields'))

        if 'summary_fields' in args:
            body_args['summary_fields'] = parse_array(args.get('summary_fields'))

        if 'field_summary' in args:
            body_args['field_summary'] = parse_bool(args.get('field_summary'))

        if 'local_search' in args:
            body_args['local_search'] = parse_bool(args.get('local_search'))

        return search_session_id

    def get_search_status_request(self, user_session_id, search_session_id):

        body_args = {
            'search_session_id': int(search_session_id),
            'user_session_id': user_session_id
        }

        res_body = ArcSightLogger().http_request("POST", 'server/search/status', None, body_args)
        return res_body

    def close_session_request(self, user_session_id, search_session_id):
        body_args = {
            'search_session_id': int(search_session_id),
            'user_session_id': user_session_id
        }
        ArcSightLogger().http_request('POST', 'server/search/close', None, body_args)

    def get_search_events_request(self, args):
        search_session_id = self.start_search_session_request(args)

        required_events = float('inf')
        length = args.get("length")
        offset = args.get("offset")
        user_session_id = args.get("user_session_id")
        dir = args.get("dir")
        fields = args.get("fields")

        if length:
            required_events = int(length) + (int(offset) if offset else 0)

        status_result = {}
        while status_result.get('status') != 'complete' and required_events > status_result.get('hit', 0):
            time.sleep(1)
            status_result = self.get_search_status_request(user_session_id, search_session_id)
            if status_result.get('status') == 'error':
                raise ValueError(f'Invalid query.\nSearch status: {json.dumps(status_result, indent=2)}')

        # Get the results
        if status_result.get('result_type') == 'chart':
            events = get_chart_request(user_session_id, search_session_id)
        else:
            events = get_events_request(user_session_id, search_session_id, offset, dir, length, fields)

        self.close_session_request(user_session_id, search_session_id)

        self.logout(user_session_id)
        return events

    def drilldown_request(self, args):
        user_session_id = args.get('session_id')
        last_days = args.get('last_days')
        start_time = args.get('start_time')
        end_time = args.get('end_time')
        search_session_id = args.get('search_session_id')

        body_args = {
            'search_session_id': int(search_session_id),
            'user_session_id': user_session_id
        }

        if last_days is not None:
            if not str(last_days).isdigit():
                raise ValueError('LastDays must be a number')
            ld = int(last_days)
            now = datetime.fromtimestamp(time.time())
            body_args['end_time'] = now.isoformat() + 'Z'
            now -= timedelta(days=ld)
            body_args['start_time'] = now.isoformat() + 'Z'
        elif start_time and end_time:
            body_args['end_time'] = end_time
            body_args['start_time'] = start_time
        else:
            raise ValueError('Make sure lastDays is provided, or both startTime and endTime are provided')

        res_body = self.http_request('POST', 'server/search/drilldown', None, body_args)
        return res_body

    def stop_search_request(self, user_session_id, search_session_id):
        body_args = {
            'search_session_id': int(search_session_id),
            'user_session_id': user_session_id
        }

        response = self.http_request('POST', 'server/search/stop', body_args)

        if response.status_code != 200:
            raise ValueError(f"Failed to stop search. StatusCode: {response.status_code}, Error: {response.text}")


def get_search_events():
    client = ArcSightLogger()
    user_session_id = client.login(client.username, client.password)
    args = {
        "user_session_id": user_session_id,
        "query": orenctl.getArg('query'),
        "timeout": orenctl.getArg('timeout'),
        "startTime": orenctl.getArg('startTime'),
        "endTime": orenctl.getArg('endTime'),
        "discover_fields": orenctl.getArg('discover_fields'),
        "summary_fields": orenctl.getArg('summary_fields'),
        "field_summary": orenctl.getArg('field_summary'),
        "local_search": orenctl.getArg('local_search'),
        "lastDays": orenctl.getArg('lastDays'),
        "offset": orenctl.getArg('offset'),
        "dir": orenctl.getArg('dir'),
        "length": orenctl.getArg('length'),
        "fields": orenctl.getArg('fields')
    }
    events = client.get_search_events_request(args)

    entry = {
        'Type': entryTypes['note'],
        'Contents': events,
        'ContentsFormat': formats['json'],
        'ReadableContentsFormat': formats['markdown'],
        'EntryContext': {
            'ArcSightLogger.Events(val.rowId === obj.rowId)': events
        }
    }

    orenctl.results(entry)


def start_search_session():
    client = ArcSightLogger()
    user_session_id = client.login(client.username, client.password)
    args = {
        "user_session_id": user_session_id,
        "query": orenctl.getArg('query'),
        "timeout": orenctl.getArg('timeout'),
        "startTime": orenctl.getArg('startTime'),
        "endTime": orenctl.getArg('endTime'),
        "discover_fields": orenctl.getArg('discover_fields'),
        "summary_fields": orenctl.getArg('summary_fields'),
        "field_summary": orenctl.getArg('field_summary'),
        "local_search": orenctl.getArg('local_search'),
        "lastDays": orenctl.getArg('lastDays')
    }

    search_session_id = client.start_search_session_request(args)

    entry = {
        'Type': 'note',
        'Contents': {
            'searchSessionId': search_session_id,
            'sessionId': user_session_id
        },
        'ContentsFormat': 'json',
        'ReadableContentsFormat': 'markdown'
    }

    context = {
        'SearchSessionId': search_session_id,
        'SessionId': user_session_id
    }

    entry['EntryContext'] = {}
    entry['EntryContext']['ArcSightLogger.Search'] = context

    orenctl.results(entry)


def drill_down():
    client = ArcSightLogger()
    user_session_id = client.login(client.username, client.password)
    args = {
        "user_session_id": user_session_id,
        "search_session_id": orenctl.getArg('search_session_id'),
        "session_id": orenctl.getArg('session_id'),
        "startTime": orenctl.getArg('startTime'),
        "endTime": orenctl.getArg('endTime'),
        "lastDays": orenctl.getArg('lastDays')
    }
    result = client.drilldown_request(args)

    entry = {
        'Type': 'note',
        'Contents': result,
        'ContentsFormat': 'json',
        'ReadableContentsFormat': 'text',
        'HumanReadable': 'Success drilldown request'
    }

    orenctl.results(entry)


def get_search_status():
    client = ArcSightLogger()
    args = {
        "session_id": orenctl.getArg('session_id'),
        "search_session_id": orenctl.getArg('search_session_id')
    }
    search_status = client.get_search_status_request(args.get("search_session_id"), args.get("session_id"))

    context_key = 'ArcSightLogger.Status(val.SearchSessionId === obj.SearchSessionId)'

    entry = create_entry(search_status, {
        'data': [
            {'to': 'Status', 'from': 'status'},
            {'to': 'ResultType', 'from': 'result_type'},
            {'to': 'Hit', 'from': 'hit'},
            {'to': 'Scanned', 'from': 'scanned'},
            {'to': 'Elapsed', 'from': 'elapsed'},
            {'to': 'Message', 'from': 'message'}
        ],
        'title': 'ArcSight Logger - Search Status',
        'contextPath': context_key
    })

    entry['EntryContext'][context_key]['SearchSessionId'] = args['search_session_id']

    orenctl.results(entry)


def get_events():
    client = ArcSightLogger()

    session_id = orenctl.getArg('session_id')
    search_session_id = orenctl.getArg('search_session_id')
    offset = orenctl.getArg('offset')
    dir = orenctl.getArg('dir')
    length = orenctl.getArg('length')
    fields = orenctl.getArg('fields')

    status_result = client.get_search_status_request(session_id, search_session_id)

    if status_result.get('result_type') == 'chart':
        events = get_chart_request(session_id, search_session_id)
    else:
        events = get_events_request(
            session_id,
            search_session_id,
            offset,
            dir,
            length,
            fields
        )

    entry = {
        'Type': 'note',
        'Contents': events,
        'ContentsFormat': 'json',
        'ReadableContentsFormat': 'markdown',
        'EntryContext': {
            'ArcSightLogger.Events(val.rowId === obj.rowId)': events
        }
    }

    orenctl.results(entry)


def stop_search():
    client = ArcSightLogger()
    client.stop_search_request(orenctl.getArg("session_id"), orenctl.getArg("search_session_id"))

    results = {
        'Type': 'note',
        'ContentsFormat': 'text',
        'Contents': 'Search stopped successfully'
    }
    orenctl.results(results)


def close_session():
    client = ArcSightLogger()
    client.close_session_request(orenctl.getArg("session_id"), orenctl.getArg("search_session_id"))

    results = {
        'Type': 'note',
        'ContentsFormat': 'text',
        'Contents': 'Session closed successfully'
    }
    orenctl.results(results)


if orenctl.command() == "as_search_events":
    get_search_events()
elif orenctl.command() == "as_search":
    start_search_session()
elif orenctl.command() == "as_drilldown":
    drill_down()
elif orenctl.command() == "as_status":
    get_search_status()
elif orenctl.command() == "as_events":
    get_events()
elif orenctl.command() == "as_stop":
    stop_search()
elif orenctl.command() == "as_close":
    close_session()
