import base64
import json
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha1

import dateparser
import requests
from requests import HTTPError

import orenctl

DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
emailRegex = r'''(?i)(?:[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_\x60{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''


def date_to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%S'):
    if isinstance(date_str_or_dt, STRING_OBJ_TYPES):
        return int(time.mktime(time.strptime(date_str_or_dt, date_format)) * 1000)

    return int(time.mktime(date_str_or_dt.timetuple()) * 1000)


from datetime import datetime, timedelta, timezone


def parse_date_range(date_range, date_format=None, to_timestamp=False, timezone_offset=0, utc=True):
    range_split = date_range.strip().split(' ')

    if len(range_split) != 2:
        raise ValueError(
            'date_range must be "number date_range_unit", examples: (2 hours, 4 minutes, 6 months, 1 day, etc.)')

    try:
        number = int(range_split[0])
    except ValueError:
        raise ValueError('The time value is invalid. Must be an integer.')

    unit = range_split[1].lower()
    if unit not in ['minute', 'minutes', 'hour', 'hours', 'day', 'days', 'month', 'months', 'year', 'years']:
        raise ValueError('The unit of date_range is invalid. Must be minutes, hours, days, months, or years.')

    if not isinstance(timezone_offset, (int, float)):
        raise ValueError(
            'Invalid timezone_offset "{}" - must be a number (of type int or float).'.format(timezone_offset))

    if utc:
        now = datetime.now(timezone.utc)
    else:
        now = datetime.now()

    end_time = now
    start_time = now

    if 'minute' in unit:
        start_time = end_time - timedelta(minutes=number)
    elif 'hour' in unit:
        start_time = end_time - timedelta(hours=number)
    elif 'day' in unit:
        start_time = end_time - timedelta(days=number)
    elif 'month' in unit:
        start_time = end_time - timedelta(days=number * 30)
    elif 'year' in unit:
        start_time = end_time - timedelta(days=number * 365)

    if timezone_offset:
        start_time += timedelta(hours=timezone_offset)
        end_time += timedelta(hours=timezone_offset)

    if to_timestamp:
        return start_time.timestamp(), end_time.timestamp()

    if date_format:
        return start_time.strftime(date_format), end_time.strftime(date_format)

    return start_time, end_time


def format_time_range(range_arg):
    if range_arg:
        dt_from, dt_to = parse_date_range(
            date_range=range_arg,
            date_format=DATE_FORMAT
        )
        return f"{dt_from},{dt_to}"
    else:
        return None


def remove_empty_elements(d):
    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


def arg_to_int(arg, arg_name, default=None):
    if arg is None:
        return default
    if isinstance(arg, str):
        if arg.isdigit():
            return int(arg)
        raise ValueError(f'Invalid number: "{arg_name}"="{arg}"')
    if isinstance(arg, int):
        return arg
    raise ValueError(f'Invalid number: "{arg_name}"')


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


def parse_key_value_arg(arg_str):
    if arg_str:
        tags = []
        for item in arg_str.split(','):
            parts = item.split(':', 1)
            if len(parts) != 2:
                raise ValueError(f"Got invalid key/value pair {item}.")
            key, value = parts
            if not key or not value:
                raise ValueError(f"Got invalid key/value pair {item}.")
            tags.append({key.strip(): value.strip()})
        return tags
    else:
        return None


def arg_to_datetime(arg, arg_name=None, is_utc=True, required=False, settings=None):
    if arg is None:
        handle_missing_arg(arg_name, required)
        return None

    if is_numeric(arg):
        return handle_numeric_arg(arg, is_utc)

    if isinstance(arg, str):
        return handle_string_arg(arg, settings, arg_name)

    check_value_error(arg, arg_name)


def handle_missing_arg(arg_name, required):
    if required:
        if arg_name:
            raise ValueError(f'Missing "{arg_name}"')
        else:
            raise ValueError('Missing required argument')


def is_numeric(arg):
    return isinstance(arg, (int, float)) or (isinstance(arg, str) and arg.isdigit())


def handle_numeric_arg(arg, is_utc):
    ms = float(arg)
    if ms > 2000000000.0:
        ms /= 1000.0

    seconds = int(ms)
    microseconds = int((ms - seconds) * 1_000_000)

    days = seconds // 86400
    remaining_seconds = seconds % 86400
    hours = remaining_seconds // 3600
    remaining_seconds %= 3600
    minutes = remaining_seconds // 60
    seconds = remaining_seconds % 60

    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    dt = epoch + timedelta(days=days, hours=hours, minutes=minutes, seconds=seconds, microseconds=microseconds)

    if not is_utc:
        dt = dt.astimezone()

    return dt


def handle_string_arg(arg, settings, arg_name):
    date = dateparser.parse(arg, settings=settings if settings else {'TIMEZONE': 'UTC'})
    if date is None:
        check_value_error(arg, arg_name)
    return date


def check_value_error(arg, arg_name):
    if arg_name:
        raise ValueError(f'Invalid value for "{arg_name}": {arg}')
    else:
        raise ValueError(f'Invalid argument value: {arg}')


class QueryHandler:
    def __init__(self, args):
        self.content_types = []
        self.type = orenctl.getParam('type')
        self.ancestor_folder_ids = orenctl.getParam('ancestor_folder_ids')
        self.item_name = orenctl.getParam('item_name')
        self.item_description = orenctl.getParam('item_description')
        self.comments = orenctl.getParam('comments')
        self.tag = orenctl.getParam('tag')
        self.created_range = format_time_range(orenctl.getParam('created_range'))
        self.file_extensions = orenctl.getParam('file_extensions')
        self.limit = orenctl.getParam('limit')
        self.offset = orenctl.getParam('offset')
        self.owner_user_ids = orenctl.getParam('owner_uids')
        self.trash_content = orenctl.getParam('trash_content')
        self.updated_at_range = format_time_range(orenctl.getParam('updated_at_range'))
        self.query = orenctl.getParam('query')
        self.args = args

        if self.item_name:
            self.content_types.append('name')
            self.query = self.item_name
            self.item_name = None
        if self.item_description:
            self.content_types.append('description')
            self.query = self.item_description
            self.item_description = None
        if self.tag:
            self.content_types.append('tag')
            self.query = self.tag
            self.tag = None
        if self.comments:
            self.content_types.append('comments')
            self.query = self.comments
            self.comments = None

    def prepare_params_object(self):
        query_params_dict = vars(QueryHandler(self.args))
        query_params_dict.pop('args')
        return remove_empty_elements(query_params_dict)


class BoxV2(object):
    def __init__(self):
        self.insecure = True if orenctl.getParam("insecure") else False
        self.first_fetch = orenctl.getParam("first_fetch") if orenctl.getParam("first_fetch") else "1 day"
        self.proxy = orenctl.getParam("proxy") if orenctl.getParam("proxy") else False
        self.url = orenctl.getParam("url") if orenctl.getParam("url") else "https://api.box.com"
        self.session = requests.session()
        self.default_as_user = orenctl.getParam('default_user')
        self.search_user_id = orenctl.getParam('search_user_id') if orenctl.getParam("search_user_id") else False
        self.session.headers = {}

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def list_users(self, fields=None, filter_term=None, limit=None, offset=None, user_type=None):
        url_suffix = '/users/'
        query_params = {
            'fields': fields,
            'filter_term': filter_term,
            'limit': limit,
            'offset': offset,
            'user_type': user_type
        }
        return self.http_request(
            method='GET',
            url_suffix=url_suffix,
            params=remove_empty_elements(query_params)
        )

    def search_user_ids(self, as_user):
        try:
            response = self.list_users(fields='id,name', filter_term=as_user, limit=1, offset=0)
            matched_user_id = response.get('entries')[0].get('id')
        except Exception as exception:
            raise ValueError(
                "An error occurred while attempting to match the as_user to a"
                " valid ID", exception)
        return str(matched_user_id)

    def handle_as_user(self, as_user_arg):
        as_user = self.handle_default_user(as_user_arg=as_user_arg)
        if re.match(emailRegex, as_user):
            if self.search_user_id is True:
                return self.search_user_ids(as_user=as_user)
            else:
                raise ValueError("The current as-user is invalid. Please either specify the "
                                 "user ID, or enable the auto-detect user IDs setting.")
        else:
            return as_user

    def handle_default_user(self, as_user_arg):
        if as_user_arg is None:
            if not self.default_as_user:
                raise ValueError(
                    "A user ID has not been specified. Please configure a default, or"
                    " add the user ID in the as_user argument.")
            return self.default_as_user
        else:
            return as_user_arg

    def search_content(self, as_user, query_object):
        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        return self.http_request(
            method='GET',
            url_suffix='/search/',
            params=query_object.prepare_params_object()
        )

    def get_folder(self, folder_id, as_user):
        url_suffix = f'/folders/{folder_id}/'

        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def list_folder_items(self, folder_id, as_user, limit, offset, sort):
        url_suffix = f'/folders/{folder_id}/'
        request_params = {
            'limit': limit,
            'offset': offset,
            'sort': sort
        }
        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        return self.http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )

    def commit_file(self, file_path, as_user, parts, upload_url_suffix):
        with open(file_path, 'rb') as file_obj:
            final_sha = sha1()
            final_sha.update(file_obj.read())
            whole_file_sha_digest = final_sha.digest()
            final_headers = {
                'Content-Type': 'application/json',
                'As-User': as_user,
                'Digest': f"SHA={base64.b64encode(whole_file_sha_digest).decode('utf-8')}",
                'Authorization': self.session.headers.get('Authorization')
            }
            return self.http_request(
                method='POST',
                url_suffix=upload_url_suffix + '/commit',
                json_data={'parts': parts},
                headers=final_headers
            )

    def create_upload_session(self, file_name, file_size, folder_id, as_user):
        url_suffix = '/files/upload_sessions'
        self._base_url = 'https://upload.box.com/api/2.0'
        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        upload_data = {
            'file_name': file_name,
            'file_size': file_size,
            'folder_id': folder_id
        }
        return self.http_request(
            method='POST',
            url_suffix=url_suffix,
            json_data=upload_data
        )

    @staticmethod
    def read_in_chunks(file_object, chunk_size=65536):
        while True:
            data = file_object.read(chunk_size)
            if not data:
                break
            yield data

    def chunk_upload(self, file_name, file_size, file_path, folder_id, as_user):
        upload_session_data = self.create_upload_session(file_name=file_name, file_size=file_size,
                                                         folder_id=folder_id, as_user=as_user)
        session_id = upload_session_data.get('id')
        part_size = upload_session_data.get('part_size')
        upload_url_suffix = f'/files/upload_sessions/{session_id}'
        parts = []
        index = 0
        with open(file_path, 'rb') as file_object:
            for chunk in self.read_in_chunks(file_object, part_size):
                content_sha1 = sha1()
                content_sha1.update(chunk)
                part_content_sha1 = content_sha1.digest()
                offset = index + len(chunk)
                self.session.headers.update({
                    'Content-Type': 'application/octet-stream',
                    'As-User': as_user,
                    'Content-length': str(file_size),
                    'Content-Range': 'bytes %s-%s/%s' % (index, offset - 1, file_size),
                    'Digest': f"SHA={base64.b64encode(part_content_sha1).decode('utf-8')}"
                })
                r = self.http_request(
                    method='PUT',
                    url_suffix=upload_url_suffix,
                    data=chunk
                )
                parts.append(r.get('part'))
                index = offset
        return parts, upload_url_suffix

    def upload_file(self, file_name=None, folder_id=None, as_user=None):
        self.base_url = 'https://upload.box.com/api/2.0'
        maximum_chunk_size = 20000000
        if not file_name:
            file_name = orenctl.getArg("file_name")
        if '.' not in file_name:
            raise ValueError('A file extension is required in the filename.')

        location = orenctl.getArg("location")
        tmpdir = tempfile.mkdtemp()
        file_path = os.path.join(tmpdir, location)
        file_size = os.path.getsize(file_path)
        if file_size > maximum_chunk_size:
            parts, upload_url_suffix = self.chunk_upload(file_name, file_size, file_path, folder_id,
                                                         as_user)
            return self.commit_file(file_path, as_user, parts, upload_url_suffix)
        else:
            with open(file_path, 'rb') as file:
                validated_as_user = self.handle_as_user(as_user_arg=as_user)
                self.session.headers.update({'As-User': validated_as_user})
                upload_url_suffix = '/files/content'
                attributes = {
                    'name': file_name,
                    'parent': {'id': folder_id}
                }
                data = {'attributes': json.dumps(attributes)}
                files = {'file': ('unused', file)}
                return self.http_request(
                    method='POST',
                    url_suffix=upload_url_suffix,
                    data=data,
                    files=files
                )

    def get_current_user(self, as_user):
        url_suffix = '/users/me/'
        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        return self.http_request(
            method='GET',
            url_suffix=url_suffix
        )

    def create_update_user(self, as_user=None, user_details=None, user_permissions=None, user_config=None):

        user_details = user_details or {}
        user_permissions = user_permissions or {}
        user_config = user_config or {}

        if user_config.get('update_user', False):
            url_suffix = f"/users/{user_config.get('user_id')}/"
            method = 'PUT'
        else:
            url_suffix = '/users/'
            method = 'POST'

        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})

        request_body = {
            "role": user_details.get('role'),
            "address": user_details.get('address'),
            "job_title": user_details.get('job_title'),
            "language": user_details.get('language'),
            "login": user_details.get('login'),
            "name": user_details.get('name'),
            "phone": user_details.get('phone'),
            "space_amount": user_details.get('space_amount'),
            "status": user_details.get('status'),
            "timezone": user_details.get('time_zone'),
            "is_sync_enabled": user_config.get('is_sync_enabled', False),
            "is_exempt_from_device_limits": user_permissions.get('is_exempt_from_device_limits', False),
            "is_external_collab_restricted": user_permissions.get('is_external_collab_restricted', False),
            "is_exempt_from_login_verification": user_permissions.get('is_exempt_from_login_verification', False),
            "can_see_managed_users": user_permissions.get('can_see_managed_users', False),
            "tracking_codes": user_details.get('tracking_codes'),
        }

        if not user_config.get('is_update', False):
            request_body["is_platform_access_only"] = user_permissions.get('is_platform_access_only', False)

        return self.http_request(
            method=method,
            url_suffix=url_suffix,
            json_data=remove_empty_elements(request_body)
        )

    def list_events(self, as_user, stream_type, created_after=None, limit=None):
        url_suffix = '/events/'
        validated_as_user = self.handle_as_user(as_user_arg=as_user)
        self.session.headers.update({'As-User': validated_as_user})
        request_params = {
            'stream_type': stream_type
        }
        if created_after:
            request_params.update({'created_after': created_after})
        if limit:
            request_params.update({'limit': limit})
        return self.http_request(
            method='GET',
            url_suffix=url_suffix,
            params=request_params
        )


def search_content_command():
    client = BoxV2()
    args = {
        "type": orenctl.getArg("type") if orenctl.getArg("type") else None,
        "ancestor_folder_ids": orenctl.getArg("ancestor_folder_ids") if orenctl.getArg("ancestor_folder_ids") else None,
        "item_name": orenctl.getArg("item_name") if orenctl.getArg("item_name") else None,
        "item_description": orenctl.getArg("item_description") if orenctl.getArg("item_description") else None,
        "comments": orenctl.getArg("comments") if orenctl.getArg("comments") else None,
        "tag": orenctl.getArg("tag") if orenctl.getArg("tag") else None,
        "created_range": orenctl.getArg("created_range") if orenctl.getArg("created_range") else None,
        "file_extensions": orenctl.getArg("file_extensions") if orenctl.getArg("file_extensions") else None,
        "limit": orenctl.getArg("limit") if orenctl.getArg("limit") else None,
        "offset": orenctl.getArg("offset") if orenctl.getArg("offset") else None,
        "owner_uids": orenctl.getArg("owner_uids") if orenctl.getArg("owner_uids") else None,
        "trash_content": orenctl.getArg("trash_content") if orenctl.getArg("trash_content") else None,
        "updated_at_range": orenctl.getArg("updated_at_range") if orenctl.getArg("updated_at_range") else None,
        "query": orenctl.getArg("query") if orenctl.getArg("query") else None,

    }
    query_object = QueryHandler(args=args)
    as_user = orenctl.getArg('as_user')
    response = client.search_content(as_user=as_user, query_object=query_object)

    results = dict(
        outputs_prefix='Box.Query',
        outputs_key_field='id',
        outputs=response.get('entries')
    )
    orenctl.results(results)


def get_folder_command():
    client = BoxV2()
    folder_id = orenctl.getArg('folder_id')
    as_user = orenctl.getArg('as_user')
    response = client.get_folder(folder_id=folder_id, as_user=as_user)
    overview_response = response.copy()
    overview_response.pop('item_collection')

    results = dict(
        outputs_prefix='Box.Folder',
        outputs_key_field='id',
        outputs=response
    )
    orenctl.results(results)


def list_folder_items_command():
    client = BoxV2()
    folder_id = orenctl.getArg('folder_id')
    as_user = orenctl.getArg('as_user')
    limit = arg_to_int(arg_name='limit', arg=orenctl.getArg('limit'), default=100)
    offset = arg_to_int(arg_name='offset', arg=orenctl.getArg('offset'), default=0)
    sort = orenctl.getArg('sort')
    response = client.list_folder_items(folder_id=folder_id, as_user=as_user, limit=limit,
                                        offset=offset, sort=sort)
    overview_response = response.copy()
    overview_response.pop('item_collection')

    results = dict(
        outputs_prefix='Box.Folder',
        outputs_key_field='id',
        outputs=response
    )
    orenctl.results(results)


def list_users_command():
    client = BoxV2()
    fields = orenctl.getArg('fields')
    filter_term = orenctl.getArg('filter_term')
    limit = arg_to_int(arg_name='limit', arg=orenctl.getArg('limit'), default=100)
    offset = arg_to_int(arg_name='offset', arg=orenctl.getArg('offset'), default=0)
    user_type = orenctl.getArg('user_type')
    response = client.list_users(fields=fields, filter_term=filter_term, limit=limit, offset=offset,
                                 user_type=user_type)

    results = dict(
        outputs_prefix='Box.Users',
        outputs_key_field='id',
        outputs=response.get('entries')
    )
    orenctl.results(results)


def upload_file_command():
    client = BoxV2()
    file_name = orenctl.getArg('file_name')
    folder_id = orenctl.getArg('folder_id')
    as_user = orenctl.getArg('as_user')
    response = client.upload_file(file_name=file_name, folder_id=folder_id,
                                  as_user=as_user)
    readable_output = "File was successfully uploaded"
    results = dict(
        readable_output=readable_output,
        outputs_prefix='Box.File',
        outputs_key_field='id',
        outputs=response.get('entities')
    )
    orenctl.results(results)


def get_current_user_command():
    client = BoxV2()
    as_user = orenctl.getArg('as_user')
    response = client.get_current_user(as_user=as_user)

    results = dict(
        outputs_prefix='Box.User',
        outputs_key_field='id',
        outputs=response
    )
    orenctl.results(results)


def update_user_command():
    client = BoxV2()
    as_user = orenctl.getArg('as_user')
    user_id = orenctl.getArg('user_id')
    login = orenctl.getArg('login')
    name = orenctl.getArg('name')
    role = orenctl.getArg('role')
    language = orenctl.getArg('language')
    is_sync_enabled = arg_to_boolean(
        orenctl.getArg('is_sync_enabled') if orenctl.getArg('is_sync_enabled') else 'false')
    job_title = orenctl.getArg('job_title')
    phone = orenctl.getArg('phone')
    address = orenctl.getArg('address')
    space_amount = arg_to_int(arg_name='space_amount', arg=orenctl.getArg('space_amount'), default=-1)
    tracking_codes = parse_key_value_arg(arg_str=orenctl.getArg('tracking_codes'))
    can_see_managed_users = arg_to_boolean(
        orenctl.getArg('can_see_managed_users') if orenctl.getArg('can_see_managed_users') else 'false')
    time_zone = orenctl.getArg('timezone')
    is_exempt_from_device_limits = arg_to_boolean(
        orenctl.getArg('is_exempt_from_device_limits') if orenctl.getArg('is_exempt_from_device_limits') else 'false')
    is_exempt_from_login_verification = arg_to_boolean(
        orenctl.getArg('is_exempt_from_login_verification') if orenctl.getArg(
            'is_exempt_from_login_verification') else 'false')
    is_external_collab_restricted = arg_to_boolean(
        orenctl.getArg('is_external_collab_restricted') if orenctl.getArg('is_external_collab_restricted') else 'false')
    status = orenctl.getArg('status')

    user_details = {
        "login": login,
        "name": name,
        "role": role,
        "language": language,
        "job_title": job_title,
        "phone": phone,
        "address": address,
        "space_amount": space_amount,
        "tracking_codes": tracking_codes,
        "time_zone": time_zone,
        "status": status
    }

    user_permissions = {
        "can_see_managed_users": can_see_managed_users,
        "is_exempt_from_device_limits": is_exempt_from_device_limits,
        "is_exempt_from_login_verification": is_exempt_from_login_verification,
        "is_external_collab_restricted": is_external_collab_restricted,
    }

    user_config = {
        "is_sync_enabled": is_sync_enabled,
        "as_user": as_user,
        "user_id": user_id
    }
    response = client.create_update_user(as_user="admin_user", user_details=user_details,
                                         user_permissions=user_permissions, user_config=user_config)

    results = dict(
        outputs_prefix='Box.User',
        outputs_key_field='id',
        outputs=response
    )
    orenctl.results(results)


def list_user_events_command():
    client = BoxV2()
    as_user = orenctl.getArg('as_user')
    stream_type = orenctl.getArg('stream_type')
    limit: int = arg_to_int(arg_name='limit', arg=orenctl.getArg('limit'), default=10)
    response: dict = client.list_events(as_user=as_user, stream_type=stream_type, limit=limit)
    events = response.get('entries', [])

    results = dict(
        outputs_prefix='Box.Events',
        outputs_key_field='event_id',
        outputs=events
    )
    orenctl.results(results)


def list_enterprise_events_command():
    client = BoxV2()
    as_user = orenctl.getArg('as_user')
    limit: int = arg_to_int(arg_name='limit', arg=orenctl.getArg('limit'), default=10)
    created_after = arg_to_datetime(
        arg=orenctl.getArg('created_after'),
        arg_name='Created after',
        required=False
    ).strftime(DATE_FORMAT)
    response: dict = client.list_events(as_user=as_user, stream_type='admin_logs',
                                        created_after=created_after, limit=limit)
    events = response.get('entries', [])

    results = dict(
        outputs_prefix='Box.Events',
        outputs_key_field='event_id',
        outputs=events
    )
    orenctl.results(results)


if orenctl.command() == "box-search-content":
    search_content_command()
elif orenctl.command() == "box-get-folder":
    get_folder_command()
elif orenctl.command() == "box-list-folder-items":
    list_folder_items_command()
elif orenctl.command() == "box-list-users":
    list_users_command()
elif orenctl.command() == "box-upload-file":
    upload_file_command()
elif orenctl.command() == "box-get-current-user":
    get_current_user_command()
elif orenctl.command() == "box-update-user":
    update_user_command()
elif orenctl.command() == "box-list-user-events":
    list_user_events_command()
elif orenctl.command() == "box-list-enterprise-events":
    list_enterprise_events_command()
