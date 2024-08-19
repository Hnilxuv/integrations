import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

import requests

import orenctl

entryTypes = {'note': 1, 'error': 2, 'pending': 3}
formats = {'html': 'html', 'table': 'table', 'json': 'json', 'text': 'text', 'markdown': 'markdown'}
BASE_URL = ''
integrationContext = {}
USERNAME = ''
PASSWORD = ''
CLIENT_ID = ''
APPLICATION_JSON = "application/json"
HEADERS = {
    'Content-Type': APPLICATION_JSON,
    'Accept': APPLICATION_JSON
}
HTTP_CODES = {
    'unauthorized': 401,
    'internal_server_error': 500,
    'success': 200
}
QUERY_OPERATORS = ['eq', 'gt', 'lt', 'contains', 'startswith']
SECURED = False
IS_PY3 = sys.version_info[0] == 3
if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)

else:
    STRING_TYPES = (str, unicode)  # type: ignore # noqa: F821
    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore

BUSINESS_OBJECT_CONTEXT_KEY = 'Cherwell.BusinessObjects(val.RecordId == obj.RecordId)'


def getIntegrationContext():
    return integrationContext


def setIntegrationContext(context):
    global integrationContext
    integrationContext = context


def createContextSingle(obj, id=None, keyTransform=None, removeNull=False):  # pragma: no cover
    res = {}  # type: dict
    if keyTransform is None:
        def keyTransform(s): return s  # noqa
    keys = obj.keys()
    for key in keys:
        if removeNull and obj[key] in ('', None, [], {}):
            continue
        values = key.split('.')
        current = res
        for v in values[:-1]:
            current.setdefault(v, {})
            current = current[v]
        current[keyTransform(values[-1])] = obj[key]

    if id is not None:
        res.setdefault('ID', id)

    return res


def createContext(data, id=None, keyTransform=None, removeNull=False):
    if isinstance(data, (list, tuple)):
        return [createContextSingle(d, id, keyTransform, removeNull) for d in data]
    else:
        return createContextSingle(data, id, keyTransform, removeNull)


def date_to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%S'):
    if isinstance(date_str_or_dt, STRING_OBJ_TYPES):
        return int(time.mktime(time.strptime(date_str_or_dt, date_format)) * 1000)

    return int(time.mktime(date_str_or_dt.timetuple()) * 1000)


def get_access_token(new_token, is_fetch=False):
    integration_context = getIntegrationContext()
    token_expiration_time = integration_context.get('token_expiration_time')
    current_time = date_to_timestamp(datetime.now(timezone.utc))
    if new_token or not token_expiration_time or token_expiration_time < current_time:
        token = get_new_access_token(is_fetch=is_fetch)
        return token
    else:
        return integration_context.get('access_token')


def request_new_access_token(using_refresh):
    url = BASE_URL + "token"
    refresh_token = getIntegrationContext().get('refresh_token')

    if using_refresh:
        payload = f'client_id={CLIENT_ID}&grant_type=refresh_token&refresh_token={refresh_token}'
    else:
        payload = f'client_id={CLIENT_ID}&grant_type=password&username={USERNAME}&password={PASSWORD}'

    headers = {
        'Accept': "application/json",
        'Content-Type': "application/x-www-form-urlencoded",
    }

    response = http_request('POST', url, payload, custom_headers=headers)
    return response


def build_headers(token, headers=None):
    headers = headers if headers else HEADERS
    headers['Authorization'] = f'Bearer {token}'
    return headers


def http_request(method, url, payload, token=None, custom_headers=None, is_fetch=False):
    headers = build_headers(token, custom_headers)
    try:
        response = requests.request(method, url, data=payload, headers=headers, verify=SECURED)
    except requests.exceptions.ConnectionError as e:
        err_message = f'Error connecting to server. Check your URL/Proxy/Certificate settings: {e}'
        raise_or_return_error(err_message, is_fetch)
        return None  # Ensure response is defined even if an error occurs
    return response


def parse_response(response, error_operation, file_content=False, is_fetch=False):
    try:
        response.raise_for_status()
        if not response.content:
            return
        if file_content:
            return response.content
        else:
            return response.json()
    except requests.exceptions.HTTPError:
        try:
            res_json = response.json()
            err_msg = res_json.get('errorMessage') or res_json.get('error_description') or res_json.get('Message')
        except Exception:
            err_msg = response.content.decode('utf-8')
        raise_or_return_error(error_operation + ": " + str(err_msg), is_fetch)
    except Exception as error:
        raise_or_return_error(f'Could not parse response {error}', is_fetch)


def get_new_access_token(is_fetch=False):
    response = request_new_access_token(True)
    if response.status_code != HTTP_CODES['success']:
        response = request_new_access_token(False)
    res_json = parse_response(response,
                              "Could not get token. Check your credentials (user/password/client id) and try again",
                              is_fetch=is_fetch)
    token_expiration_time = int(date_to_timestamp(res_json.get('.expires'), '%a, %d %b %Y %H:%M:%S GMT'))
    setIntegrationContext({
        'refresh_token': res_json.get('refresh_token'),
        'token_expiration_time': token_expiration_time,
        'access_token': res_json.get('access_token')
    })
    return res_json.get('access_token')


def make_request(method, url, payload=None, headers=None, is_fetch=False):
    token = get_access_token(False, is_fetch=is_fetch)
    response = http_request(method, url, payload, token, custom_headers=headers, is_fetch=is_fetch)
    if response.status_code == HTTP_CODES['unauthorized']:
        token = get_access_token(True, is_fetch=is_fetch)
        response = http_request(method, url, payload, token, custom_headers=headers, is_fetch=is_fetch)
    return response


def return_error(error):
    raise ValueError(error)


def raise_or_return_error(msg, raise_flag):
    if raise_flag:
        raise ValueError(msg)
    else:
        return_error(msg)


def get_key_value_dict_from_template(key, val, business_object_id, is_fetch=False):
    cherwell = Cherwell()
    template_dict = cherwell.get_business_object_template(business_object_id, is_fetch=is_fetch)
    return cherwell_dict_parser(key, val, template_dict.get('fields'))


def cherwell_dict_parser(key, value, item_list):
    new_dict = {}
    for item in item_list:
        field_key = item.get(key)
        new_dict[field_key] = item.get(value)

    return new_dict


def build_fields_for_business_object(data_dict, ids_dict):
    fields = []
    for key, value in data_dict.items():
        new_field = {
            "dirty": "true",
            "fieldId": ids_dict.get(key),
            "name": key,
            "value": value
        }
        fields.append(new_field)
    return fields


def parse_fields_from_business_object(field_list):
    new_business_obj = cherwell_dict_parser('name', 'value', field_list)

    return new_business_obj


def uniqueFile():
    return str(uuid.uuid4())


def investigation():
    return {"id": "1"}


def fileResult(filename, data, file_type=None):
    if file_type is None:
        file_type = entryTypes['file']
    temp = uniqueFile()
    if (IS_PY3 and isinstance(data, str)) or (not IS_PY3 and isinstance(data, unicode)):  # type: ignore # noqa: F821
        data = data.encode('utf-8')
    # pylint: enable=undefined-variable
    with open(investigation()['id'] + '_' + temp, 'wb') as f:
        f.write(data)

    if isinstance(filename, str):
        replaced_filename = filename.replace("../", "")
        if filename != replaced_filename:
            filename = replaced_filename
            orenctl.error(
                "replaced {filename} with new file name {replaced_file_name}".format(
                    filename=filename, replaced_file_name=replaced_filename
                )
            )

    return {'Contents': '', 'ContentsFormat': formats['text'], 'Type': file_type, 'File': filename, 'FileID': temp}


def string_to_context_key(string):
    if isinstance(string, STRING_OBJ_TYPES):
        return "".join(word.capitalize() for word in string.split('_'))
    else:
        raise Exception('The key is not a string: {}'.format(string))


def getFilePath(id):
    return {'id': id, 'path': 'test/test.txt', 'name': 'test.txt'}


def get_attachments_info(id_type, object_id, attachment_type, business_object_type_name=None,
                         business_object_type_id=None):
    type = 'File'
    cherwell = Cherwell()
    result = cherwell.get_attachments_details(id_type, object_id, business_object_type_name, business_object_type_id, type,
                                     attachment_type)
    attachments = result.get('attachments')
    attachments_info = [{
        'AttachmentFiledId': attachment.get('attachmentFileId'),
        'FileName': attachment.get('displayText'),
        'AttachmentId': attachment.get('attachmentId'),
        'BusinessObjectType': business_object_type_name,
        f'BusinessObject{string_to_context_key(id_type)}': object_id

    } for attachment in attachments]
    return attachments_info, result


def validate_query_list(query_list, is_fetch):
    for index, query in enumerate(query_list):
        if len(query) != 3:
            length_err_message = f'Cannot parse query, should be of the form: `[["FieldName","Operator","Value"],' \
                                 f'["FieldName","Operator","Value"],...]`. Filter in index {index} is malformed: {query}'
            raise_or_return_error(length_err_message, is_fetch)
        if query[1] not in QUERY_OPERATORS:
            operator_err_message = f'Operator should be one of the following: {", ".join(QUERY_OPERATORS)}. Filter in' \
                                   f' index {index}, was: {query[1]}'
            raise_or_return_error(operator_err_message, is_fetch)


def parse_string_query_to_list(query_string, is_fetch=False):
    try:
        query_list = json.loads(query_string)
    except (ValueError, TypeError):
        err_message = 'Cannot parse query, should be of the form: `[["FieldName","Operator","Value"],' \
                      '["FieldName","Operator","Value"]]`.'
        raise_or_return_error(err_message, is_fetch)
    validate_query_list(query_list, is_fetch)
    return query_list


def build_query_dict(query, filed_ids_dict, is_fetch):
    field_name = query[0]
    operator = query[1]
    value = query[2]
    field_id = filed_ids_dict.get(field_name)
    if not field_id:
        err_message = f'Field name: {field_name} does not exit in the given business objects'
        raise_or_return_error(err_message, is_fetch)
    return {
        'fieldId': filed_ids_dict.get(field_name),
        'operator': operator,
        'value': value
    }


def build_query_dict_list(query_list, filed_ids_dict, is_fetch):
    query_dict_list = []
    for query in query_list:
        query_dict = build_query_dict(query, filed_ids_dict, is_fetch)
        query_dict_list.append(query_dict)
    return query_dict_list


def run_query_on_business_objects(bus_id, filter_query, max_results, is_fetch):
    cherwell = Cherwell()
    payload = {
        'busObId': bus_id,
        'includeAllFields': True,
        'filters': filter_query
    }
    if max_results:
        payload['pageSize'] = max_results
    return cherwell.get_search_results(payload, is_fetch=is_fetch)


def parse_fields_from_business_object_list(response):
    object_list = []
    if not response.get('businessObjects'):
        return []
    for business_obj in response.get('businessObjects'):
        new_business_obj = parse_fields_from_business_object(business_obj.get('fields'))
        new_business_obj['BusinessObjectId'] = business_obj.get('busObId')
        new_business_obj['PublicId'] = business_obj.get('busObPublicId')
        new_business_obj['RecordId'] = business_obj.get('busObRecId')
        object_list.append(new_business_obj)

    return object_list


def query_business_object(query_list, business_object_id, max_results, is_fetch=False):
    filed_ids_dict = get_key_value_dict_from_template('name', 'fieldId', business_object_id, is_fetch=is_fetch)
    filters = build_query_dict_list(query_list, filed_ids_dict, is_fetch=is_fetch)
    query_result = run_query_on_business_objects(business_object_id, filters, max_results, is_fetch=is_fetch)
    business_objects = parse_fields_from_business_object_list(query_result)
    return business_objects, query_result


def cherwell_run_saved_search(association_id, scope, scope_owner, search_name):
    cherwell = Cherwell()
    search_payload = {
        "Association": association_id,
        "scope": scope,
        "scopeOwner": scope_owner,
        "searchName": search_name,
        "includeAllFields": True,
    }

    results = cherwell.get_search_results(search_payload)
    return parse_fields_from_business_object_list(results)


def cherwell_get_business_object_id(business_object_name):
    business_object_id = resolve_business_object_id_by_name(business_object_name)
    business_object_info = {
        'BusinessObjectId': business_object_id,
        'BusinessObjectName': business_object_name
    }
    return business_object_info


def query_business_object_string(business_object_name, query_string, max_results):
    if max_results:
        try:
            int(max_results)
        except ValueError:
            return return_error('`max_results` argument received is not a number')
    business_object_id = resolve_business_object_id_by_name(business_object_name)
    query_filters_list = parse_string_query_to_list(query_string)
    return query_business_object(query_filters_list, business_object_id, max_results)


def upload_attachment(id_type, object_id, type_name, file_entry_id):
    cherwell = Cherwell()
    file_data = getFilePath(file_entry_id)
    file_path = file_data.get('path')
    file_name = file_data.get('name')
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as f:
            file_content = f.read()
        attachment_id = cherwell.upload_business_object_attachment(file_name, file_size, file_content, type_name,
                                                                   id_type, object_id)
        return attachment_id
    except Exception as err:
        return_error(f'unable to open file: {err}')


def download_attachments(id_type, object_id, business_object_type_name=None, business_object_type_id=None,
                         is_fetch=False):
    type = 'File'
    attachment_type = 'Imported'
    cherwell = Cherwell()
    result = cherwell.get_attachments_details(id_type, object_id, business_object_type_name, business_object_type_id, type,
                                     attachment_type, is_fetch=is_fetch)
    attachments_to_download = result.get('attachments')
    if not attachments_to_download:
        return
    return get_attachments_content(attachments_to_download, is_fetch=is_fetch)


def get_attachments_content(attachments_to_download, is_fetch):
    cherwell = Cherwell()
    attachments = []
    for attachment in attachments_to_download:
        new_attachment = {
            'FileName': attachment.get('displayText'),
            'CreatedAt': attachment.get('created'),
            'Content': cherwell.download_attachment_from_business_object(attachment, is_fetch=is_fetch)
        }
        attachments.append(new_attachment)
    return attachments


def attachment_results(attachments):
    attachments_file_results = []
    for attachment in attachments:
        attachment_content = attachment.get('Content')
        attachment_name = attachment.get('FileName')
        attachments_file_results.append(fileResult(attachment_name, attachment_content))
    return attachments_file_results


def resolve_business_object_id_by_name(name, is_fetch=False):
    cherwell = Cherwell()
    res = cherwell.get_business_object_summary_by_name(name, is_fetch)
    if not res:
        err_message = f'Could not retrieve "{name}" business object id. Make sure "{name}" is a valid business object.'
        raise_or_return_error(err_message, is_fetch)
    return res[0].get('busObId')


def build_business_object_json(simple_json, business_object_id, object_id=None, id_type=None):
    business_object_ids_dict = get_key_value_dict_from_template('name', 'fieldId', business_object_id)
    fields_for_business_object = build_fields_for_business_object(simple_json, business_object_ids_dict)
    business_object_json = {
        'busObId': business_object_id,
        "fields": fields_for_business_object
    }
    if object_id:
        id_key = 'busObPublicId' if id_type == 'public_id' else 'busObRecId'
        business_object_json[id_key] = object_id
    return business_object_json


def create_business_object(name, data_json):
    cherwell = Cherwell()
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id)
    return cherwell.save_business_object(business_object_json)


def update_business_object(name, data_json, object_id, id_type):
    cherwell = Cherwell()
    business_object_id = resolve_business_object_id_by_name(name)
    business_object_json = build_business_object_json(data_json, business_object_id, object_id, id_type)
    return cherwell.save_business_object(business_object_json)


def get_business_object(name, object_id, id_type):
    cherwell = Cherwell()
    business_object_id = resolve_business_object_id_by_name(name)
    results = cherwell.get_business_object_record(business_object_id, object_id, id_type)
    parsed_business_object = parse_fields_from_business_object(results.get('fields'))
    parsed_business_object['PublicId'] = results.get('busObPublicId')
    parsed_business_object['RecordId'] = results.get('busObRecId')
    return parsed_business_object, results


class Cherwell(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.client_id = orenctl.getParam("client_id")
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)
        self.verify = True  # or False, depending on your needs

    def http_request(self, method, url, *args, **kwargs):
        response = self.session.request(method=method, url=url, verify=self.verify, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise ValueError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def save_business_object(self, payload):
        url = BASE_URL + "api/V1/savebusinessobject"
        response = make_request("POST", url, json.dumps(payload)).json()
        return parse_response(response, "Could not save business object")

    def get_business_object_summary_by_name(self, name, is_fetch=False):
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobname/{name}'
        response = make_request('GET', url, is_fetch=is_fetch).json()
        return parse_response(response, "Could not get business object summary", is_fetch=is_fetch)

    def get_business_object_record(self, business_object_id, object_id, id_type):
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        url = BASE_URL + f'api/V1/getbusinessobject/busobid/{business_object_id}/{id_type_str}/{object_id}'
        response = make_request("GET", url).json()
        return parse_response(response, "Could not get business objects")

    def download_attachment_from_business_object(self, attachment, is_fetch):
        attachment_id = attachment.get('attachmentId')
        business_object_id = attachment.get('busObId')
        business_record_id = attachment.get('busObRecId')
        url = BASE_URL + f'api/V1/getbusinessobjectattachment' \
                         f'/attachmentid/{attachment_id}/busobid/{business_object_id}/busobrecid/{business_record_id}'
        response = make_request('GET', url, is_fetch=is_fetch).json()
        return parse_response(response, f'Unable to get content of attachment {attachment_id}', file_content=True,
                              is_fetch=is_fetch)

    def upload_business_object_attachment(self, file_name, file_size, file_content, object_type_name, id_type,
                                          object_id, ):
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        url = BASE_URL + f'/api/V1/uploadbusinessobjectattachment/' \
                         f'filename/{file_name}/busobname/{object_type_name}/{id_type_str}/{object_id}/offset/0/totalsize/{file_size}'
        payload = file_content
        headers = HEADERS
        headers['Content-Type'] = "application/octet-stream"
        response = make_request('POST', url, payload, headers).json()
        return parse_response(response, f'Could not upload attachment {file_name}')

    def remove_attachment(self, id_type, object_id, type_name, attachment_id):
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        url = BASE_URL + f'/api/V1/removebusinessobjectattachment/' \
                         f'attachmentid/{attachment_id}/busobname/{type_name}/{id_type_str}/{object_id}'
        response = make_request('DELETE', url).json()
        parse_response(response, f'Could not remove attachment {attachment_id} from {type_name} {object_id}')

    def get_search_results(self, payload, is_fetch=False):
        url = BASE_URL + "api/V1/getsearchresults"
        response = make_request("POST", url, json.dumps(payload)).json()
        return parse_response(response, "Could not search for business objects", is_fetch=is_fetch)

    def get_business_object_summary_by_id(self, _id, is_fetch=False):
        url = BASE_URL + f'api/V1/getbusinessobjectsummary/busobid/{_id}'
        response = make_request('GET', url, is_fetch=is_fetch).json()
        return parse_response(response, "Could not get business object summary", is_fetch=is_fetch)

    def get_business_object_template(self, business_object_id, include_all=True, field_names=None, fields_ids=None,
                                     is_fetch=False):
        url = BASE_URL + "api/V1/getbusinessobjecttemplate"
        payload = {
            "busObId": business_object_id,
            "includeAll": include_all
        }

        if field_names:
            payload['fieldNames'] = field_names
        if fields_ids:
            payload['fieldIds'] = fields_ids
        response = make_request("POST", url, json.dumps(payload), is_fetch=is_fetch).json()
        return parse_response(response, "Could not get business object template", is_fetch=is_fetch)

    def get_attachments_details(self, id_type, object_id, object_type_name, object_type_id, type, attachment_type,
                                is_fetch=False):
        id_type_str = 'publicid' if id_type == 'public_id' else 'busobrecid'
        business_object_type_str = 'busobid' if object_type_id else 'busobname'
        object_type = object_type_id if object_type_id else object_type_name
        url = BASE_URL + f'api/V1/getbusinessobjectattachments/' \
                         f'{business_object_type_str}/{object_type}/' \
                         f'{id_type_str}/{object_id}' \
                         f'/type/{type}' \
                         f'/attachmenttype/{attachment_type}'
        response = make_request('GET', url, is_fetch=is_fetch).json()
        return parse_response(response, f'Unable to get attachments for {object_type} {object_id}', is_fetch=is_fetch)


def create_business_object_command():
    type_name = orenctl.getArg('type')
    data_json = json.loads(orenctl.getArg('json'))
    result = create_business_object(type_name, data_json)
    ids = {
        'PublicId': result.get('busObPublicId'),
        'RecordId': result.get('busObRecId')
    }

    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'EntryContext': {
            BUSINESS_OBJECT_CONTEXT_KEY: ids
        }
    })


def update_business_object_command():
    type_name = orenctl.getArg('type')
    data_json = json.loads(orenctl.getArg('json'))
    object_id = orenctl.getArg('id_value')
    id_type = orenctl.getArg('id_type')
    result = update_business_object(type_name, data_json, object_id, id_type)
    ids = {
        'PublicId': result.get('busObPublicId'),
        'RecordId': result.get('busObRecId')
    }

    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': result,
        'EntryContext': {
            BUSINESS_OBJECT_CONTEXT_KEY: ids
        }
    })


def get_business_object_command():
    type_name = orenctl.getArg('type')
    id_type = orenctl.getArg('id_type')
    object_id = orenctl.getArg('id_value')
    business_object, results = get_business_object(type_name, object_id, id_type)

    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': results,
        'EntryContext': {
            BUSINESS_OBJECT_CONTEXT_KEY: createContext(business_object)
        }
    })


def download_attachments_command():
    id_type = orenctl.getArg('id_type')
    object_id = orenctl.getArg('id_value')
    type_name = orenctl.getArg('type')
    attachments = download_attachments(id_type, object_id, business_object_type_name=type_name)
    if not attachments:
        return_error(f'No attachments were found for {type_name}:{object_id}')

    orenctl.results({
        "attachments": attachment_results(attachments)
    })


def upload_attachment_command():
    id_type = orenctl.getArg('id_type')
    object_id = orenctl.getArg('id_value')
    type_name = orenctl.getArg('type')
    file_entry_id = orenctl.getArg('file_entry_id')
    attachment_id = upload_attachment(id_type, object_id, type_name, file_entry_id)
    entry_context = {
        'AttachmentFileId': attachment_id,
        'BusinessObjectType': type_name,
        string_to_context_key(id_type): object_id
    }
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': {'attachment_id': attachment_id},
        'EntryContext': {'Cherwell.UploadedAttachments(val.AttachmentId == obj.AttachmentId)': entry_context},
    })


def get_attachments_info_command():
    id_type = orenctl.getArg('id_type')
    object_id = orenctl.getArg('id_value')
    type_name = orenctl.getArg('type')
    attachment_type = orenctl.getArg('attachment_type')
    attachments_info, raw_result = get_attachments_info(id_type, object_id, attachment_type,
                                                        business_object_type_name=type_name)

    result = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': raw_result,
    }
    if attachments_info:
        result['EntryContext'] = {
            'Cherwell.AttachmentsInfo': attachments_info}

    orenctl.results(result)


def remove_attachment_command():
    cherwell = Cherwell()
    id_type = orenctl.getArg('id_type')
    object_id = orenctl.getArg('id_value')
    type_name = orenctl.getArg('type')
    attachment_id = orenctl.getArg('attachment_id')
    cherwell.remove_attachment(id_type, object_id, type_name, attachment_id)
    md = f'### Attachment: {attachment_id}, was successfully removed from {type_name} {object_id}'
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': md,
        'HumanReadable': md,
    })


def query_business_object_command():
    type_name = orenctl.getArg('type')
    query_string = orenctl.getArg('query')
    max_results = orenctl.getArg('max_results')
    results, raw_response = query_business_object_string(type_name, query_string, max_results)
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': raw_response,
        'EntryContext': {'Cherwell.QueryResults': results},
    })


def cherwell_run_saved_search_command():
    association_id = orenctl.getArg('association_id')
    scope = orenctl.getArg('scope')
    scope_owner = orenctl.getArg('scope_owner')
    search_name = orenctl.getArg('search_name')
    results = cherwell_run_saved_search(association_id, scope, scope_owner, search_name)
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': results,
        'EntryContext': {'Cherwell.SearchOperation(val.RecordId == obj.RecordId)': results},
    })


def cherwell_get_business_object_id_command():
    business_object_name = orenctl.getArg('business_object_name')
    result = cherwell_get_business_object_id(business_object_name)
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': result,
        'EntryContext': {'Cherwell.BusinessObjectInfo(val.BusinessObjectId == obj.BusinessObjectId)': result},
    })


def cherwell_get_business_object_summary_command():
    cherwell = Cherwell()
    business_object_name = orenctl.getArg('name')
    business_object_id = orenctl.getArg('id')

    if not business_object_id and not business_object_name:
        raise ValueError('No name or ID were specified. Please specify at least one of them.')
    elif business_object_id:
        result = cherwell.get_business_object_summary_by_id(business_object_id)
    else:
        result = cherwell.get_business_object_summary_by_name(business_object_name)

    orenctl.results({"outputs": result,
                     "outputs_key_field": 'busObId',
                     "outputs_prefix": 'Cherwell.BusinessObjectSummary',
                     "raw_response": result})


if orenctl.command() == 'cherwell-create-business-object':
    create_business_object_command()
elif orenctl.command() == 'cherwell-update-business-object':
    update_business_object_command()
elif orenctl.command() == 'cherwell-get-business-object':
    get_business_object_command()
elif orenctl.command() == 'cherwell-download-attachments':
    download_attachments_command()
elif orenctl.command() == 'cherwell-upload-attachment':
    upload_attachment_command()
elif orenctl.command() == 'cherwell-get-attachments-info':
    get_attachments_info_command()
elif orenctl.command() == 'cherwell-remove-attachment':
    remove_attachment_command()
elif orenctl.command() == 'cherwell-query-business-object':
    query_business_object_command()
elif orenctl.command() == 'cherwell-run-saved-search':
    cherwell_run_saved_search_command()
elif orenctl.command() == 'cherwell-get-business-object-id':
    cherwell_get_business_object_id_command()
elif orenctl.command() == 'cherwell-get-business-object-summary':
    cherwell_get_business_object_summary_command()
