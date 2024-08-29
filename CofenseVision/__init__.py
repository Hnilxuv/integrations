import json
from datetime import datetime

import requests
from requests import HTTPError

import orenctl

API_SUFFIX = "/api/v4"
API_ENDPOINTS = {
    "AUTHENTICATION": "/uaa/oauth/token",
    "GET_ALL_SEARCHES": API_SUFFIX + "/searches",
    "GET_ATTACHMENT": API_SUFFIX + "/attachment",
    "GET_MESSAGE": API_SUFFIX + "/messages",
    "GET_MESSAGE_METADATA": API_SUFFIX + "/messages/metadata",
    "GET_QUARANTINE_JOBS": API_SUFFIX + "/quarantineJobs/filter",
    "GET_MESSAGE_TOKEN": API_SUFFIX + "/messages",
    "QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs",
    "RESTORE_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/restore",
    "GET_MESSAGE_SEARCH": API_SUFFIX + "/searches/{}",
    "APPROVE_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/approve",
    "GET_SEARCH_RESULTS": API_SUFFIX + "/searches/{}/results",
    "IOC_REPOSITORY": "/iocrepository/v1/iocs",
    "STOP_QUARANTINE_JOB": API_SUFFIX + "/quarantineJobs/{}/stop",
    "CREATE_MESSAGE_SEARCH": API_SUFFIX + "/searches",
    "GET_LAST_IOC": "/iocrepository/v1/iocs/last",
    "GET_IOCS": "/iocrepository/v1/iocs",
    "GET_SEARCHABLE_HEADERS": API_SUFFIX + "/config/searchableHeaders"
}
ERROR_MESSAGE = {
    'INVALID_FORMAT': "{} is an invalid format for {}. Supported format is: {}",
    'INVALID_PAGE_VALUE': 'Page number must be a non-zero and positive numeric value.',
    'INVALID_PAGE_SIZE_RANGE': 'Page size should be in the range from 1 to 2000.',
    'UNSUPPORTED_FIELD': "{} is not a supported value for {}. Supported values for {} are: {}.",
    'UNSUPPORTED_FIELD_FOR_IOCS_LIST': "{} is not a supported value for {}. Supported value for {} is: {}.",
    'INVALID_REQUIRED_PARAMETER_HASH': 'At least one of the hash values (md5 or sha256) is required.',
    'INVALID_ARGUMENT': '{} is an invalid value for {}.',
    'MISSING_REQUIRED_PARAM': "{} is a required parameter. Please provide correct value.",
    'INVALID_QUARANTINE_JOB_PARAM': "{} must be a non-zero positive integer number.",
    'INVALID_SEARCH_ID': 'ID must be a non-zero positive integer number.',
    "INVALID_QUARANTINE_JOB_ID": "Quarantine Job ID must be a non-zero positive integer number.",
    'INVALID_SEARCH_LENGTH': "Maximum 3 values are allowed to create a search for {} parameter."
}
DEFAULT_SORT_VALUE = "id:asc"
QUARANTINE_JOB_OUTPUT_PREFIX = "Cofense.QuarantineJob"
MAX_PAGE_SIZE = 2000
SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST = "propertyName:sortOrder"
SUPPORTED_SORT_FORMAT = 'propertyName1:sortOrder1,propertyName2:sortOrder2'
SUPPORTED_SORT = {
    'order_by': ['asc', 'desc'],
    'quarantine_jobs_list': ['id', 'createdBy', 'createdDate', 'modifiedBy', 'modifiedDate', 'stopRequested'],
    'message_searches_list': ['id', 'createdBy', 'createdDate', 'modifiedBy', 'modifiedDate', 'receivedAfterDate',
                              'receivedBeforeDate'],
    'message_search_result_get': ['id', 'subject', 'createdOn', 'sentOn', 'htmlBody', 'md5', 'sha1', 'sha256'],
    "iocs_list": ["updatedAt"],
}
STATUS = ['NEW', 'PENDING_APPROVAL', 'QUEUED', 'RUNNING', 'COMPLETED', 'FAILED']
SUPPORTED_QUARANTINE_EMAILS_FORMAT = "internetMessageID1:recipientAddress1,internetMessageID2:recipientAddress2"
APPLICATION_JSON = "application/json"
STRING_OBJ_TYPES = (str,)
DATE_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
SUPPORTED_CRITERIA = ['ANY', 'ALL']
SUPPORTED_HASH_VALUE_FORMAT = 'hashtype1:hashvalue1,hashtype2:hashvalue2'
SUPPORTED_HASH = ['MD5', 'SHA256']
SUPPORTED_HEADERS_FORMAT = 'key1:value1,key2:value1:value2:value3'
THREAT_TYPES = ['domain', 'md5', 'sender', 'sha256', 'subject', 'url']


def validate_required_parameters(**kwargs):
    for key, value in kwargs.items():
        if not value:
            raise ValueError(ERROR_MESSAGE["MISSING_REQUIRED_PARAM"].format(key))


def get_hash_type(hash_file):
    hash_len = len(hash_file)
    if hash_len == 32:
        return 'md5'
    elif hash_len == 40:
        return 'sha1'
    elif hash_len == 64:
        return 'sha256'
    elif hash_len == 128:
        return 'sha512'
    else:
        return 'Unknown'


def validate_params_for_attachment_get(md5=None, sha256=None):
    if not md5 and not sha256:
        raise ValueError(ERROR_MESSAGE['INVALID_REQUIRED_PARAMETER_HASH'])
    if md5 and get_hash_type(md5) != 'md5':
        raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(md5, 'md5 hash'))
    if sha256 and get_hash_type(sha256) != 'sha256':
        raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(sha256, 'sha256 hash'))


def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    if values_to_ignore is None:
        values_to_ignore = (None, "", [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }


def validate_page_size(page_size):
    if not page_size or not str(page_size).isdigit() or int(page_size) <= 0 or int(page_size) > MAX_PAGE_SIZE:
        raise ValueError(ERROR_MESSAGE["INVALID_PAGE_SIZE_RANGE"])


def validate_sort(sort_list, command):
    for sort_by in sort_list:
        if len(list(filter(None, sort_by.split(':')))) != 2:
            sort_by = sort_by if sort_by else "None"
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(sort_by, 'sort',
                                                                    SUPPORTED_SORT_FORMAT_FOR_IOCS_LIST
                                                                    if command == "iocs_list"
                                                                    else SUPPORTED_SORT_FORMAT))

        property_name, sort_order = sort_by.split(':')

        check_error_property_name_and_sort_order(command, property_name, sort_order)


def check_error_property_name_and_sort_order(command, property_name, sort_order):
    if (property_name[0].lower() + property_name[1:]) not in SUPPORTED_SORT[command]:
        message = ERROR_MESSAGE["UNSUPPORTED_FIELD_FOR_IOCS_LIST"] if command == "iocs_list" else ERROR_MESSAGE[
            "UNSUPPORTED_FIELD"]

        raise ValueError(
            message.format(property_name, 'property name', 'property name', ', '.join(SUPPORTED_SORT[command])))
    if sort_order.lower() not in SUPPORTED_SORT['order_by']:
        raise ValueError(
            ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(sort_order, 'sort order', 'sort order',
                                                      ', '.join(SUPPORTED_SORT['order_by'])))


def prepare_sort_query(sort_list, command):
    validate_sort(sort_list, command)
    sort_by = ''
    for sort_property_order in sort_list:
        sort_by += 'sort=' + sort_property_order + '&'

    sort_by = sort_by[:-1]
    sort_by = sort_by.replace(':', ',')
    return sort_by


def prepare_body_for_qurantine_jobs_list_command():
    filter_options = {}
    if orenctl.getArg('auto_quarantine'):
        filter_options["autoQuarantine"] = orenctl.getArg('auto_quarantine')

    if orenctl.getArg('include_status'):
        filter_options["includeStatus"] = orenctl.getArg('include_status')
        for status in filter_options["includeStatus"]:
            if status not in STATUS:
                raise ValueError(
                    ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(status, 'status', 'status', ', '.join(STATUS)))

    if orenctl.getArg('exclude_status'):
        filter_options["excludeStatus"] = orenctl.getArg('exclude_status')
        for status in filter_options["excludeStatus"]:
            if status not in STATUS:
                raise ValueError(
                    ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(status, 'status', 'status', ', '.join(STATUS)))


def prepare_requests_body_for_quarantine_job_create(quarantine_emails):
    data = []

    for email in quarantine_emails:
        if len(list(filter(None, email.split(":")))) != 2:
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(
                email, "quarantine_emails", SUPPORTED_QUARANTINE_EMAILS_FORMAT
            ))
        data.append({
            "recipientAddress": email.split(":")[1].strip(),
            "internetMessageId": email.split(":")[0].strip()
        })

    return {"quarantineEmails": data}


def validate_quarantine_job_id(id):
    validate_required_parameters(id=id)

    if arg_to_number(id, arg_name="id") <= 0:
        raise ValueError(ERROR_MESSAGE["INVALID_QUARANTINE_JOB_PARAM"].format("id"))


def is_missing_argument(arg, required):
    return arg in (None, '') and required


def create_missing_argument_message(arg_name):
    return f'Missing "{arg_name}"' if arg_name else 'Missing required argument'


def encode_string_results(text):
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def create_invalid_number_message(arg, arg_name):
    return f'Invalid number: "{arg_name}"="{arg}"' if arg_name else f'"{arg}" is not a valid number'


def convert_string_to_number(arg, arg_name):
    if arg.isdigit():
        return int(arg)
    try:
        return int(float(arg))
    except ValueError:
        raise ValueError(create_invalid_number_message(arg, arg_name))


def arg_to_number(arg, arg_name=None, required=False):
    if is_missing_argument(arg, required):
        raise ValueError(create_missing_argument_message(arg_name))

    arg = encode_string_results(arg)
    if isinstance(arg, str):
        return convert_string_to_number(arg, arg_name)
    elif isinstance(arg, int):
        return arg

    raise ValueError(create_invalid_number_message(arg, arg_name))


def validate_search_id(search_id):
    validate_required_parameters(id=search_id)
    if arg_to_number(search_id, arg_name="id") <= 0:
        raise ValueError(ERROR_MESSAGE['INVALID_SEARCH_ID'])


def validate_create_search_parameter_allowed_search_length(**kwargs):
    for key, value in kwargs.items():
        if len(value) > 3:
            raise ValueError(ERROR_MESSAGE['INVALID_SEARCH_LENGTH'].format(key))


def validate_arguments_for_message_search_create(**kwargs):
    validate_create_search_parameter_allowed_search_length(subjects=kwargs.get("subjects"),
                                                           senders=kwargs.get("senders"),
                                                           attachment_names=kwargs.get("attachment_names"),
                                                           attachment_hashes=kwargs.get("attachment_hashes"),
                                                           attachment_mime_types=kwargs.get("attachment_mime_types"),
                                                           attachment_exclude_mime_types=kwargs.get(
                                                               "attachment_exclude_mime_types"),
                                                           domains=kwargs.get("domains"),
                                                           whitelist_urls=kwargs.get("whitelist_urls"),
                                                           headers=kwargs.get("headers"))

    attachment_hash_criteria = kwargs.get('attachment_hash_criteria', 'ANY')
    if attachment_hash_criteria.upper() not in SUPPORTED_CRITERIA:
        raise ValueError(
            ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(attachment_hash_criteria, 'attachment_hash_match_criteria',
                                                      'attachment_hash_match_criteria', SUPPORTED_CRITERIA))

    domain_match_criteria = kwargs.get('domain_match_criteria', 'ANY')
    if domain_match_criteria.upper() not in SUPPORTED_CRITERIA:
        raise ValueError(
            ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(domain_match_criteria, 'domain_match_criteria',
                                                      'domain_match_criteria', SUPPORTED_CRITERIA))

    attachment_hashes = kwargs.get('attachment_hashes', [])
    for attachment_hash in attachment_hashes:
        if len(list(filter(None, attachment_hash.split(':')))) != 2:
            raise ValueError(
                ERROR_MESSAGE['INVALID_FORMAT'].format(attachment_hash, 'attachment_hashes',
                                                       SUPPORTED_HASH_VALUE_FORMAT))

        hash_type = attachment_hash.split(':')[0]
        hash_value = attachment_hash.split(':')[1]
        if hash_type.upper() not in SUPPORTED_HASH:
            raise ValueError(ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(hash_type, 'hash', 'hash', SUPPORTED_HASH))
        if hash_type.lower() != get_hash_type(hash_value):
            raise ValueError(ERROR_MESSAGE['INVALID_ARGUMENT'].format(hash_value, hash_type))

    headers = kwargs.get('headers', [])
    for header in headers:
        if len(list(filter(None, header.split(":")))) < 2:
            raise ValueError(ERROR_MESSAGE['INVALID_FORMAT'].format(header, 'headers', SUPPORTED_HEADERS_FORMAT))


def prepare_requests_body_for_message_search_create(**kwargs):
    attachment_hashes = []
    for attachment_hash in kwargs.get('attachment_hashes', []):
        attachment_hashes.append({
            "hashType": attachment_hash.split(":", 1)[0].upper(),
            "hashString": attachment_hash.split(":", 1)[1]
        })

    attachment_hash_criteria = {
        "type": kwargs.get('attachment_hash_match_criteria', 'ANY').upper(),
        "attachmentHashes": attachment_hashes
    }

    domain_criteria = {
        "type": kwargs.get('domain_match_criteria', 'ANY').upper(),
        "domains": kwargs.get('domains'),
        "whiteListUrls": kwargs.get('whitelist_urls')
    }

    headers = []
    for header in kwargs.get('headers', []):
        headers.append({
            "key": header.split(':', 1)[0],
            "values": header.split(':', 1)[1]
        })

    return assign_params(subjects=kwargs.get('subjects'), senders=kwargs.get('senders'),
                         attachmentNames=kwargs.get('attachment_names'),
                         attachmentHashCriteria=attachment_hash_criteria,
                         attachmentMimeTypes=kwargs.get('attachment_mime_types'),
                         attachmentExcludeMimeTypes=kwargs.get('attachment_exclude_mime_types'),
                         domainCriteria=domain_criteria, headers=headers,
                         internetMessageId=kwargs.get('internet_message_id'),
                         partialIngest=kwargs.get('partial_ingest'),
                         receivedAfterDate=kwargs.get('received_after_date'),
                         receivedBeforeDate=kwargs.get('received_before_date'),
                         recipient=kwargs.get('recipient'), url=kwargs.get('url'))


def prepare_context_for_message_search_results_get_command(response):
    context_data = {
        "Message": response.get('messages', []),
        **response.get('search', {})
    }
    return context_data


def validate_arguments_for_iocs_list(source, page, size):
    validate_required_parameters(source=source)
    validate_page_size(page_size=size)

    if int(page) < 0:
        raise ValueError(ERROR_MESSAGE["INVALID_PAGE_VALUE"])


def prepare_body_for_ioc_update(expires_at):
    updated_iocs = {
        "type": "ioc",
        "metadata": {
            "quarantine": {
                "expires_at": expires_at
            },
        }
    }
    return {"data": updated_iocs}


def prepare_and_validate_body_for_iocs_update(request_body):
    data = []
    for body in request_body:
        threat_type = body.get('threat_type')
        if threat_type and threat_type.lower() not in THREAT_TYPES:
            raise ValueError(
                ERROR_MESSAGE['UNSUPPORTED_FIELD'].format(threat_type, 'threat type', 'threat type', THREAT_TYPES))

        threat_value = body.get('threat_value')
        threat_level = body.get('threat_level')
        source_id = body.get('source_id')

        created_at = body.get('created_at')
        if created_at:
            created_at = arg_to_datetime(created_at, arg_name='created_at').strftime(DATE_FORMAT)  # type: ignore

        updated_at = body.get('updated_at')
        if updated_at:
            updated_at = arg_to_datetime(updated_at, arg_name='updated_at').strftime(DATE_FORMAT)  # type: ignore
        else:
            updated_at = datetime.now().strftime(DATE_FORMAT)

        requested_expiration = body.get('requested_expiration')
        if requested_expiration:
            requested_expiration = requested_expiration.strftime(DATE_FORMAT)

        validate_required_parameters(threat_type=threat_type, threat_value=threat_value,
                                     threat_level=threat_level, source_id=source_id, created_at=created_at,
                                     updated_at=updated_at)

        updated_ioc = {
            "type": "ioc",
            "attributes": {
                "threat_type": threat_type,
                "threat_value": threat_value
            },
            "metadata": {
                "source": {
                    "threat_level": threat_level,
                    "id": source_id,
                    "requested_expiration": requested_expiration,
                    "created_at": created_at,
                    "updated_at": updated_at
                },
            }
        }
        data.append(updated_ioc)

    return {"data": data}


class CofenseVision(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.threat_levels_good = orenctl.getParam("threat_levels_good") if orenctl.getParam(
            "threat_levels_good") else []
        self.threat_levels_suspicious = orenctl.getParam("threat_levels_suspicious") if orenctl.getParam(
            "threat_levels_suspicious") else []
        self.threat_levels_bad = orenctl.getParam("threat_levels_bad") if orenctl.getParam("threat_levels_bad") else []
        self.session = requests.session()
        self.session.headers = {}

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response

    def get_message(self, token):
        return self.http_request(method='GET', url_suffix=API_ENDPOINTS["GET_MESSAGE"], params={"token": token})

    def get_attachment(self, md5=None, sha256=None):
        params = assign_params(md5=md5, sha256=sha256)
        return self.http_request(method='GET', url_suffix=API_ENDPOINTS["GET_ATTACHMENT"], params=params)

    def quarantine_jobs_list(self, page, size, sort, exclude_quarantine_emails, body):
        query = f'?page={page}&size={size}&excludeQuarantineEmails={exclude_quarantine_emails}&{sort}'
        return self.http_request(method="POST", url_suffix=API_ENDPOINTS["GET_QUARANTINE_JOBS"] + query, json_data=body)

    def create_quarantine_job(self, requests_body):
        headers = {"Content-Type": APPLICATION_JSON, **self.session.headers}
        return self.http_request(method="POST", url_suffix=API_ENDPOINTS["QUARANTINE_JOB"], headers=headers,
                                 json_data=requests_body)

    def get_quarantine_job(self, job_id):
        return self.http_request(method="GET", url_suffix=API_ENDPOINTS["QUARANTINE_JOB"] + "/" + str(job_id))

    def get_search(self, search_id):
        return self.http_request(method="GET", url_suffix=API_ENDPOINTS["GET_MESSAGE_SEARCH"].format(search_id))

    def create_search(self, requests_body):
        return self.http_request(method="POST", url_suffix=API_ENDPOINTS["CREATE_MESSAGE_SEARCH"],
                                 json_data=requests_body)

    def get_search_results(self, search_id, page=None, size=None, sort=None):
        query = f'?page={page}&size={size}&{sort}'
        return self.http_request(method="GET", url_suffix=API_ENDPOINTS["GET_SEARCH_RESULTS"].format(search_id) + query)

    def list_iocs(self, source, page, size, include_expired, since, sort_string):
        headers = {"X-Cofense-IOC-Source": source, **self.session.headers}
        query = f"?page={page}&size={size}&includeExpired={include_expired}"
        if since:
            query += f"&since={since}"
        if sort_string:
            query += f"&{sort_string}"
        return self.http_request(method="GET", url_suffix=API_ENDPOINTS["GET_IOCS"] + query, headers=headers)

    def update_ioc(self, md5_id, body):
        headers = {"Content-Type": APPLICATION_JSON, **self.session.headers}
        return self.http_request(method="PUT", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"] + "/" + str(md5_id),
                                 headers=headers, json_data=body)

    def update_iocs(self, source, body):
        headers = {"Content-Type": APPLICATION_JSON, "X-Cofense-IOC-Source": source, **self.session.headers}
        return self.http_request(method="PUT", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"], headers=headers,
                                 json_data=body)

    def get_ioc(self, source, ioc_id):
        headers = {"X-Cofense-IOC-Source": source, **self.session.headers}
        return self.http_request(method="GET", url_suffix=API_ENDPOINTS["IOC_REPOSITORY"] + "/" + str(ioc_id),
                                 headers=headers)


def cofense_message_get_command():
    client = CofenseVision()
    token = orenctl.getArg("token")

    response = client.get_message(token)
    results = dict(filename='message.zip', data=response.content)
    return orenctl.results(results)


def cofense_message_attachment_get_command():
    client = CofenseVision()
    file_name = orenctl.getArg('file_name')
    md5 = orenctl.getArg('md5')
    sha256 = orenctl.getArg('sha256')

    validate_required_parameters(file_name=file_name, md5=md5)

    validate_params_for_attachment_get(md5, sha256)

    response = client.get_attachment(md5, sha256)

    results = dict(filename=file_name, data=response.content)
    return orenctl.results(results)


def cofense_quarantine_jobs_list_command():
    client = CofenseVision()
    exclude_quarantine_emails = orenctl.getArg('exclude_quarantine_emails') if orenctl.getArg(
        'exclude_quarantine_emails') else False

    page = orenctl.getArg('page') if orenctl.getArg('page') else 0
    if int(page) < 0:
        raise ValueError(ERROR_MESSAGE['INVALID_PAGE_VALUE'])

    size = orenctl.getArg('size') if orenctl.getArg('size') else 50
    validate_page_size(size)

    sort = prepare_sort_query(orenctl.getArg('sort') if orenctl.getArg('sort') else DEFAULT_SORT_VALUE,
                              'quarantine_jobs_list')

    body = prepare_body_for_qurantine_jobs_list_command()

    response = client.quarantine_jobs_list(
        page=page, size=size, sort=sort, exclude_quarantine_emails=exclude_quarantine_emails, body=body).json()

    return orenctl.results({"quarantine_jobs": response.get('quarantineJobs')})


def cofense_quarantine_job_create_command():
    client = CofenseVision()
    quarantine_emails = orenctl.getArg('quarantine_emails')
    validate_required_parameters(quarantine_emails=quarantine_emails)
    requests_body = prepare_requests_body_for_quarantine_job_create(quarantine_emails)

    response = client.create_quarantine_job(requests_body).json()

    return orenctl.results({"created_quarantine_job": response})


def cofense_quarantine_job_get_command():
    client = CofenseVision()
    job_id = orenctl.getArg('id') if orenctl.getArg('id') else ''
    validate_quarantine_job_id(id=job_id)

    response = client.get_quarantine_job(job_id=job_id).json()

    return orenctl.results({"got_quarantine_job": response})


def cofense_message_search_get_command():
    client = CofenseVision()
    search_id = orenctl.getArg('id') if orenctl.getArg('id') else ''
    validate_search_id(search_id)

    response = client.get_search(search_id).json()

    return orenctl.results({"search_results": response})


def cofense_message_search_create_command():
    client = CofenseVision()
    subjects = orenctl.getArg('subjects')
    senders = orenctl.getArg('senders')
    attachment_names = orenctl.getArg('attachment_names')
    attachment_hash_criteria = orenctl.getArg('attachment_hash_match_criteria') if orenctl.getArg(
        'attachment_hash_match_criteria') else 'ANY'
    attachment_hashes = orenctl.getArg('attachment_hashes')
    attachment_mime_types = orenctl.getArg('attachment_mime_types')
    attachment_exclude_mime_types = orenctl.getArg('attachment_exclude_mime_types')
    domain_match_criteria = orenctl.getArg('domain_match_criteria') if orenctl.getArg(
        'domain_match_criteria') else 'ANY'
    domains = orenctl.getArg('domains')
    whitelist_urls = orenctl.getArg('whitelist_urls')
    headers = orenctl.getArg('headers')
    internet_message_id = orenctl.getArg('internet_message_id')
    partial_ingest = orenctl.getArg('partial_ingest') if orenctl.getArg('partial_ingest') else False
    received_after_date = orenctl.getArg('received_after_date')
    received_before_date = orenctl.getArg('received_before_date')
    recipient = orenctl.getArg('recipient')
    url = orenctl.getArg('url')

    if received_after_date:
        received_after_date = received_after_date.strftime(DATE_FORMAT)

    if received_before_date:
        received_before_date = received_before_date.strftime(DATE_FORMAT)

    validate_arguments_for_message_search_create(subjects=subjects, senders=senders,
                                                 attachment_names=attachment_names,
                                                 attachment_hashes=attachment_hashes,
                                                 attachment_hash_criteria=attachment_hash_criteria,
                                                 domain_match_criteria=domain_match_criteria,
                                                 attachment_mime_types=attachment_mime_types,
                                                 attachment_exclude_mime_types=attachment_exclude_mime_types,
                                                 domains=domains, whitelist_urls=whitelist_urls,
                                                 headers=headers)

    body = prepare_requests_body_for_message_search_create(subjects=subjects, senders=senders,
                                                           attachment_names=attachment_names,
                                                           attachment_hash_match_criteria=attachment_hash_criteria,
                                                           attachment_hashes=attachment_hashes,
                                                           attachment_mime_types=attachment_mime_types,
                                                           attachment_exclude_mime_types=attachment_exclude_mime_types,
                                                           domain_match_criteria=domain_match_criteria,
                                                           domains=domains, whitelist_urls=whitelist_urls,
                                                           headers=headers, internet_message_id=internet_message_id,
                                                           partial_ingest=partial_ingest,
                                                           received_after_date=received_after_date,
                                                           received_before_date=received_before_date,
                                                           recipient=recipient, url=url)

    response = client.create_search(body).json()

    return orenctl.results({"created_search": response})


def cofense_message_search_results_get_command():
    client = CofenseVision()
    search_id = orenctl.getArg('id') if orenctl.getArg('id') else ''
    validate_search_id(search_id)

    page = orenctl.getArg('page') if orenctl.getArg('page') else 0
    size = orenctl.getArg('size') if orenctl.getArg('size') else 50

    if int(page) < 0:
        raise ValueError(ERROR_MESSAGE['INVALID_PAGE_VALUE'])
    validate_page_size(size)

    sort = prepare_sort_query(
        orenctl.getArg('sort') if orenctl.getArg('sort') else DEFAULT_SORT_VALUE, "message_search_result_get")

    response = client.get_search_results(search_id=search_id, page=page, size=size, sort=sort).json()
    context_data = prepare_context_for_message_search_results_get_command(response)

    return orenctl.results({"search_results": context_data})


def cofense_iocs_list_command():
    client = CofenseVision()
    source = orenctl.getArg("source") if orenctl.getArg("source") else ""
    page = arg_to_number(orenctl.getArg("page") if orenctl.getArg("page") else 0, arg_name="page")
    size = arg_to_number(orenctl.getArg("size") if orenctl.getArg("size") else 50, arg_name="size")
    validate_arguments_for_iocs_list(source=source, page=page, size=size)

    include_expired = orenctl.getArg("include_expired") if orenctl.getArg("include_expired") else False
    since = orenctl.getArg("since")
    sort = prepare_sort_query(orenctl.getArg("sort") if orenctl.getArg("sort") else "", command="iocs_list")

    if since:
        since = since.strftime(DATE_FORMAT)

    response = client.list_iocs(source=source, page=page, size=size, since=since,
                                include_expired=include_expired, sort_string=sort).json()

    return orenctl.results({"list_iocs": response.get('data')})


def cofense_ioc_update_command():
    client = CofenseVision()
    md5_id = orenctl.getArg('id')
    expires_at = orenctl.getArg('expires_at')
    if expires_at:
        expires_at = expires_at.strftime(DATE_FORMAT)

    validate_required_parameters(id=md5_id, expires_at=expires_at)

    body = prepare_body_for_ioc_update(expires_at)

    response = client.update_ioc(md5_id, body).json()

    return orenctl.results({"updated_ioc": response.get('data', {})})


def cofense_iocs_update_command():
    client = CofenseVision()
    source = orenctl.getArg('source')
    iocs_json = orenctl.getArg('iocs_json')
    if not iocs_json:
        iocs_json = json.dumps([{
            "threat_type": orenctl.getArg("threat_type"),
            "threat_value": orenctl.getArg("threat_value"),
            "threat_level": orenctl.getArg("threat_level"),
            "source_id": orenctl.getArg("source_id"),
            "created_at": orenctl.getArg("created_at"),
            "updated_at": orenctl.getArg("updated_at"),
            "requested_expiration": orenctl.getArg("requested_expiration")
        }])
    validate_required_parameters(iocs_json=iocs_json, source=source)

    try:
        iocs_json = json.loads(iocs_json)
        if isinstance(iocs_json, dict):
            iocs_json = [iocs_json]
    except json.JSONDecodeError:
        raise ValueError('{} is an invalid JSON format'.format(iocs_json))

    body = prepare_and_validate_body_for_iocs_update(iocs_json)

    response = client.update_iocs(source, body).json()

    return orenctl.results({"updated_iocs": response.get('data', [])})


def cofense_ioc_get_command():
    client = CofenseVision()
    md5_id = orenctl.getArg('id')
    source = orenctl.getArg('source')

    validate_required_parameters(id=md5_id)

    response = client.get_ioc(source, md5_id).json()

    return orenctl.results({"got_ioc": response.get('data', {})})


if orenctl.command() == "cofense_message_get":
    cofense_message_get_command()
elif orenctl.command() == "cofense_message_attachment_get":
    cofense_message_attachment_get_command()
elif orenctl.command() == "cofense_quarantine_jobs_list":
    cofense_quarantine_jobs_list_command()
elif orenctl.command() == "cofense_quarantine_job_create":
    cofense_quarantine_job_create_command()
elif orenctl.command() == "cofense_quarantine_job_get":
    cofense_quarantine_job_get_command()
elif orenctl.command() == "cofense_message_search_get":
    cofense_message_search_get_command()
elif orenctl.command() == "cofense_message_search_create":
    cofense_message_search_create_command()
elif orenctl.command() == "cofense_message_search_results_get":
    cofense_message_search_results_get_command()
elif orenctl.command() == "cofense_iocs_list":
    cofense_iocs_list_command()
elif orenctl.command() == "cofense_ioc_update":
    cofense_ioc_update_command()
elif orenctl.command() == "cofense_iocs_update":
    cofense_iocs_update_command()
elif orenctl.command() == "cofense_ioc_get":
    cofense_ioc_get_command()
