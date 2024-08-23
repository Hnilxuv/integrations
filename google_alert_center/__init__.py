import json
import os
import sys
import urllib.parse
from typing import Dict, Optional, List, Any, Tuple
import httplib2
from google.oauth2 import service_account
from google_auth_httplib2 import AuthorizedHttp
from google.auth import exceptions
import requests
import orenctl

SCOPES: Dict[str, List[str]] = {
    'ALERT': ['https://www.googleapis.com/auth/apps.alerts']
}

IS_PY3 = sys.version_info[0] == 3

if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)

else:
    STRING_TYPES = (str, unicode)  # type: ignore # noqa: F821

    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore

ALERT_FEEDBACK_TYPES = ['alert_feedback_type_unspecified', 'not_useful', 'somewhat_useful', 'very_useful']
LIST_FEEDBACK_PAGE_SIZE = 50

URL_SUFFIX: Dict[str, str] = {
    'LIST_ALERTS': 'v1beta1/alerts',
    'FEEDBACK': 'v1beta1/alerts/{0}/feedback',
    'GET_ALERT': 'v1beta1/alerts/{}',
    'BATCH_DELETE': 'v1beta1/alerts:batchDelete',
    'BATCH_RECOVER': 'v1beta1/alerts:batchUndelete'
}

OUTPUT_PATHS = {
    'ALERT': 'GSuiteSecurityAlert.Alert(val.alertId == obj.alertId)',
    'TOKEN': 'GSuiteSecurityAlert.PageToken.Alert(val.name == val.name)',
    'FEEDBACK': 'GSuiteSecurityAlert.Feedback',
    'BATCH_DELETE_SUCCESS': 'GSuiteSecurityAlert.Delete.successAlerts(val.id && val.id == obj.id)',
    'BATCH_DELETE_FAILED': 'GSuiteSecurityAlert.Delete.failedAlerts(val.id && val.id == obj.id)',
    'BATCH_RECOVER_SUCCESS': 'GSuiteSecurityAlert.Recover.successAlerts(val.id && val.id == obj.id)',
    'BATCH_RECOVER_FAILED': 'GSuiteSecurityAlert.Recover.failedAlerts(val.id && val.id == obj.id)'
}

MESSAGES = {
    'NO_RECORDS_FOUND': "No {} were found for the given argument(s).",
    "API_TOKEN": "No API token found. Please try again.",
    "PAGE_SIZE": "{} is an invalid value for page size. Page size must be between 1 and 200.",
    "PAGE_NUMBER": "{} is an invalid value for page number. Page number must be greater than 0",
    "FILTER": 'Please provide the filter in the valid JSON format. Format accepted- \' '
              '{"attribute1_operator" : "value1, value2" , "attribute2_operator" : "value3, value4"} \'',
    "REQUIRED_ARGUMENT": "Invalid argument value. {} is a required argument.",
    "INVALID_MAX_FETCH": "{} is an invalid value for maximum fetch. Maximum fetch must be between 1 and 200.",
    "INVALID_FIRST_FETCH": "Argument 'First fetch time interval' should be a valid date or relative timestamp such as "
                           "'2 days', '2 months', 'yyyy-mm-dd', 'yyyy-mm-ddTHH:MM:SSZ'",
    "INVALID_LOCATION_FOR_CATEGORY_ID": "If Category ID is provided in fetch incident parameters, the Report Location "
                                        "cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_CATEGORIZATION_TAGS": "If Categorization Tags are provided in fetch incident parameters, "
                                                "the Report Location cannot be 'Inbox' or 'Reconnaissance'.",
    "INVALID_LOCATION_FOR_TAGS": "If Tags are provided in fetch incident parameters, the Report Location "
                                 "must be 'Reconnaissance'.",
    "BODY_FORMAT": "Invalid value for body format. Body format must be text or json.",
    "INTEGRATION_SUBMISSION_TYPE": "Invalid value for integration submission type. Type must be urls or "
                                   "attachment_payloads.",
    "INVALID_IMAGE_TYPE": "Invalid value for type. Type must be png or jpg.",
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'MISSING_REQUIRED_ARGUMENTS_ERROR': 'Missing required arguments error.',
}

COMMON_MESSAGES: Dict[str, str] = {
    'TIMEOUT_ERROR': 'Connection Timeout Error - potential reasons might be that the Server URL parameter'
                     ' is incorrect or that the Server is not accessible from your host. Reason: {}',
    'HTTP_ERROR': 'HTTP Connection error occurred. Status: {}. Reason: {}',
    'TRANSPORT_ERROR': 'Transport error occurred. Reason: {}',
    'AUTHENTICATION_ERROR': 'Unauthenticated. Check the configured Service Account JSON. Reason: {}',
    'BAD_REQUEST_ERROR': 'An error occurred while fetching/submitting the data. Reason: {}',
    'TOO_MANY_REQUESTS_ERROR': 'Too many requests please try after sometime. Reason: {}',
    'INTERNAL_SERVER_ERROR': 'The server encountered an internal error. Reason: {}',
    'AUTHORIZATION_ERROR': 'Request has insufficient privileges. Reason: {}',
    'JSON_PARSE_ERROR': 'Unable to parse JSON string. Please verify the JSON is valid.',
    'NOT_FOUND_ERROR': 'Not found. Reason: {}',
    'UNKNOWN_ERROR': 'An error occurred. Status: {}. Reason: {}',
    'PROXY_ERROR': 'Proxy Error - if the \'Use system proxy\' checkbox in the integration configuration is'
                   ' selected, try clearing the checkbox.',
    'REFRESH_ERROR': 'Failed to generate/refresh token. Subject email or service account credentials'
                     ' are invalid. Reason: {}',
    'BOOLEAN_ERROR': 'The argument {} must be either true or false.',
    'INTEGER_ERROR': 'The argument {} must be a positive integer.',
    'UNEXPECTED_ERROR': 'An unexpected error occurred.',
}


def argToList(arg, separator=',', transform=None):
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
            except ValueError:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result


def validate_get_int(max_results: Optional[str], message: str, limit: int = 0):
    if max_results:
        try:
            max_results_int = int(max_results)
            if max_results_int <= 0:
                raise ValueError
            if limit and max_results_int > limit:
                raise ValueError
            return max_results_int
        except ValueError:
            raise ValueError(message)
    return None


def validate_params_for_list_alerts():
    gac = GoogleAlertCenter(None)
    page_size = orenctl.getArg('page_size') if orenctl.getArg('page_size') else ''
    page_size = int(page_size) if page_size == '0' else \
        validate_get_int(page_size, message=MESSAGES['INTEGER_ERROR'].format('page_size'))

    alert_filter = orenctl.getArg('filter') if orenctl.getArg('filter') else ''
    if alert_filter:
        alert_filter = alert_filter.replace("'", '"')

    params = {
        'pageToken': orenctl.getArg('page_token') if orenctl.getArg('page_token') else '',
        'pageSize': page_size,
        'filter': alert_filter,
        'orderBy': orenctl.getArg('order_by') if orenctl.getArg('order_by') else ''
    }

    return remove_empty_entities(params)


def skip_proxy():
    for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'):
        if k in os.environ:
            del os.environ[k]


def skip_cert_verification():
    for k in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        if k in os.environ:
            del os.environ[k]


def get_proxies():
    return {
        'http': os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy', ''),
        'https': os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy', '')
    }


def should_use_proxy(proxy_param_name, checkbox_default_value):
    param_value = orenctl.getParam(proxy_param_name)
    return param_value if param_value is not None else checkbox_default_value


def should_skip_cert_verification(insecure_param_name):
    param_names = (insecure_param_name,) if insecure_param_name else ('insecure', 'unsecure')
    return any(orenctl.getParam(p) for p in param_names)


def handle_proxy(proxy_param_name='proxy', checkbox_default_value=False, handle_insecure=True,
                 insecure_param_name=None):
    if should_use_proxy(proxy_param_name, checkbox_default_value):
        proxies = get_proxies()
    else:
        skip_proxy()
        proxies = {}

    if handle_insecure and should_skip_cert_verification(insecure_param_name):
        skip_cert_verification()

    return proxies


def urljoin(url, suffix=""):
    if not url.endswith("/"):
        url += "/"

    if suffix.startswith("/"):
        suffix = suffix[1:]

    return url + suffix


def check_required_arguments(required_arguments, args):
    missing_args = []
    for arg in required_arguments:
        if arg not in args.keys():
            missing_args.append(arg)
    if len(missing_args) > 0:
        raise ValueError(MESSAGES['MISSING_REQUIRED_ARGUMENTS_ERROR'].format(", ".join(missing_args)))


def create_custom_context_for_batch_command(response: Dict[str, Any]):
    success_list: List = []
    failed_list: List = []
    for each_id in response.get('successAlertIds', []):
        success_obj: Dict[str, Any] = {
            'id': each_id,
            'status': 'Success'
        }
        success_list.append(success_obj)

    for failed_key, value in response.get('failedAlertStatus', {}).items():
        failed_alert_id: Dict[str, Any] = {
            'id': failed_key,
            'status': 'Fail',
            'code': value.get('code'),
            'message': value.get('message', '')
        }
        failed_list.append(failed_alert_id)

    return success_list, failed_list


def safe_load_non_strict_json(json_string: str):
    try:
        if json_string:
            return json.loads(json_string, strict=False)
        return {}
    except ValueError:
        raise ValueError(COMMON_MESSAGES['JSON_PARSE_ERROR'])


def http_exception_handler():
    try:
        yield
    except httplib2.socks.HTTPError as error:
        handle_http_error(error)
    except exceptions.TransportError as error:
        if 'proxyerror' in str(error).lower():
            raise Exception(COMMON_MESSAGES['PROXY_ERROR'])
        raise Exception(COMMON_MESSAGES['TRANSPORT_ERROR'].format(error))
    except exceptions.RefreshError as error:
        if error.args:
            raise Exception(COMMON_MESSAGES['REFRESH_ERROR'].format(error.args[0]))
        raise Exception(error)
    except TimeoutError as error:
        raise Exception(COMMON_MESSAGES['TIMEOUT_ERROR'].format(error))
    except Exception as error:
        raise Exception(error)


def handle_http_error(error: httplib2.socks.HTTPError):
    if error.args and isinstance(error.args[0], tuple):
        error_status, error_msg = error.args[0][0], error.args[0][1].decode()
        if error_status == 407:  # Proxy Error
            raise Exception(COMMON_MESSAGES['PROXY_ERROR'])
        raise Exception(COMMON_MESSAGES['HTTP_ERROR'].format(error_status, error_msg))
    raise Exception(error)


def validate_and_extract_response(response: Tuple[httplib2.Response, Any]) -> Dict[str, Any]:
    if response[0].status == 200 or response[0].status == 204:
        return safe_load_non_strict_json(response[1])

    status_code_message_map = {
        400: COMMON_MESSAGES['BAD_REQUEST_ERROR'],
        401: COMMON_MESSAGES['AUTHENTICATION_ERROR'],
        403: COMMON_MESSAGES['AUTHORIZATION_ERROR'],
        404: COMMON_MESSAGES['NOT_FOUND_ERROR'],
        429: COMMON_MESSAGES['TOO_MANY_REQUESTS_ERROR'],
        500: COMMON_MESSAGES['INTERNAL_SERVER_ERROR']
    }

    try:
        orenctl.error(response[1].decode() if type(response[1]) is bytes else response[1])
        message = safe_load_non_strict_json(response[1]).get('error', {}).get('message', '')
    except ValueError:
        message = COMMON_MESSAGES['UNEXPECTED_ERROR']

    if response[0].status in status_code_message_map:
        raise Exception(status_code_message_map[response[0].status].format(message))
    else:
        raise Exception(COMMON_MESSAGES['UNKNOWN_ERROR'].format(response[0].status, message))


def remove_empty_entities(d):
    def empty(x):
        return x is None or x == {} or x == [] or x == ''

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [value for value in (remove_empty_entities(value) for value in d) if not empty(value)]
    else:
        return {key: value for key, value in ((key, remove_empty_entities(value))
                                              for key, value in d.items()) if not empty(value)}


def set_authorized_http(scopes: List[str], subject: Optional[str] = None, timeout: int = 60):
    gac = GoogleAlertCenter(None)
    gac.credentials = gac.credentials.with_scopes(scopes)
    if subject:
        gac.credentials = gac.credentials.with_subject(subject)
    authorized_http = AuthorizedHttp(credentials=gac.credentials,
                                     http=get_http_client(gac.proxy, gac.verify, timeout=timeout))
    gac.authorized_http = authorized_http


def get_http_client(proxy: bool, verify: bool, timeout: int = 60):
    proxy_info = {}
    proxies = handle_proxy()
    if proxy:
        https_proxy = proxies['https']
        if not https_proxy.startswith('https') and not https_proxy.startswith('http'):
            https_proxy = 'https://' + https_proxy
        parsed_proxy = urllib.parse.urlparse(https_proxy)
        proxy_info = httplib2.ProxyInfo(
            proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
            proxy_host=parsed_proxy.hostname,
            proxy_port=parsed_proxy.port,
            proxy_user=parsed_proxy.username,
            proxy_pass=parsed_proxy.password)

    return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=not verify, timeout=timeout)


class GoogleAlertCenter(object):
    def __init__(self, service_account_dict):
        self.url = orenctl.getParam("url")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        self.admin_email = orenctl.getParam("admin_email")
        self.credentials = service_account.Credentials.from_service_account_info(info=service_account_dict)
        self.maximum = 1000
        self.base_url = ''
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)
        self.verify = True
        self.authorized_http = None

    def http_request(self, url_suffix: str = None, params: Optional[Dict[str, Any]] = None,
                     method: str = 'GET',
                     body=None, full_url=None):
        encoded_params = f'?{urllib.parse.urlencode(params)}' if params else ''

        url = full_url

        if url_suffix:
            url = urljoin(self.base_url, url_suffix)

        url = f'{url}{encoded_params}'

        body = json.dumps(body) if body else None

        with http_exception_handler():
            response = self.authorized_http.request(headers=self.session.headers, method=method, uri=url, body=body)
            return validate_and_extract_response(response)


def gsac_list_alerts_command():
    gac = GoogleAlertCenter(None)
    admin_email = orenctl.getArg('admin_email')
    params = validate_params_for_list_alerts()

    set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    response = gac.http_request(url_suffix=URL_SUFFIX['LIST_ALERTS'], method='GET', params=params)

    total_records = response.get('alerts', [])
    if not total_records:
        orenctl.results({
            "readable_output": MESSAGES['NO_RECORDS_FOUND'].format('alert(s)')
        })

    token_ec = {}

    if response.get('nextPageToken'):
        token_ec = {'name': 'gsac-alert-list', 'nextPageToken': response.get('nextPageToken')}

    output = {
        OUTPUT_PATHS['ALERT']: total_records,
        OUTPUT_PATHS['TOKEN']: token_ec
    }

    output = remove_empty_entities(output)

    orenctl.results({
        "outputs": output,
        "raw_response": response
    })


def gsac_get_alert_command():
    args = {
        "admin_email": orenctl.getArg('admin_email'),
        "alert_id": orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else ''
    }
    gac = GoogleAlertCenter(None)
    check_required_arguments(required_arguments=['alert_id'], args=args)

    admin_email = args.get('admin_email')
    alert_id = args.get('alert_id')

    set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    response = gac.http_request(url_suffix=URL_SUFFIX['GET_ALERT'].format(alert_id), method='GET')

    if not response:
        orenctl.results({
            "readable_output": MESSAGES['NO_RECORDS_FOUND'].format('alert')
        })

    custom_ec_for_alerts = remove_empty_entities(response)

    orenctl.results({
        "outputs_prefix": 'GSuiteSecurityAlert.Alert',
        "outputs_key_field": 'alertId',
        "outputs": custom_ec_for_alerts,
        "raw_response": response
    })


def gsac_create_alert_feedback_command():
    args = {
        "alert_id": orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else '',
        "feedback_type": orenctl.getArg('feedback_type'),
    }
    gac = GoogleAlertCenter(None)
    check_required_arguments(required_arguments=['alert_id', 'feedback_type'], args=args)

    json_body: Dict[str, Any] = {}
    params: Dict[str, Any] = {}
    admin_email =  orenctl.getArg('admin_email')

    if args['feedback_type'].lower() not in ALERT_FEEDBACK_TYPES:
        raise ValueError(MESSAGES['INVALID_FEEDBACK_TYPE_ERROR'])

    json_body['type'] = args['feedback_type']

    set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    create_feedback_response = gac.http_request(
        url_suffix=URL_SUFFIX['FEEDBACK'].format(args['alert_id']),
        method='POST', body=json_body, params=params)

    custom_ec = remove_empty_entities(create_feedback_response)

    orenctl.results({
        "outputs_prefix": OUTPUT_PATHS['FEEDBACK'],
        "outputs_key_field": 'feedbackId',
        "outputs": custom_ec,
        "raw_response": create_feedback_response
    })


def gsac_list_alert_feedback_command():
    gac = GoogleAlertCenter(None)
    args = {
        "alert_id": orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else ''
    }
    check_required_arguments(required_arguments=['alert_id'], args=args)

    params: Dict[str, Any] = {
        'filter': (orenctl.getArg('filter') if orenctl.getArg('filter') else '').replace("'", '"'),
    }
    admin_email = orenctl.getArg('admin_email')
    page_size = (orenctl.getArg('page_size') if orenctl.getArg('page_size') else LIST_FEEDBACK_PAGE_SIZE)
    page_size = validate_get_int(page_size, message=MESSAGES['INTEGER_ERROR'].format('page_size'))

    set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    list_alert_feedback_response = gac.http_request(
        url_suffix=URL_SUFFIX['FEEDBACK'].format(args['alert_id']),
        method='GET',
        params=remove_empty_entities(params))

    no_records = len(list_alert_feedback_response.get('feedback', [])) == 0
    if no_records:
        orenctl.results({
            "readable_output": MESSAGES['NO_RECORDS_FOUND'].format('feedback(s)')
        })

    list_alert_feedback_response["feedback"] = list_alert_feedback_response["feedback"][0:page_size]

    custom_ec = remove_empty_entities(list_alert_feedback_response["feedback"])

    orenctl.results({
        "outputs_prefix": OUTPUT_PATHS['FEEDBACK'],
        "outputs_key_field": 'feedbackId',
        "outputs": custom_ec,
        "raw_response": list_alert_feedback_response
    })


def gsac_batch_recover_alerts_command():
    gac = GoogleAlertCenter(None)
    args = {
        "alert_id": orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else ''
    }
    check_required_arguments(required_arguments=['alert_id'], args=args)

    json_body: Dict[str, Any] = {}
    admin_email = orenctl.getArg('admin_email')

    ids = argToList((orenctl.getArg('alert_id') if orenctl.getArg('alert_id') else []), ",")

    json_body['alertId'] = ids

    set_authorized_http(scopes=SCOPES['ALERT'], subject=admin_email)
    batch_recover_response = gac.http_request(url_suffix=URL_SUFFIX['BATCH_RECOVER'], method='POST',
                                              body=json_body)

    success_list, failed_list = create_custom_context_for_batch_command(batch_recover_response)
    custom_context: Dict[str, Any] = {
        OUTPUT_PATHS['BATCH_RECOVER_SUCCESS']: success_list,
        OUTPUT_PATHS['BATCH_RECOVER_FAILED']: failed_list
    }

    orenctl.results({
        'outputs': remove_empty_entities(custom_context),
        "raw_response": batch_recover_response
    })


if orenctl.command() == "gsac_alert_list":
    gsac_list_alerts_command()
elif orenctl.command() == "gsac_alert_get":
    gsac_get_alert_command()
elif orenctl.command() == "gsac_alert_feedback_create":
    gsac_create_alert_feedback_command()
elif orenctl.command() == "gsac_alert_feedback_list":
    gsac_list_alert_feedback_command()
elif orenctl.command() == "gsac_alert_recover":
    gsac_batch_recover_alerts_command()
