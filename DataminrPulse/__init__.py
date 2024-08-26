import json
import logging
from functools import reduce
from operator import concat

import requests
from requests import HTTPError

import orenctl

OUTPUT_PREFIX_WATCHLISTS = 'DataminrPulse.WatchLists'

ENDPOINTS = {
    'AUTH_ENDPOINT': '/auth/2/token',
    'WATCHLISTS_ENDPOINT': '/account/2/get_lists',
    'ALERTS_ENDPOINT': '/api/3/alerts',
    'RELATED_ALERTS_ENDPOINT': 'alerts/2/get_related'
}
OUTPUT_PREFIX_ALERTS = 'DataminrPulse.Alerts'
OUTPUT_PREFIX_CURSOR = 'DataminrPulse.Cursor'

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE = 40
MAX_NUMBER_OF_ALERTS_TO_RETRIEVE = 3333
ERRORS = {
    'INVALID_JSON_OBJECT': 'Failed to parse json object from response: {}.',
    'UNAUTHORIZED_REQUEST': 'Unauthorized request: {}.',
    'GENERAL_AUTH_ERROR': 'Error occurred while creating an authorization token. '
                          'Please check the Client ID, Client Secret {}.',
    'NOT_MATCHED_WATCHLIST_NAMES': 'No matching watchlist data was found for the watchlist names configured in the '
                                   'instance.',
    'INVALID_MAX_NUM': ''.join(('{} is invalid value for num. Value of num should be between 0 to ',
                                str(MAX_NUMBER_OF_ALERTS_TO_RETRIEVE), '.')),
    'INVALID_MAX_FETCH': '{} is invalid value for max_fetch. Value of max_fetch should be greater than or equal to 0.',
    'AT_LEAST_ONE_REQUIRED': 'At least {} or {} is required.',
    'EITHER_ONE_REQUIRED': 'Either {} or {} is required.',
    'INVALID_REQUIRED_PARAMETER': '{} is a required field. Please provide correct input.'
}
ALERT_VERSION = 14


def transform_watchlists_data(watchlists_data):
    list_of_watchlists = watchlists_data.get('watchlists', {}).values()
    list_of_watchlists = list(list_of_watchlists)
    list_of_watchlists = reduce(concat, list_of_watchlists)
    return list_of_watchlists


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


def encode_string_results(text):
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def raise_value_error(arg_name, arg, message):
    if arg_name:
        raise ValueError(f'{message}: "{arg_name}"="{arg}"')
    else:
        raise ValueError(f'{message}: "{arg}"')


def convert_to_number(arg, arg_name):
    if isinstance(arg, str) and arg.isdigit():
        return int(arg)

    try:
        return int(float(arg))
    except Exception:
        raise_value_error(arg_name, arg, 'Invalid number')


def arg_to_number(arg, arg_name=None, required=False):
    if not arg:
        if required:
            raise_value_error(arg_name, arg, 'Missing required argument')
        return None

    arg = encode_string_results(arg)

    if isinstance(arg, (str, int)):
        return convert_to_number(arg, arg_name)

    raise_value_error(arg_name, arg, 'Invalid number')


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


def get_watchlist_ids(client, watchlist_names):
    watchlists_data = transform_watchlists_data(client.get_watchlists())
    filtered_watchlists_data = list(filter(
        lambda watchlist_data: watchlist_data.get('name') in watchlist_names,  # type: ignore
        watchlists_data)) if watchlist_names else watchlists_data
    if not filtered_watchlists_data:
        logging.debug(
            'No matching watchlist data was found for the "{}" watchlist names configured in the instance.'.format(
                watchlist_names))
        return []
    watchlist_ids = [watchlist_data.get('id') for watchlist_data in filtered_watchlists_data]
    watchlist_ids = list(filter(None, watchlist_ids))
    return watchlist_ids


def validate_params_for_alerts_get(watchlist_ids, watchlist_names, query, _from, to,
                                   num=DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE, use_configured_watchlist_names=True,
                                   is_fetch=False):
    if is_fetch:
        if num < 0:
            raise ValueError(ERRORS['INVALID_MAX_FETCH'].format(num))
    elif MAX_NUMBER_OF_ALERTS_TO_RETRIEVE < num or num < 0:
        raise ValueError(ERRORS['INVALID_MAX_NUM'].format(num, MAX_NUMBER_OF_ALERTS_TO_RETRIEVE))
    if not watchlist_ids and not query:
        if use_configured_watchlist_names:
            if is_fetch or watchlist_names:
                raise ValueError(ERRORS['NOT_MATCHED_WATCHLIST_NAMES'])
            raise ValueError(
                ERRORS['AT_LEAST_ONE_REQUIRED'].format('query', 'watchlist_names configured in integration'))
        raise ValueError(
            ERRORS['AT_LEAST_ONE_REQUIRED'].format('query', 'watchlist_ids'))
    if _from and to:
        raise ValueError(ERRORS['EITHER_ONE_REQUIRED'].format('from', 'to'))


def remove_nulls_from_dictionary(data):
    list_of_keys = list(data.keys())[:]
    for key in list_of_keys:
        if data[key] in ('', None, [], {}, ()):
            del data[key]


def remove_empty_elements(data):
    return [item for item in data if item]


def validate_params_for_related_alerts_get_command(alert_id):
    if not alert_id:
        raise ValueError(ERRORS['INVALID_REQUIRED_PARAMETER'].format('alert_id'))


class DataminrPulse(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.client_id = orenctl.getParam("client_id")
        self.client_secret = orenctl.getParam("client_secret")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.watchlist_names = orenctl.getParam("watchlist_names ")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_watchlists(self):
        return self.http_request(method='GET', url_suffix=ENDPOINTS['WATCHLISTS_ENDPOINT'])

    def get_alerts(self, watchlist_ids, query, _from, to, num=DEFAULT_NUMBER_OF_ALERTS_TO_RETRIEVE):
        params = {'num': num, 'alertversion': ALERT_VERSION, 'from': _from, 'to': to, 'query': query,
                  'application': 'palo_alto_cortex_xsoar'}

        remove_nulls_from_dictionary(params)
        if watchlist_ids:
            params['lists'] = ','.join(map(str, watchlist_ids))
        return self.http_request(method='GET', url_suffix=ENDPOINTS['ALERTS_ENDPOINT'], params=params)

    def get_related_alerts(self, alert_id, include_root):
        params = {
            'alertversion': ALERT_VERSION,
            'id': alert_id,
            'includeRoot': include_root
        }
        return self.http_request(
            method='GET', url_suffix=ENDPOINTS['RELATED_ALERTS_ENDPOINT'], params=params)


def dataminrpulse_watchlists_get_command():
    client = DataminrPulse()
    raw_lists_resp = client.get_watchlists()
    list_of_watchlists = transform_watchlists_data(raw_lists_resp)
    result = {
        "outputs_prefix": OUTPUT_PREFIX_WATCHLISTS,
        "outputs_key_field": 'id',
        "outputs": list_of_watchlists,
        "raw_response": raw_lists_resp
    }
    orenctl.results(result)


def dataminrpulse_alerts_get():
    client = DataminrPulse()
    watchlist_names = arg_to_list(orenctl.getArg('watchlist_names') if orenctl.getArg('watchlist_names') else '')
    watchlist_ids = arg_to_list(orenctl.getArg('watchlist_names') if orenctl.getArg('watchlist_names') else '')
    query = orenctl.getArg('query') if orenctl.getArg('query') else ''
    _from = orenctl.getArg('from') if orenctl.getArg('from') else ''
    to = orenctl.getArg('to') if orenctl.getArg('to') else ''
    num = arg_to_number(orenctl.getArg('num') if orenctl.getArg('num') else '40', arg_name='num')
    use_configured_watchlist_names = arg_to_boolean(
        orenctl.getArg('use_configured_watchlist_names') if orenctl.getArg(
            'use_configured_watchlist_names') else 'yes')

    if use_configured_watchlist_names and not watchlist_ids:
        watchlist_ids = get_watchlist_ids(client, watchlist_names)

    validate_params_for_alerts_get(watchlist_ids=watchlist_ids, watchlist_names=watchlist_names, query=query,
                                   _from=_from, to=to, num=num,
                                   use_configured_watchlist_names=use_configured_watchlist_names)

    response = client.get_alerts(watchlist_ids, query, _from, to, num)
    alert_response = response.get('data', {}).get('alerts', [])
    alert_valid_response = remove_empty_elements(alert_response)

    _from = response.get('data', {}).get('from', '')
    to = response.get('data', {}).get('to', '')
    cursor_response = {'from': _from, 'to': to}
    cursor_valid_response = remove_empty_elements(cursor_response)

    alert_results = {
        "outputs_prefix": OUTPUT_PREFIX_ALERTS,
        "outputs_key_field": 'alertId',
        "outputs": alert_valid_response,
        "raw_response": alert_response,
    }

    cursor_results = {
        "outputs_prefix": OUTPUT_PREFIX_CURSOR,
        "outputs_key_field": ['from', 'to'],
        "outputs": cursor_valid_response,
        "raw_response": cursor_response,
    }

    results = [alert_results, cursor_results]
    orenctl.results(results)


def dataminrpulse_related_alerts_get_command():
    client = DataminrPulse()
    alert_id = orenctl.getArg('alert_id')
    include_root = arg_to_boolean(orenctl.getArg('include_root'))

    validate_params_for_related_alerts_get_command(alert_id=alert_id)

    alerts = client.get_related_alerts(alert_id=alert_id, include_root=include_root)

    validate_response = remove_empty_elements(alerts)

    results = {
        "outputs_prefix": OUTPUT_PREFIX_ALERTS,
        "outputs_key_field": 'alertId',
        "outputs": validate_response,
        "raw_response": alerts
    }
    orenctl.results(results)


if orenctl.command() == "dataminrpulse_watchlists_get":
    dataminrpulse_watchlists_get_command()
elif orenctl.command() == "dataminrpulse_alerts_get":
    dataminrpulse_alerts_get()
elif orenctl.command() == "dataminrpulse_related_alerts_get":
    dataminrpulse_related_alerts_get_command()
