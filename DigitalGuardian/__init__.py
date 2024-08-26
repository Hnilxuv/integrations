import json
import logging

import requests
from requests import HTTPError

import orenctl

AUTH_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded'}
CLIENT_HEADERS = {'Authorization': ''}
WATCH_LIST = '/watchlists/'
ERROR = 'Please provide both watchlist_name and watchlist_entry'


def check_componentlist(componentlist):
    if componentlist:
        results = {
            "readable_output": 'Componentlist found',
            "outputs": {'DigitalGuardian.Componentlist.Found': True},
            "raw_response": 'Componentlist entry not found'
        }
        orenctl.results(results)
    else:
        results = {
            "readable_output": 'Componentlist not found',
            "outputs": {'DigitalGuardian.Componentlist.Found': True},
            "raw_response": 'Componentlist entry not found'
        }
        orenctl.results(results)


class DigitalGuardian(object):
    def __init__(self):
        self.auth_sever = orenctl.getParam("auth_url")
        self.auth_url = self.auth_sever + '/as/token.oauth2'
        self.insecure = True if orenctl.getParam("insecure") else False
        self.arc_url = orenctl.getParam("arc_url")
        self.arc_url += '/rest/1.0'
        self.client_id = orenctl.getParam("client_id")
        self.client_secret = orenctl.getParam("client_secret")
        self.export_profile = orenctl.getParam("export_profile")
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        response = self.session.request(method=method, url=url_suffix, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_watchlist_id(self, watchlist_name):
        full_url = self.arc_url + WATCH_LIST
        r = requests.get(url=full_url, headers=CLIENT_HEADERS, verify=self.insecure)
        json_text = json.loads(r.text)
        list_id = None
        if 200 <= r.status_code <= 299:
            for item in json_text:
                if item.get('display_name', '').lower() == watchlist_name.lower():
                    list_id = item.get('name')
        else:
            orenctl.results(
                orenctl.error(f'Error retrieving watchlist_id for {watchlist_name}, {r.status_code}: {r.text}'))

        if not list_id:
            orenctl.results(orenctl.error(f'Unable to find watchlist_id for {watchlist_name}'))

        return str(list_id)

    def get_watchlist_entry_id(self, watchlist_name, watchlist_entry):
        if watchlist_name is None or watchlist_entry is None:
            orenctl.results(orenctl.error(ERROR))

        watchlist_entry_id = None
        watchlist_id = self.get_watchlist_id(watchlist_name)

        if watchlist_id:
            full_url = self.arc_url + WATCH_LIST
            r = requests.get(url=full_url + watchlist_id + '/values?limit=100000', headers=CLIENT_HEADERS,
                             verify=self.insecure)
            json_text = json.loads(r.text)
            if r.status_code != requests.codes.ok:
                orenctl.results(orenctl.error('Unable to retrieve watchlist entries'))
            for j_text in json_text:
                if str(j_text.get('value_name', '')).lower() == watchlist_entry.lower():
                    watchlist_entry_id = j_text.get('value_id')

        return str(watchlist_entry_id)

    def get_list_id(self, list_name, list_type):
        full_url = self.arc_url + '/lists/' + list_type
        r = requests.get(url=full_url, headers=CLIENT_HEADERS, verify=self.insecure)
        json_text = json.loads(r.text)
        list_id = None
        if 200 <= r.status_code <= 299:
            for j_text in json_text:
                if str(j_text.get('name', '')).lower() == list_name.lower():
                    list_id = j_text.get('id')
        else:
            orenctl.results(orenctl.error(f'Error retrieving list_id for {list_name}, {r.status_code}: {r.text}'))

        if not list_id:
            orenctl.results(orenctl.error(f'List id not found for name {list_name} and type {list_type}'))

        return str(list_id)


def add_entry_to_watchlist():
    client = DigitalGuardian()
    watchlist_name = orenctl.getArg("watchlist_name") if orenctl.getArg("watchlist_name") else None
    watchlist_entry = orenctl.getArg("watchlist_entry") if orenctl.getArg("watchlist_entry") else None
    if watchlist_name is None or watchlist_entry is None:
        orenctl.results(orenctl.error(ERROR))

    watchlist_id = client.get_watchlist_id(watchlist_name)
    watchlist_entry_json = '[{"value_name":"' + watchlist_entry + '"}]'
    full_url = client.arc_url + WATCH_LIST
    r = requests.post(url=full_url + watchlist_id + '/values/', data=watchlist_entry_json,
                      headers=CLIENT_HEADERS, verify=client.insecure)
    if 200 <= r.status_code <= 299:
        orenctl.results(f'added watchlist entry ({watchlist_entry}) to watchlist name ({watchlist_name})')
    else:
        orenctl.results(orenctl.error(
            'Failed to add watchlist entry({}) to watchlist name ({}). The response failed with status code {}. '
            'The response was: {}'.format(watchlist_entry, watchlist_name, r.status_code, r.text)))


def check_watchlist_entry():
    client = DigitalGuardian()
    watchlist_name = orenctl.getArg("watchlist_name") if orenctl.getArg("watchlist_name") else None
    watchlist_entry = orenctl.getArg("watchlist_entry") if orenctl.getArg("watchlist_entry") else None
    if watchlist_name is None or watchlist_entry is None:
        orenctl.results(orenctl.error(ERROR))

    watchlist_entry_id = client.get_watchlist_entry_id(watchlist_name, watchlist_entry)

    if watchlist_entry_id:
        results = {
            "readable_output": 'Watchlist found',
            "outputs": {'DigitalGuardian.Watchlist.Found': True},
            "raw_response": 'Watchlist found'
        }
        orenctl.results(results)
    else:
        results = {
            "readable_output": 'Watchlist not found',
            "outputs": {'DigitalGuardian.Watchlist.Found': True},
            "raw_response": 'Watchlist not found'
        }
        orenctl.results(orenctl.error(results))


def rm_entry_from_watchlist():
    client = DigitalGuardian()
    watchlist_name = orenctl.getArg("watchlist_name") if orenctl.getArg("watchlist_name") else None
    watchlist_entry = orenctl.getArg("watchlist_entry") if orenctl.getArg("watchlist_entry") else None

    if watchlist_name is None or watchlist_entry is None:
        orenctl.results(orenctl.error('Please provide both watchlist_name and watchlist_entry'))
    watchlist_id = client.get_watchlist_id(watchlist_name)
    watchlist_entry_id = client.get_watchlist_entry_id(watchlist_name, watchlist_entry)
    logging.debug('wli= ' + str(watchlist_entry_id) + ' wld=' + str(watchlist_id))
    full_url = client.arc_url + '/watchlists/'
    r = requests.delete(url=full_url + watchlist_id + '/values/' + watchlist_entry_id,
                        headers=CLIENT_HEADERS, verify=client.insecure)
    if 200 <= r.status_code <= 299:
        orenctl.results(
            f'removed watchlist entry ({watchlist_entry}) from watchlist name ({watchlist_name})')
    else:
        orenctl.results(orenctl.error(
            'Failed to remove watchlist entry({}) from watchlist name ({}). The response failed with status code {}. '
            'The response was: {}'.format(watchlist_entry, watchlist_name, r.status_code, r.text)))


def add_entry_to_component_list():
    client = DigitalGuardian()
    componentlist_name = orenctl.getArg("componentlist_name") if orenctl.getArg("componentlist_name") else None
    componentlist_entry = orenctl.getArg("componentlist_entry") if orenctl.getArg("componentlist_entry") else None

    if componentlist_name is None or componentlist_entry is None:
        orenctl.results(orenctl.error('Please provide both componentlist_name and componentlist_entry'))
    else:
        list_id = client.get_list_id(componentlist_name, 'component_list')
        CLIENT_HEADERS['Content-Type'] = 'application/json'
        if list_id:
            full_url = client.arc_url + '/remediation/lists/'
            list_entry_json = '{"items":["' + componentlist_entry + '"]}'
            r = requests.put(url=full_url + list_id + '/append', headers=CLIENT_HEADERS, data=list_entry_json,
                             verify=client.insecure)
            if 200 <= r.status_code <= 299:
                orenctl.results('added componentlist entry ({}) to componentlist name ({})'.format(componentlist_entry,
                                                                                                   componentlist_name))
            else:
                orenctl.results(orenctl.error(
                    'Failed to add componentlist entry({}) to componentlist name ({}). The response failed with status '
                    'code {}. The '
                    'response was: {}'.format(componentlist_entry, componentlist_name, r.status_code, r.text)))
        else:
            orenctl.results(orenctl.error('Failed to find componentlist name ({})').format(componentlist_name))


def check_componentlist_entry():
    client = DigitalGuardian()
    componentlist_name = orenctl.getArg("componentlist_name") if orenctl.getArg("componentlist_name") else None
    componentlist_entry = orenctl.getArg("componentlist_entry") if orenctl.getArg("componentlist_entry") else None
    if not componentlist_name or not componentlist_entry:
        orenctl.results(orenctl.error('Please provide both componentlist_name and componentlist_entry'))

    componentlist = None
    list_id = client.get_list_id(componentlist_name, 'component_list')
    if list_id:
        full_url = client.arc_url + '/lists/'
        r = requests.get(url=full_url + list_id + '/values?limit=100000', headers=CLIENT_HEADERS,
                         verify=client.insecure)
        json_text = json.loads(r.text)

        if 200 <= r.status_code <= 299:
            for j_text in json_text:
                if str(j_text.get('content_value', '')).lower() == componentlist_entry.lower():
                    componentlist = j_text.get('content_value')
        else:
            orenctl.results(orenctl.error(f'Unable to find componentlist named {componentlist_name}, {r.status_code}'))

    check_componentlist(componentlist)


def rm_entry_from_componentlist():
    client = DigitalGuardian()
    componentlist_name = orenctl.getArg("componentlist_name") if orenctl.getArg("componentlist_name") else None
    componentlist_entry = orenctl.getArg("componentlist_entry") if orenctl.getArg("componentlist_entry") else None
    if componentlist_name is None or componentlist_entry is None:
        orenctl.results(orenctl.error('Please provide either componentlist_name and componentlist_entry'))

    list_id = client.get_list_id(componentlist_name, 'component_list')
    full_url = client.arc_url + '/remediation/lists/'
    CLIENT_HEADERS['Content-Type'] = 'application/json'
    list_entry_json = '{"items":["' + componentlist_entry + '"]}'
    r = requests.post(url=full_url + list_id + '/delete', headers=CLIENT_HEADERS, data=list_entry_json,
                      verify=client.insecure)
    if 200 <= r.status_code <= 299:
        orenctl.results('removed componentlist entry ({}) from componentlist name ({})'.format(componentlist_entry,
                                                                                               componentlist_name))
    else:
        orenctl.results(orenctl.error(
            'Failed to remove componentlist entry({}) from componentlist name ({}). The response failed with '
            'status code {}. The response was: {}'.format(componentlist_entry, componentlist_name, r.status_code,
                                                          r.text)))


if orenctl.command() == "digitalguardian_add_watchlist_entry":
    add_entry_to_watchlist()
elif orenctl.command() == "digitalguardian_check_watchlist_entry":
    check_watchlist_entry()
elif orenctl.command() == "digitalguardian_remove_watchlist_entry":
    rm_entry_from_watchlist()
elif orenctl.command() == "digitalguardian_add_componentlist_entry":
    add_entry_to_component_list()
elif orenctl.command() == "digitalguardian_check_componentlist_entry":
    check_componentlist_entry()
elif orenctl.command() == "digitalguardian_remove_componentlist_entry":
    rm_entry_from_componentlist()
