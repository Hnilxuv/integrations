import json

import requests
from requests import HTTPError

import orenctl

PASSIVE_DNS_QUERY_PARAMS = ['domain', 'ipv4']
PASSIVE_DNS_ENDPOINT = 'passivedns'
TIMEOUT = 60
OS_INDICATORS_ENDPOINT = "os_indicators"
DYNAMIC_DNS_ENDPOINT = 'dynamicdns'
WHOIS_ENDPOINT = 'whois'
DOMAIN_PARAM = 'domain'
WHOIS_CURRENT_ENDPOINT = 'whois/v1'
MALWARE_ENDPOINT = 'sample'
C2_ATTRIBUTION_ENDPOINT = "c2attribution"
PASSIVE_HASH_ENDPOINT = "passivehash"
SSL_CERTIFICATE_ENDPOINT = "ssl_certificate"
DEVICE_GEO_ENDPOINT = "device_geo"
SINKHOLE_ENDPOINT = "sinkhole"
MALWARE_INFO_ENDPOINT = "sample/information"
IPV4_PARAM = 'ipv4'
HASH_PARAM = 'hash'
MD5_PARAM = 'md5'


def flatten_json(y):
    out = {}

    def flatten(x, name=''):
        if type(x) is dict:
            for a in x:
                flatten(x[a], name + a + '_')
        else:
            out[name[:-1]] = x

    flatten(y)
    return out


def get_flatten_json_response(raw_api_response, endpoint):
    flatten_json_response = []
    if raw_api_response:
        for obj in raw_api_response:
            if endpoint == OS_INDICATORS_ENDPOINT:
                data = json.loads(obj.get("data", "{}"))
                obj = {**obj, **data}
            flatten_json_response.append(flatten_json(obj))

    return flatten_json_response


class HyasInsight(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.api_key = orenctl.getParam("X-API-Key")
        self.session = requests.session()
        self.session.headers = {}

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def request_body(self, query_param, query_input, current):
        if current:
            return {
                'applied_filters': {
                    query_param: query_input,
                    'current': True
                }
            }
        else:
            return {
                'applied_filters': {
                    query_param: query_input
                }
            }

    def query(self, end_point, ind_type, ind_value, current, method, limit):
        response = []
        if method == 'GET':
            url_path = f'{end_point}/search?{ind_type}={ind_value}'
            response = self.http_request(
                'GET',
                url_suffix=url_path,
                timeout=TIMEOUT
            )
        elif method == 'POST':
            url_path = f'{end_point}'
            req_body = self.request_body(ind_type, ind_value, current)
            response = self.http_request(
                'POST',
                url_suffix=url_path,
                json_data=req_body,
                timeout=TIMEOUT
            )
        if limit != 0:
            return response[:limit]
        return response

    def fetch_data_from_hyas_api(self, end_point, ind_type, ind_value, current, req_method, limit=0):
        return self.query(end_point, ind_type, ind_value, current, req_method, limit)


def get_passive_dns_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = PASSIVE_DNS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"passive_dns_records_by_indicator": flatten_json_response})


def get_dynamic_dns_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = DYNAMIC_DNS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"dynamic_dns_records_by_indicator": flatten_json_response})


def get_whois_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = WHOIS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"whois_records_by_indicator": flatten_json_response})


def get_whois_current_records_by_domain():
    client = HyasInsight()
    args = {
        "domain": orenctl.getArg("domain")
    }
    indicator_type = DOMAIN_PARAM
    indicator_value = args.get('domain')

    end_point = WHOIS_CURRENT_ENDPOINT
    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, True,
                                                   'POST').json()
    whois_current_record = None
    if api_response:
        whois_current_record = api_response.get("items", [])

    return orenctl.results({"whois_current_records_by_domain": whois_current_record})


def get_malware_samples_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = MALWARE_ENDPOINT
    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, False,
                                                   'POST', limit)

    return orenctl.results({"malware_samples_records_by_indicator": api_response})


def get_c2attribution_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = C2_ATTRIBUTION_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"c2attribution_records_by_indicator": flatten_json_response})


def get_passive_hash_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = PASSIVE_HASH_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"passive_hash_records_by_indicator": flatten_json_response})


def get_ssl_certificate_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = SSL_CERTIFICATE_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', 0).json()
    flatten_json_response = None
    if raw_api_response:
        raw_api_response = raw_api_response.get('ssl_certs')
        if limit and limit > 0:
            raw_api_response = raw_api_response[:limit]
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"ssl_certificate_records_by_indicator": flatten_json_response})


def get_opensource_indicator_records_by_indicator():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = OS_INDICATORS_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"opensource_indicator_records_by_indicator": flatten_json_response})


def get_device_geo_records_by_ip_address():
    client = HyasInsight()
    args = {
        "indicator_type": orenctl.getArg("indicator_type"),
        "indicator_value": orenctl.getArg("indicator_value"),
        "limit": orenctl.getArg("limit")
    }
    indicator_type = args.get('indicator_type')
    indicator_value = args.get('indicator_value')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = DEVICE_GEO_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       indicator_type,
                                                       indicator_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"device_geo_records_by_ip_address": flatten_json_response})


def get_sinkhole_records_by_ipv4_address():
    client = HyasInsight()
    args = {
        "ipv4": orenctl.getArg("ipv4"),
        "limit": orenctl.getArg("limit")
    }
    ipv4_value = args.get('ipv4')
    limit = args.get('limit') if args.get('limit') else 0

    end_point = SINKHOLE_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       IPV4_PARAM,
                                                       ipv4_value, False,
                                                       'POST', limit)
    flatten_json_response = None
    if raw_api_response:
        flatten_json_response = get_flatten_json_response(raw_api_response, end_point)

    return orenctl.results({"sinkhole_records_by_ipv4_address": flatten_json_response})


def get_malware_sample_information_by_hash():
    client = HyasInsight()
    args = {
        "hash": orenctl.getArg("hash")
    }
    hash_value = args.get('hash')
    end_point = MALWARE_INFO_ENDPOINT
    raw_api_response = client.fetch_data_from_hyas_api(end_point,
                                                       HASH_PARAM,
                                                       hash_value, False,
                                                       'POST')
    return orenctl.results({"malware_sample_information_by_hash": raw_api_response})


def get_associated_ips_by_hash():
    client = HyasInsight()
    args = {
        "md5": orenctl.getArg("md5")
    }
    indicator_type = MD5_PARAM
    indicator_value = args.get('md5')
    end_point = MALWARE_ENDPOINT
    api_response = client.fetch_data_from_hyas_api(end_point, indicator_type,
                                                   indicator_value, False,
                                                   'POST')

    associated_ips = [str(obj['ipv4']) for obj in api_response if 'ipv4' in obj]
    outputs = {'md5': indicator_value, 'ips': associated_ips}
    return orenctl.results({"associated_ips_by_hash": outputs})


if orenctl.command() == "hyas_get_passive_dns_records_by_indicator":
    get_passive_dns_records_by_indicator()
elif orenctl.command() == "hyas_get_dynamic_dns_records_by_indicator":
    get_dynamic_dns_records_by_indicator()
elif orenctl.command() == "hyas_get_whois_records_by_indicator":
    get_whois_records_by_indicator()
elif orenctl.command() == "hyas_get_whois_current_records_by_domain":
    get_whois_current_records_by_domain()
elif orenctl.command() == "hyas_get_malware_samples_records_by_indicator":
    get_malware_samples_records_by_indicator()
elif orenctl.command() == "hyas_get_c2attribution_records_by_indicator":
    get_c2attribution_records_by_indicator()
elif orenctl.command() == "hyas_get_passive_hash_records_by_indicator":
    get_passive_hash_records_by_indicator()
elif orenctl.command() == "hyas_get_ssl_certificate_records_by_indicator":
    get_ssl_certificate_records_by_indicator()
elif orenctl.command() == "hyas_get_opensource_indicator_records_by_indicator":
    get_opensource_indicator_records_by_indicator()
elif orenctl.command() == "hyas_get_device_geo_records_by_ip_address":
    get_device_geo_records_by_ip_address()
elif orenctl.command() == "hyas_get_sinkhole_records_by_ipv4_address":
    get_sinkhole_records_by_ipv4_address()
elif orenctl.command() == "hyas_get_malware_sample_information_by_hash":
    get_malware_sample_information_by_hash()
elif orenctl.command() == "hyas_get_associated_ips_by_hash":
    get_associated_ips_by_hash()
