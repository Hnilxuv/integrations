import json
import logging

import requests
from requests import HTTPError

import orenctl

SEARCHABLE_BY_NAME = 'threat-actor,campaign,attack-pattern,tool,signature'
SEARCHABLE_BY_HASH = 'sha256,sha1,md5'


class BluelivThreatContext(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()
        self.session.headers = {}

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def authen(self, username, password):
        body = {
            'username': username,
            'password': password
        }
        res = self.http_request(method='POST', url_suffix='/auth', json_data=body)
        self.session.headers = {"Content-Type": "application/json", "x-cookie": str(res.get('token'))}
        return str(res.get('token'))

    def query_gateway(self, url):
        body = {"apiId": "THIAPP", "url": "/api/v1/" + url, "requestType": "GET"}
        logging.debug("Gateway call to " + json.dumps(body))
        res = self.http_request(method='POST', url_suffix='/gateway', json_data=body, headers=self.session.headers)
        return res

    def get_malware_hash_info(self, file_hash, hash_type="md5"):
        url = "malware/?dork={}%3A%22{}%22".format(hash_type, file_hash)
        result = self.query_gateway(url)
        return result

    def get_malware_info(self, malware_id):
        url = "malware/{}".format(malware_id)
        result = self.query_gateway(url)
        return result

    def get_ip_info(self, ip_id):
        url = "ip/{}".format(ip_id)
        result = self.query_gateway(url)
        return result

    def get_cve_info(self, cve_id):
        url = "cve/{}".format(cve_id)
        result = self.query_gateway(url)
        return result

    def search_by_name(self, key, value):
        if value:
            value = value.replace(' ', '+')
        else:
            value = ""
        url = ''
        if key in SEARCHABLE_BY_NAME:
            url = "{}/?fuzzy_filter%5Bname%5D={}".format(key, value)
        if key in SEARCHABLE_BY_HASH:
            url = "indicator/?fuzzy_filter%5Bvalue%5D={}".format(value)
        if key == 'crime-server':
            url = "crime-server/?fuzzy_filter%5Bcrime_server_url%5D={}".format(value)
        if key == 'fqdn':
            url = "fqdn/?fuzzy_filter%5Bdomain%5D={}".format(value)
        if key == 'ip':
            url = "ip/?fuzzy_filter%5Baddress%5D={}".format(value)

        result = self.query_gateway(url)
        return result.get("data", [])[0].get("id", "0")

    def get_fqdn_info(self, fqdn_id):
        url = "fqdn/{}".format(fqdn_id)
        result = self.query_gateway(url)
        return result

    def get_crime_server_info(self, cs_id):
        url = "crime-server/{}".format(cs_id)
        result = self.query_gateway(url)
        return result

    def get_threat_actor_info(self, threat_actor_id):
        url = "threat-actor/{}".format(threat_actor_id)
        result = self.query_gateway(url)
        return result

    def get_campaign_info(self, campaign_id):
        url = "campaign/{}".format(campaign_id)
        result = self.query_gateway(url)
        return result

    def get_attack_pattern_info(self, attack_pattern_id):
        url = "attack-pattern/{}".format(attack_pattern_id)
        result = self.query_gateway(url)
        return result

    def get_tool_info(self, tool_id):
        url = "tool/{}".format(tool_id)
        result = self.query_gateway(url)
        return result

    def get_signature_info(self, signature_id):
        url = "signature/{}".format(signature_id)
        result = self.query_gateway(url)
        return result


def authenticate():
    client = BluelivThreatContext()
    token = client.authen(client.username, client.password)
    return orenctl.results({"token": token})


def blueliv_malware():
    client = BluelivThreatContext()
    hash_value = orenctl.getArg('hash') if orenctl.getArg('hash') else ''
    malware_id = orenctl.getArg('hash_id') if orenctl.getArg('hash_id') else ''
    hash_type = ''

    if hash_value:
        if len(hash_value) == 40:
            hash_type = 'sha1'
        elif len(hash_value) == 64:
            hash_type = 'sha256'
        elif len(hash_value) == 32:
            hash_type = 'md5'

    if not malware_id:
        result = client.get_malware_hash_info(hash_value, hash_type)
        return orenctl.results({"malware_hash_info": result})
    result = client.get_malware_info(malware_id)
    return orenctl.results({"malware_info": result})


def blueliv_indicator_ip():
    client = BluelivThreatContext()
    name_ip = orenctl.getArg('IP') if orenctl.getArg("IP") else ''
    value_ip = orenctl.getArg('IP_id') if orenctl.getArg("IP_id") else ''

    if name_ip:
        value_ip = name_ip

    result = client.get_ip_info(value_ip)
    orenctl.results({"ip_info": result})


def blueliv_cve():
    client = BluelivThreatContext()
    cve_code = orenctl.getArg('CVE') if orenctl.getArg("CVE") else ''
    vuln_id = orenctl.getArg('CVE_id') if orenctl.getArg("CVE_id") else ''

    if not vuln_id:
        vuln_id = cve_code

    result = client.get_cve_info(vuln_id)
    return orenctl.results({"cve_info": result})


def blueliv_indicator_fqdn():
    client = BluelivThreatContext()
    name_fqdn = orenctl.getArg('FQDN') if orenctl.getArg("FQDN") else ''
    value_fqdn = orenctl.getArg('FQDN_id') if orenctl.getArg("FQDN_id") else ''

    if not value_fqdn and name_fqdn:
        value_fqdn = client.search_by_name('fqdn', name_fqdn)

    result = client.get_fqdn_info(value_fqdn)
    return orenctl.results({"fqdn_info": result})


def blueliv_indicator_cs():
    client = BluelivThreatContext()
    name_cs = orenctl.getArg('CS') if orenctl.getArg("CS") else ''
    value_cs = orenctl.getArg('CS_id') if orenctl.getArg("CS_id") else ''

    if not value_cs and name_cs:
        value_cs = client.search_by_name('crime-server', name_cs)

    result = client.get_crime_server_info(value_cs)
    return orenctl.results({"crime_server_info": result})


def blueliv_threat_actor():
    client = BluelivThreatContext()
    threat_actor_id = orenctl.getArg('threatActor_id') if orenctl.getArg("threatActor_id") else ''
    threat_actor_bname = orenctl.getArg('threatActor') if orenctl.getArg("threatActor") else ''

    if not threat_actor_id:
        threat_actor_id = client.search_by_name('threat-actor', threat_actor_bname)

    result = client.get_threat_actor_info(threat_actor_id)

    orenctl.results({"threat_actor_info": result})


def blueliv_campaign():
    client = BluelivThreatContext()
    campaign = orenctl.getArg('campaign') if orenctl.getArg("campaign") else ''
    campaign_id = orenctl.getArg('campaign_id') if orenctl.getArg("campaign_id") else ''

    if not campaign_id:
        campaign_id = client.search_by_name('campaign', campaign)

    result = client.get_campaign_info(campaign_id)
    return orenctl.results({"campaign_info": result})


def blueliv_attack_pattern():
    client = BluelivThreatContext()
    attack_pattern = orenctl.getArg('attackPattern') if orenctl.getArg("attackPattern") else ''
    attack_pattern_id = orenctl.getArg('attackPattern_id') if orenctl.getArg("attackPattern_id") else ''

    if not attack_pattern_id:
        attack_pattern_id = client.search_by_name('attack-pattern', attack_pattern)

    result = client.get_attack_pattern_info(attack_pattern_id)
    return orenctl.results({"attack_pattern_info": result})


def blueliv_tool():
    client = BluelivThreatContext()
    tool = orenctl.getArg('tool') if orenctl.getArg("tool") else ''
    tool_id = orenctl.getArg('tool_id') if orenctl.getArg("tool_id") else ''

    if not tool_id:
        tool_id = client.search_by_name('attack-pattern', tool)

    result = client.get_tool_info(tool_id)
    return orenctl.results({"tool_info": result})


def blueliv_signature():
    client = BluelivThreatContext()
    signature = orenctl.getArg('signature') if orenctl.getArg("signature") else ''
    signature_id = orenctl.getArg('signature_id') if orenctl.getArg("signature_id") else ''

    if not signature_id:
        signature_id = client.search_by_name('attack-pattern', signature)

    result = client.get_signature_info(signature_id)
    return orenctl.results({"ignature_info": result})


if orenctl.command() == "blueliv_authenticate":
    authenticate()
elif orenctl.command() == "blueliv_tc_malware":
    blueliv_malware()
elif orenctl.command() == "blueliv_tc_indicator_ip":
    blueliv_indicator_ip()
elif orenctl.command() == "blueliv_tc_cve":
    blueliv_cve()
elif orenctl.command() == "blueliv_tc_indicator_fqdn":
    blueliv_indicator_fqdn()
elif orenctl.command() == "blueliv_tc_indicator_cs":
    blueliv_indicator_cs()
elif orenctl.command() == "blueliv_tc_threat_actor":
    blueliv_threat_actor()
elif orenctl.command() == "blueliv_tc_campaign":
    blueliv_campaign()
elif orenctl.command() == "blueliv_tc_attack_pattern":
    blueliv_attack_pattern()
elif orenctl.command() == "blueliv_tc_tool":
    blueliv_tool()
elif orenctl.command() == "blueliv_tc_signature":
    blueliv_signature()
