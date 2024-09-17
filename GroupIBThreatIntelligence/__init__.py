import random

import requests
from requests import HTTPError

import orenctl

PUBIC_LEAK = "osi/public_leak"
VULNERABILITY = "osi/vulnerability"
PHISHING_KIT_INFO = "attacks/phishing_kit"
PHISHING_INFO = "attacks/phishing"
ATTACKS_DDOS_INFO = "attacks/ddos"
ATTACKS_DEFACE_INFO = "attacks/deface"
THREAT_INFO = "threat"
THREAT_ACTOR_INFO = "threat_actor"
SUSPICIOUS_IP_TOR_NODE_INFO = "suspicious_ip/tor_node"
SUSPICIOUS_IP_OPEN_PROXY_INFO = "suspicious_ip/open_proxy"
SUSPICIOUS_IP_SOCKS_PROXY_INFO = "suspicious_ip/socks_proxy"
MALWARE_TARGETED_MALWARE_INFO = "malware/targeted_malware"
MALWARE_CNC_INFO = "malware/cnc"
TIMEOUT = 60.
RETRIES = 4
STATUS_LIST_TO_RETRY = [429, 500]
CNC_IPV4_REGION = "cnc.ipv4.region"
CNC_DOMAIN = "cnc.domain"
CNC_IPV4_COUNTRY_NAME = "cnc.ipv4.countryName"
PV4_COUNTRY_NAME = "ipv4.countryName"
INDICATORS_PARAM_HASHES_MD5 = "indicators.params.hashes.md5"
CNC_URL = "cnc.url"
IPV4_ASN = "ipv4.asn"
CNC_IPV4_IP = "cnc.ipv4.ip"
CNC_IPV4_ASN = "cnc.ipv4.asn"
PHISHING_DOMAIN = "phishingDomain.domain"
IPV4_IP = "ipv4.ip"
IPV4_REGION = "ipv4.region"

MAPPING: dict = {
    "compromised/account_group": {
        "date":
            "dateFirstSeen",
        "name":
            "login",
        "prefix":
            "Compromised Account",
        "indicators":
            [
                {
                    "main_field": "events.cnc.url", "main_field_type": "URL"
                },
                {
                    "main_field": "events.cnc.domain", "main_field_type": "Domain"
                },
                {
                    "main_field": "events.cnc.ipv4.ip", "main_field_type": "IP",
                    "add_fields": ["events.cnc.ipv4.asn", "events.cnc.ipv4.countryName", "events.cnc.ipv4.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                },
                {
                    "main_field": "events.client.ipv4.ip",
                }
            ]
    },
    "compromised/card": {
        "date":
            "dateDetected",
        "name":
            "cardInfo.number",
        "prefix":
            "Compromised Card",
        "indicators":
            [
                {
                    "main_field": CNC_URL, "main_field_type": "URL"
                },
                {
                    "main_field": CNC_DOMAIN, "main_field_type": "Domain"
                },
                {
                    "main_field": CNC_IPV4_IP, "main_field_type": "IP",
                    "add_fields": [CNC_IPV4_ASN, CNC_IPV4_COUNTRY_NAME, CNC_IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "compromised/breached": {
        "date":
            "uploadTime",
        "name":
            "email",
        "prefix":
            "Data Breach",
        "indicators": []
    },
    "bp/phishing": {
        "date":
            "dateDetected",
        "name":
            PHISHING_DOMAIN,
        "prefix":
            "Phishing",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL"
                },
                {
                    "main_field": PHISHING_DOMAIN, "main_field_type": "Domain",
                    "add_fields": ["phishingDomain.registrar"],
                    "add_fields_types": ["registrarname"]
                },
                {
                    "main_field": IPV4_IP, "main_field_type": "IP"
                }
            ]
    },
    "bp/phishing_kit": {
        "date":
            "dateDetected",
        "name":
            "hash",
        "prefix":
            "Phishing Kit",
        "indicators":
            [
                {
                    "main_field": "emails", "main_field_type": "Email"
                }
            ]
    },
    "osi/git_repository": {
        "date":
            "dateDetected",
        "name":
            "name",
        "prefix":
            "Git Leak",
    },
    "osi/public_leak": {
        "date":
            "created",
        "name":
            "hash",
        "prefix":
            "Public Leak",
    },
    "malware/targeted_malware": {
        "date":
            "date",
        "name":
            "injectMd5",
        "prefix":
            "Targeted Malware",
        "indicators":
            [
                {
                    "main_field": "md5", "main_field_type": "File",
                    "add_fields": ["fileName", "md5", "sha1", "sha256", "size"],
                    "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                }
            ]
    },

    "compromised/mule": {
        "name":
            "account",
        "prefix":
            "Compromised Mule",
        "indicators":
            [
                {
                    "main_field": CNC_URL, "main_field_type": "URL",
                },
                {
                    "main_field": CNC_DOMAIN, "main_field_type": "Domain",
                },
                {
                    "main_field": CNC_IPV4_IP, "main_field_type": "IP",
                    "add_fields": [CNC_IPV4_ASN, CNC_IPV4_COUNTRY_NAME, CNC_IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "compromised/imei": {
        "name":
            "device.imei",
        "prefix":
            "Compromised IMEI",
        "indicators":
            [
                {
                    "main_field": CNC_URL, "main_field_type": "URL",
                },
                {
                    "main_field": CNC_DOMAIN, "main_field_type": "Domain",
                },
                {
                    "main_field": CNC_IPV4_IP, "main_field_type": "IP",
                    "add_fields": [CNC_IPV4_ASN, CNC_IPV4_COUNTRY_NAME, CNC_IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/ddos": {
        "name":
            "target.ipv4.ip",
        "prefix":
            "Attacks DDoS",
        "indicators":
            [
                {
                    "main_field": CNC_URL, "main_field_type": "URL",
                },
                {
                    "main_field": CNC_DOMAIN, "main_field_type": "Domain",
                },
                {
                    "main_field": CNC_IPV4_IP, "main_field_type": "IP",
                    "add_fields": [CNC_IPV4_ASN, CNC_IPV4_COUNTRY_NAME, CNC_IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                },
            ]
    },
    "attacks/deface": {
        "name":
            "url",
        "prefix":
            "Attacks Deface",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL",
                },
                {
                    "main_field": "targetDomain", "main_field_type": "Domain",
                },
                {
                    "main_field": "targetIp.ip", "main_field_type": "IP",
                    "add_fields": ["targetIp.asn", "targetIp.countryName", "targetIp.region"],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/phishing": {
        "name":
            PHISHING_DOMAIN,
        "prefix":
            "Phishing",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL",
                },
                {
                    "main_field": PHISHING_DOMAIN, "main_field_type": "Domain",
                    "add_fields": ["phishingDomain.registrar"],
                    "add_fields_types": ["registrarname"]
                },
                {
                    "main_field": IPV4_IP, "main_field_type": "IP",
                    "add_fields": [IPV4_ASN, PV4_COUNTRY_NAME, IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "attacks/phishing_kit": {
        "name":
            "emails",
        "prefix":
            "Phishing Kit",
        "indicators":
            [
                {
                    "main_field": "emails", "main_field_type": "Email",
                }
            ]
    },
    "apt/threat": {
        "prefix":
            "Threat",
        "indicators":
            [
                {
                    "main_field": "indicators.params.ipv4", "main_field_type": "IP",
                },
                {
                    "main_field": "indicators.params.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "indicators.params.url", "main_field_type": "URL",
                },
                {
                    "main_field": INDICATORS_PARAM_HASHES_MD5, "main_field_type": "File",
                    "add_fields":
                        [
                            "indicators.params.name", INDICATORS_PARAM_HASHES_MD5,
                            "indicators.params.hashes.sha1",
                            "indicators.params.hashes.sha256", "indicators.params.size"
                        ],
                    "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                }
            ]
    },
    "hi/threat": {
        "prefix":
            "Threat",
        "indicators":
            [
                {
                    "main_field": "indicators.params.ipv4", "main_field_type": "IP",
                },
                {
                    "main_field": "indicators.params.domain", "main_field_type": "Domain",
                },
                {
                    "main_field": "indicators.params.url", "main_field_type": "URL",
                },
                {
                    "main_field": INDICATORS_PARAM_HASHES_MD5, "main_field_type": "File",
                    "add_fields":
                        [
                            "indicators.params.name", INDICATORS_PARAM_HASHES_MD5,
                            "indicators.params.hashes.sha1",
                            "indicators.params.hashes.sha256", "indicators.params.size"
                        ],
                    "add_fields_types": ["gibfilename", "md5", "sha1", "sha256", "size"]
                }
            ]
    },
    "suspicious_ip/tor_node": {
        "name":
            IPV4_IP,
        "prefix":
            "Suspicious IP Tor Node",
        "indicators":
            [
                {
                    "main_field": IPV4_IP, "main_field_type": "IP",
                    "add_fields": [IPV4_ASN, PV4_COUNTRY_NAME, IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "suspicious_ip/open_proxy": {
        "name":
            IPV4_IP,
        "prefix":
            "Suspicious IP Open Proxy",
        "indicators":
            [
                {
                    "main_field": IPV4_IP, "main_field_type": "IP",
                    "add_fields": [IPV4_ASN, PV4_COUNTRY_NAME, IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "suspicious_ip/socks_proxy": {
        "name":
            IPV4_IP,
        "prefix":
            "Suspicious IP Socks Proxy",
        "indicators":
            [
                {
                    "main_field": IPV4_IP, "main_field_type": "IP",
                    "add_fields": [IPV4_ASN, PV4_COUNTRY_NAME, IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "malware/cnc": {
        "name":
            IPV4_IP,
        "prefix":
            "Malware CNC",
        "indicators":
            [
                {
                    "main_field": "url", "main_field_type": "URL"
                },
                {
                    "main_field": "domain", "main_field_type": "Domain"
                },
                {
                    "main_field": IPV4_IP, "main_field_type": "IP",
                    "add_fields": [IPV4_ASN, PV4_COUNTRY_NAME, IPV4_REGION],
                    "add_fields_types": ["asn", "geocountry", "geolocation"]
                }
            ]
    },
    "osi/vulnerability": {
        "name":
            "id",
        "prefix":
            "OSI Vulnerability",
        "indicators":
            [
                {
                    "main_field": "id", "main_field_type": "CVE",
                    "add_fields": ["cvss.score", "description", "dateLastSeen", "datePublished"],
                    "add_fields_types": ["cvss", "cvedescription", "cvemodified", "published"]
                }
            ]
    },
    "hi/threat_actor": {"prefix": "Threat Actor"},
    "apt/threat_actor": {"prefix": "Threat Actor"}
}


def find_element_by_key(obj, key):
    invalid_values = ["255.255.255.255", "0.0.0.0", ""]
    path = key.split(".", 1)

    if len(path) == 1:
        return filter_invalid(obj, path[0], invalid_values)

    return recursive_find(obj, path[0], path[1])


def filter_invalid(obj, key, invalid_values):
    if isinstance(obj, list):
        return [i.get(key) for i in obj if i.get(key) not in invalid_values]
    elif isinstance(obj, dict):
        return obj.get(key) if obj.get(key) not in invalid_values else None
    else:
        return obj if obj not in invalid_values else None


def recursive_find(obj, current_key, remaining_key):
    if isinstance(obj, list):
        return [find_element_by_key(i.get(current_key), remaining_key) for i in obj]
    elif isinstance(obj, dict):
        return find_element_by_key(obj.get(current_key), remaining_key)
    return None


def find_iocs_in_feed(feed, collection_name):
    indicators = []
    indicators_info = MAPPING.get(collection_name, {}).get("indicators", [])
    for i in indicators_info:
        add_fields = []
        add_fields_list = i.get("add_fields", []) + ["evaluation.severity"]
        for j in add_fields_list:
            add_fields.append(find_element_by_key(feed, j))

    return indicators


def resolve_collection_name(coll_name, is_aptn):
    if coll_name in ["threat", "threat_actor"]:
        return f"apt/{coll_name}" if is_aptn else f"hi/{coll_name}"
    return coll_name


def clean_result(result, coll_name):
    fields_to_remove = {"displayOptions", "isFavourite", "isHidden", "seqUpdate"}
    for field in fields_to_remove:
        result.pop(field, None)

    if coll_name in ["apt/threat", "hi/threat"]:
        fields_to_remove = {"indicatorMalwareRelationships", "indicatorRelationships",
                            "indicatorToolRelationships", "indicatorsIds", "indicators"}
        for field in fields_to_remove:
            result.pop(field, None)

    if coll_name == "compromised/breached":
        result.pop("updateTime", None)


class GroupIBThreatIntelligence(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.incident_collections = orenctl.getParam("incident_collections") if orenctl.getParam(
            "incident_collections") else []
        self.incidents_first_fetch = (
            orenctl.getParam("first_fetch") if orenctl.getParam("first_fetch") else "3 days").strip()
        self.requests_count = orenctl.getParam("max_fetch") if orenctl.getParam("max_fetch") else 3
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

    def search_feed_by_id(self, collection_name, feed_id):
        portion = self.http_request(method="GET", url_suffix=collection_name + "/" + feed_id, timeout=TIMEOUT,
                                    retries=RETRIES, status_list_to_retry=STATUS_LIST_TO_RETRY,
                                    backoff_factor=random.random() * 10 + 1)

        return portion


def get_osi_public_leak_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = PUBIC_LEAK
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_osi_public_vulnerability_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = VULNERABILITY
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_phishing_kit_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = PHISHING_KIT_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_get_phishing_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = PHISHING_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_attacks_ddos_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = ATTACKS_DDOS_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_attacks_deface_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = ATTACKS_DEFACE_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_threat_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = THREAT_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_threat_actor_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = THREAT_ACTOR_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_suspicious_ip_tor_node_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = SUSPICIOUS_IP_TOR_NODE_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_suspicious_ip_open_proxy_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = SUSPICIOUS_IP_OPEN_PROXY_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_suspicious_ip_socks_proxy_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = SUSPICIOUS_IP_SOCKS_PROXY_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_malware_targeted_malware_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = MALWARE_TARGETED_MALWARE_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


def get_malware_cnc_info():
    client = GroupIBThreatIntelligence()
    args = {"id": orenctl.getArg("id")}

    def get_info_by_id_for_collection():
        coll_name = MALWARE_CNC_INFO
        id_ = str(args.get("id"))

        coll_name = resolve_collection_name(coll_name, args.get("isAPT"))

        result = client.search_feed_by_id(coll_name, id_)
        clean_result(result, coll_name)

        return orenctl.results({"result": result})

    return orenctl.results({"info_by_id_for_collection": get_info_by_id_for_collection})


if orenctl.command() == "gibtia_get_osi_public_leak_info":
    get_osi_public_leak_info()
elif orenctl.command() == "gibtia_get_osi_vulnerability_info":
    get_osi_public_vulnerability_info()
elif orenctl.command() == "gibtia_get_phishing_kit_info":
    get_phishing_kit_info()
elif orenctl.command() == "gibtia_get_phishing_info":
    get_get_phishing_info()
elif orenctl.command() == "gibtia_get_attacks_ddos_info":
    get_attacks_ddos_info()
elif orenctl.command() == "gibtia_get_attacks_deface_info":
    get_attacks_deface_info()
elif orenctl.command() == "gibtia_get_threat_info":
    get_threat_info()
elif orenctl.command() == "gibtia_get_threat_actor_info":
    get_threat_actor_info()
elif orenctl.command() == "gibtia_get_suspicious_ip_tor_node_info":
    get_suspicious_ip_tor_node_info()
elif orenctl.command() == "gibtia_get_suspicious_ip_open_proxy_info":
    get_suspicious_ip_open_proxy_info()
elif orenctl.command() == "gibtia_get_suspicious_ip_socks_proxy_info":
    get_suspicious_ip_socks_proxy_info()
elif orenctl.command() == "gibtia_get_malware_targeted_malware_info":
    get_malware_targeted_malware_info()
elif orenctl.command() == "gibtia_get_malware_cnc_info":
    get_malware_cnc_info()
