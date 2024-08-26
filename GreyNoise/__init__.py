import copy
import json

import requests
from requests import HTTPError
from greynoise import GreyNoise, util
import orenctl

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
API_SERVER = util.DEFAULT_CONFIG.get("api_server")
EXCEPTION_MESSAGES = {
    "API_RATE_LIMIT": "API Rate limit hit. Try after sometime.",
    "UNAUTHENTICATED": "Unauthenticated. Check the configured API Key.",
    "COMMAND_FAIL": "Failed to execute {} command.\n Error: {}",
    "SERVER_ERROR": "The server encountered an internal error for GreyNoise and was unable to complete your request.",
    "CONNECTION_TIMEOUT": "Connection timed out. Check your network connectivity.",
    "PROXY": "Proxy Error - cannot connect to proxy. Either try clearing the 'Use system proxy' check-box or check "
             "the host, authentication details and connection details for the proxy.",
    "INVALID_RESPONSE": "Invalid response from GreyNoise. Response: {}",
    "QUERY_STATS_RESPONSE": "GreyNoise request failed. Reason: {}",
}
TIMEOUT = 30
PRETTY_KEY = {
    "ip": "IP",
    "first_seen": "First Seen",
    "last_seen": "Last Seen",
    "seen": "Seen",
    "tags": "Tags",
    "actor": "Actor",
    "spoofable": "Spoofable",
    "classification": "Classification",
    "cve": "CVE",
    "metadata": "MetaData",
    "asn": "ASN",
    "city": "City",
    "country": "Country",
    "country_code": "Country Code",
    "destination_countries": "Destination Countries",
    "destination_country_codes": "Destination Country Codes",
    "organization": "Organization",
    "category": "Category",
    "sensor_count": "Sensor Count",
    "sensor_hits": "Sensor Hits",
    "source_country": "Source Country",
    "source_country_code": "Source Country Code",
    "tor": "Tor",
    "rdns": "rDNS",
    "os": "OS",
    "region": "Region",
    "vpn": "VPN",
    "vpn_service": "VPN Service",
    "raw_data": "Raw Data",
    "scan": "Scan",
    "port": "Port",
    "protocol": "Protocol",
    "web": "Web",
    "paths": "Paths",
    "useragents": "User-Agents",
    "ja3": "ja3",
    "fingerprint": "fingerprint",
    "hassh": "HASSH",
    "bot": "BOT",
}
QUERY_OUTPUT_PREFIX = {
    "IP": "GreyNoise.IP(val.address && val.address == obj.address)",
    "QUERY": "GreyNoise.Query(val.query && val.query == obj.query)",
}
STATS_H_KEY = {
    "classification": "Classification",
    "spoofable": "Spoofable",
    "organization": "Organization",
    "actor": "Actor",
    "country": "Country",
    "tag": "Tag",
    "operating_system": "Operating System",
    "category": "Category",
    "asn": "ASN",
    "count": "Count",
}


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


def remove_empty_elements(d):
    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


def generate_advanced_query(args):
    advanced_query = args.get("advanced_query", "")
    used_args: dict = {
        "actor": args.get("actor"),
        "classification": args.get("classification"),
        "spoofable": args.get("spoofable"),
        "last_seen": args.get("last_seen"),
        "organization": args.get("organization"),
        "cve": args.get("cve"),
    }

    if advanced_query:
        advanced_query = advanced_query.replace(": ", ":")
        advanced_query = advanced_query.replace(" :", ":")

    arg_list = list(used_args.keys())
    arg_list.sort()

    for each in arg_list:
        if used_args[each] and f"{each}:" not in advanced_query:
            advanced_query += f" {each}:{used_args.get(each)}"

    advanced_query = advanced_query.strip(" ")

    if not advanced_query:
        advanced_query = "spoofable:false"

    return advanced_query


def get_ip_context_data(responses):
    ip_context_responses = []

    responses = remove_empty_elements(responses)
    for response in responses:
        metadata_list: list = []
        tmp_response: dict = {}
        for key, value in response.get("metadata", {}).items():
            if value != "":
                metadata_list.append(f"{PRETTY_KEY.get(key, key)}: {value}")
            if key == "tor":
                tmp_response[PRETTY_KEY.get(key, key)] = value
        tmp_response["MetaData"] = metadata_list

        for key, value in response.items():
            if value != "" and key not in ["metadata", "raw_data"]:
                tmp_response[PRETTY_KEY.get(key, key)] = value

        ip = tmp_response["IP"]
        tmp_response["IP"] = f"[{ip}](https://viz.greynoise.io/ip/{ip})"

        ip_context_responses.append(tmp_response)

    return ip_context_responses


def check_query_response(query_response):
    if not isinstance(query_response, dict):
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(query_response)))
    if query_response.get("message") not in ["ok", "no results"]:
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["QUERY_STATS_RESPONSE"].format(query_response.get("message"))))


class GreyNoiseV1(object):
    def __init__(self):
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()
        self.grey_noise_v2 = GreyNoise(
            api_key=self.api_key,
            api_server=API_SERVER,
            timeout=TIMEOUT,
            proxy=self.proxy,
            use_cache=False,
        )

    def http_request(self, method, url_suffix, *args, **kwargs):
        response = self.session.request(method=method, url=url_suffix, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()


def ip_quick_check_command():
    client = GreyNoise()
    ip_address = arg_to_list(orenctl.getArg("ip") if orenctl.getArg("ip") else ",")

    response = client.quick(ip_address)
    if not isinstance(response, list):
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response)))

    original_response = copy.deepcopy(response)

    for resp in response:
        if "ip" in resp:
            resp["address"] = resp["ip"]
            del resp["ip"]
        resp["code_value"] = resp["code_message"]
        del resp["code_message"]

    results = {
        "outputs_prefix": "GreyNoise.IP",
        "outputs_key_field": "address",
        "outputs": remove_empty_elements(response),
        "raw_response": original_response,
    }
    orenctl.results(results)


def query_command():
    client = GreyNoiseV1().grey_noise_v2
    args = {
        "classification": orenctl.getArg("classification") if orenctl.getArg("classification") else None,
        "spoofable": orenctl.getArg("spoofable") if orenctl.getArg("spoofable") else None,
        "actor": orenctl.getArg("actor") if orenctl.getArg("actor") else None,
        "size": orenctl.getArg("size") if orenctl.getArg("size") else None,
        "advanced_query": orenctl.getArg("advanced_query") if orenctl.getArg("advanced_query") else None,
        "next_token": orenctl.getArg("next_token") if orenctl.getArg("next_token") else None,
        "last_seen": orenctl.getArg("last_seen") if orenctl.getArg("last_seen") else None,
        "organization": orenctl.getArg("organization") if orenctl.getArg("organization") else None
    }

    advanced_query = generate_advanced_query(args)

    query_response = client.query(query=advanced_query, size=args.get("size", "10"), scroll=args.get("next_token"))
    check_query_response(query_response)

    original_response = copy.deepcopy(query_response)

    outputs = {}
    human_readable = ""
    if query_response["message"] == "ok":

        for each in query_response.get("data", []):
            each["address"] = each["ip"]
            del each["ip"]

        human_readable = f'### Total findings: {query_response.get("count")}\n'

        if not query_response.get("complete"):
            human_readable += f'\n### Next Page Token: \n{query_response.get("scroll")}'

        query = query_response.get("query", "").replace(" ", "+")
        query_link = f"https://viz.greynoise.io/query/?gnql={query}"
        query_link = query_link.replace("*", "&ast;")
        query_link = query_link.replace('"', "&quot;")
        human_readable += f"\n*To view the detailed query result please click [here]({query_link}).*"

        outputs = {
            QUERY_OUTPUT_PREFIX["IP"]: query_response.get("data", []),
            QUERY_OUTPUT_PREFIX["QUERY"]: {
                "complete": query_response.get("complete"),
                "count": query_response.get("count"),
                "message": query_response.get("message"),
                "query": query_response.get("query"),
                "scroll": query_response.get("scroll"),
            },
        }
    elif query_response["message"] == "no results":
        human_readable = "### GreyNoise Query returned No Results."
        query = query_response.get("query", "").replace(" ", "+")
        query_link = f"https://viz.greynoise.io/query/?gnql={query}"
        query_link = query_link.replace("*", "&ast;")
        query_link = query_link.replace('"', "&quot;")
        human_readable += f"\n*To view the detailed query result please click [here]({query_link}).*"

    results = {
        "readable_output": human_readable,
        "outputs": remove_empty_elements(outputs),
        "raw_response": original_response
    }
    orenctl.results(results)


def stats_command():
    client = GreyNoise()
    args = {
        "classification": orenctl.getArg("classification") if orenctl.getArg("classification") else None,
        "spoofable": orenctl.getArg("spoofable") if orenctl.getArg("spoofable") else None,
        "actor": orenctl.getArg("actor") if orenctl.getArg("actor") else None,
        "size": orenctl.getArg("size") if orenctl.getArg("size") else None,
        "advanced_query": orenctl.getArg("advanced_query") if orenctl.getArg("advanced_query") else None,
        "last_seen": orenctl.getArg("last_seen") if orenctl.getArg("last_seen") else None,
        "organization": orenctl.getArg("organization") if orenctl.getArg("organization") else None,
    }
    advance_query = generate_advanced_query(args)
    response = client.stats(query=advance_query, count=args.get("size", "10"))
    if not isinstance(response, dict):
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response)))

    results = {
        "outputs_prefix": "GreyNoise.Stats",
        "outputs_key_field": "query",
        "outputs": remove_empty_elements(response),
    }
    orenctl.results(results)


def riot_command():
    client = GreyNoise()
    ip = orenctl.getArg("ip") if orenctl.getArg("ip") else ""
    response = client.riot(ip)
    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)

    if response.get("logo_url", "") != "":
        del response["logo_url"]
    if response.get("trust_level") == "1":
        response["trust_level"] = "1 - Reasonably Ignore"
        response["classification"] = "benign"
    elif response.get("trust_level") == "2":
        response["trust_level"] = "2 - Commonly Seen"
        response["classification"] = "unknown"

    results = {
        "outputs_prefix": "GreyNoise.Riot",
        "outputs_key_field": "address",
        "outputs": response,
        "raw_response": original_response,
    }
    orenctl.results(results)


def context_command():
    client = GreyNoise()
    ip = orenctl.getArg("ip") if orenctl.getArg("ip") else ""
    response = client.ip(ip)

    if not isinstance(response, dict):
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response)))

    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)

    response["address"] = response["ip"]
    del response["ip"]

    human_readable = f"### IP: {ip} No Mass-Internet Scanning Noise Found\n"

    city = response.get("metadata", {}).get("city", "")
    region = response.get("metadata", {}).get("region", "")
    country_code = response.get("metadata", {}).get("country_code", "")
    geo_description = (
        f"City: {city}, Region: {region}, Country Code: {country_code}" if (city or region or country_code) else ""
    )
    ip_standard_context = {
        "ip": response.get("address"),
        "asn": response.get("metadata", {}).get("asn"),
        "hostname": response.get("actor"),
        "geo_country": response.get("metadata", {}).get("country"),
        "geo_description": geo_description,
    }

    results = {
        "readable_output": human_readable,
        "outputs_prefix": "GreyNoise.IP",
        "outputs_key_field": "address",
        "outputs": response,
        "indicator": ip_standard_context,
        "raw_response": original_response,
    }
    orenctl.results(results)


def similarity_command():
    client = GreyNoise()
    ip = orenctl.getArg("ip") if orenctl.getArg("ip") else ""
    min_score = orenctl.getArg("minimum_score") if orenctl.getArg("minimum_score") else 90
    limit = orenctl.getArg("maximum_results") if orenctl.getArg("maximum_results") else 50
    if isinstance(min_score, str):
        min_score = int(min_score)
    if isinstance(limit, str):
        limit = int(limit)
    response = client.similar(ip, min_score=min_score, limit=limit)
    original_response = copy.deepcopy(response)
    response = remove_empty_elements(response)
    if not isinstance(response, dict):
        orenctl.results(orenctl.error(EXCEPTION_MESSAGES["INVALID_RESPONSE"].format(response)))

    if response.get("similar_ips"):
        tmp_response = []
        for sim_ip in response.get("similar_ips", []):
            modified_sim_ip = copy.deepcopy(sim_ip)
            modified_sim_ip["IP"] = sim_ip.get("ip")
            modified_sim_ip["Score"] = sim_ip.get("score", "0") * 100
            modified_sim_ip["Classification"] = sim_ip.get("classification")
            modified_sim_ip["Actor"] = sim_ip.get("actor")
            modified_sim_ip["Organization"] = sim_ip.get("organization")
            modified_sim_ip["Source Country"] = sim_ip.get("source_country")
            modified_sim_ip["Last Seen"] = sim_ip.get("last_seen")
            modified_sim_ip["Similarity Features"] = sim_ip.get("features")
            tmp_response.append(modified_sim_ip)

    results = {
        "outputs_prefix": "GreyNoise.Similar",
        "outputs_key_field": "ip",
        "outputs": remove_empty_elements(response),
        "raw_response": original_response
    }
    orenctl.results(results)


if orenctl.command() == "greynoise_ip_quick_check":
    ip_quick_check_command()
elif orenctl.command() == "greynoise_query":
    query_command()
elif orenctl.command() == "greynoise_st":
    stats_command()
elif orenctl.command() == "greynoise_riot":
    riot_command()
elif orenctl.command() == "greynoise_context":
    context_command()
elif orenctl.command() == "greynoise_similarity":
    similarity_command()
