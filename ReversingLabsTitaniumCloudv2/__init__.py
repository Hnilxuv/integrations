import json
import os
import tempfile

from ReversingLabs.SDK.ticloud import (FileReputation, AVScanners, FileAnalysis, AdvancedSearch,
                                       URLThreatIntelligence, AnalyzeURL, DomainThreatIntelligence,
                                       IPThreatIntelligence, NetworkReputation)

import orenctl


def get_instance():
    proxies = {
        "http": orenctl.getParam("proxy"),
        "https": orenctl.getParam("proxy")
    }
    return {
        "host": orenctl.getParam("url"),
        "username": orenctl.getParam("username"),
        "password": orenctl.getParam("password"),
        "user_agent": orenctl.getParam("user_agent"),
        "proxies": proxies,
        "verify": True if orenctl.getParam("insecure") else False
    }


def file_reputation_command():
    instance = get_instance()
    mwp = FileReputation(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    hash_value = orenctl.getArg("hash")

    try:
        response = mwp.get_file_reputation(hash_input=hash_value)
    except Exception as e:
        orenctl.results({
            "file_reputation": None
        })
        return

    response_json = response.json()
    orenctl.results({
        "file_reputation": response_json
    })
    return


def av_scanners_command():
    instance = get_instance()
    xref = AVScanners(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    hash_value = orenctl.getArg("hash")

    try:
        response = xref.get_scan_results(hash_input=hash_value)
    except Exception as e:
        orenctl.results({
            "av_scanners": None
        })
        return

    response_json = response.json()
    orenctl.results({
        "av_scanners": response_json
    })
    return


def file_analysis_command():
    instance = get_instance()
    rldata = FileAnalysis(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    hash_value = orenctl.getArg("hash")
    file_name = orenctl.getArg("file_name")

    try:
        response = rldata.get_analysis_results(hash_input=hash_value)
    except Exception as e:
        orenctl.results({
            "location": None,
            "file_name": file_name,
            "file_analysis": None
        })
        return

    response_json = response.json()
    response_json = json.dumps(response_json, indent=4)
    data = response_json.encode('utf-8')
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, file_name)
    with open(path, "wb") as f:
        f.write(data)
    location = orenctl.upload_file(path, None)
    os.remove(path)
    os.rmdir(tmpdir)
    orenctl.results({
        "location": location,
        "file_name": file_name,
        "file_analysis": response_json
    })
    return


def advanced_search_command():
    instance = get_instance()
    advanced_search = AdvancedSearch(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    query = orenctl.getArg("query")
    limit = orenctl.getArg("limit")

    try:
        result_list = advanced_search.search_aggregated(query_string=query, max_results=int(limit))
    except Exception as e:
        orenctl.results({
            "advanced_search": None
        })
        return

    orenctl.results({
        "advanced_search": result_list
    })
    return


def url_report_command():
    instance = get_instance()
    url_ti = URLThreatIntelligence(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    url = orenctl.getArg("url")
    try:
        response = url_ti.get_url_report(url_input=url)
    except Exception as e:
        orenctl.results({
            "url_report": None
        })
        return
    response_json = response.json()
    orenctl.results({
        "url_report": response_json
    })
    return


def analyze_url_command():
    instance = get_instance()
    analyze_url = AnalyzeURL(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    url = orenctl.getArg("url")
    try:
        response = analyze_url.submit_url(url_input=url)
    except Exception as e:
        orenctl.results({
            "analyze_url": None
        })
        return
    response_json = response.json()
    orenctl.results({
        "analyze_url": response_json
    })
    return


def create_domain_ti_object():
    """Creates a DomainThreatIntelligence object."""
    instance = get_instance()
    domain_ti = DomainThreatIntelligence(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    return domain_ti


def domain_report_command():
    domain_ti = create_domain_ti_object()

    domain = orenctl.getArg("domain")
    try:
        response = domain_ti.get_domain_report(domain=domain)
    except Exception as e:
        orenctl.results({
            "domain_report": None
        })
        return
    response_json = response.json()
    orenctl.results({
        "domain_report": response_json
    })
    return


def domain_urls_command():
    domain_ti = create_domain_ti_object()

    domain = orenctl.getArg("domain")
    per_page = orenctl.getArg("per_page")
    limit = orenctl.getArg("max_results")
    try:
        result = domain_ti.urls_from_domain_aggregated(
            domain=domain,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        orenctl.results({
            "domain_urls": None
        })
        return
    orenctl.results({
        "domain_urls": result
    })
    return


def domain_to_ip_command():
    domain_ti = create_domain_ti_object()

    domain = orenctl.getArg("domain")
    per_page = orenctl.getArg("per_page")
    limit = orenctl.getArg("max_results")
    try:
        result = domain_ti.domain_to_ip_resolutions_aggregated(
            domain=domain,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        orenctl.results({
            "domain_to_ip": None
        })
        return
    orenctl.results({
        "domain_to_ip": result
    })
    return


def create_ip_ti_object():
    """Creates an IPThreatIntelligence object."""
    instance = get_instance()
    ip_ti = IPThreatIntelligence(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    return ip_ti


def ip_report_command():
    ip_ti = create_ip_ti_object()

    ip_address = orenctl.getArg("ip_address")
    try:
        response = ip_ti.get_ip_report(ip_address=ip_address)
    except Exception as e:
        orenctl.results({
            "ip_report": None
        })
        return
    response_json = response.json()
    orenctl.results({
        "ip_report": response_json
    })
    return


def ip_urls_command():
    ip_ti = create_ip_ti_object()

    ip_address = orenctl.getArg("ip_address")
    per_page = orenctl.getArg("per_page")
    limit = orenctl.getArg("max_results")
    try:
        result = ip_ti.urls_from_ip_aggregated(
            ip_address=ip_address,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        orenctl.results({
            "ip_urls": None
        })
        return
    orenctl.results({
        "ip_urls": result
    })
    return


def ip_to_domain_command():
    ip_ti = create_ip_ti_object()

    ip_address = orenctl.getArg("ip_address")
    per_page = orenctl.getArg("per_page")
    limit = orenctl.getArg("max_results")
    try:
        result = ip_ti.ip_to_domain_resolutions_aggregated(
            ip_address=ip_address,
            results_per_page=per_page,
            max_results=limit
        )
    except Exception as e:
        orenctl.results({
            "ip_to_domain": None
        })
        return
    orenctl.results({
        "ip_to_domain": result
    })
    return


def network_reputation_command():
    instance = get_instance()
    net_reputation = NetworkReputation(
        host=instance.get("host"),
        username=instance.get("username"),
        password=instance.get("password"),
        user_agent=instance.get("user_agent"),
        proxies=instance.get("proxies"),
        verify=instance.get("verify")
    )

    network_locations = orenctl.getArg("network_locations")
    try:
        response = net_reputation.get_network_reputation(
            network_locations=network_locations
        )
    except Exception as e:
        orenctl.results({
            "network_reputation": None
        })
        return
    response_json = response.json()
    orenctl.results({
        "network_reputation": response_json
    })
    return


if orenctl.command() == "reversinglabs_titaniumcloud_file_reputation":
    file_reputation_command()
if orenctl.command() == "reversinglabs_titaniumcloud_av_scanners":
    av_scanners_command()
if orenctl.command() == "reversinglabs_titaniumcloud_file_analysis":
    file_analysis_command()
if orenctl.command() == "reversinglabs_titaniumcloud_advanced_search":
    advanced_search_command()
if orenctl.command() == "reversinglabs_titaniumcloud_url_report":
    url_report_command()
if orenctl.command() == "reversinglabs_titaniumcloud_analyze_url":
    analyze_url_command()
if orenctl.command() == "reversinglabs_titaniumcloud_domain_report":
    domain_report_command()
if orenctl.command() == "reversinglabs_titaniumcloud_domain_urls":
    domain_urls_command()
if orenctl.command() == "reversinglabs_titaniumcloud_domain_to_ip":
    domain_to_ip_command()
if orenctl.command() == "reversinglabs_titaniumcloud_ip_report":
    ip_report_command()
if orenctl.command() == "reversinglabs_titaniumcloud_ip_urls":
    ip_urls_command()
if orenctl.command() == "reversinglabs_titaniumcloud_ip_to_domain":
    ip_to_domain_command()
if orenctl.command() == "reversinglabs_titaniumcloud_network_reputation":
    network_reputation_command()
