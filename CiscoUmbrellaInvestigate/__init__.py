import requests
from requests import HTTPError

import orenctl

DEFAULT_PAGE = 0
DEFAULT_OFFSET = 0
DEFAULT_LIMIT = 50


def get_pagination_args(page, limit, page_size):
    lmt = page_size or limit or DEFAULT_LIMIT

    if (pg := page) and (pg_sz := page_size):
        ofst = pg * pg_sz
    else:
        ofst = DEFAULT_OFFSET

    return lmt, ofst


def remove_empty_elements(d):
    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


class CiscoUmbrellaInvestigate(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.reliability = orenctl.getParam("integrationReliability")
        self.session = requests.session()
        self.session.headers = {}

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def search_domain(self, expression, start, stop, include_category, type_, limit, offset, ):
        return self.http_request(
            method="GET",
            url_suffix=f"investigate/v2/search/{expression}",
            params=remove_empty_elements(
                {
                    "start": start,
                    "stop": stop,
                    "includeCategory": include_category,
                    "type": type_,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    def get_domain_who_is(self, domain, ):
        return self.http_request(
            method="GET",
            url_suffix=f"investigate/v2/whois/{domain}",
        )

    def get_domain_risk_score(self, domain):
        return self.http_request(
            method="GET",
            url_suffix=f"investigate/v2/domains/risk-score/{domain}",
        )

    def get_domain_categorization(self, domain, show_labels):
        url_suffix = f"investigate/v2/domains/categorization/{domain}"
        if show_labels:
            url_suffix = f"{url_suffix}?showLabels"
        return self.http_request(
            method="GET",
            url_suffix=url_suffix,
        )

    def get_domain_security_score(self, domain):
        return self.http_request(
            method="GET",
            url_suffix=f"investigate/v2/security/name/{domain}",
        )

    def list_timeline(self, name):
        return self.http_request(
            method="GET",
            url_suffix=f"investigate/v2/timeline/{name}",
        )


def domain_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "domain": orenctl.getArg("domain")
    }
    outputs = None
    domains = args.get("domain") or []
    for domain in domains:
        whois_res = client.get_domain_who_is(
            domain,
        )
        whois_data = whois_res
        risk_score_res = client.get_domain_risk_score(
            domain,
        )
        risk_score_data = risk_score_res
        categorization_res = client.get_domain_categorization(
            domain=domain,
            show_labels=False,
        )
        categorization_data = categorization_res[domain]

        security_res = client.get_domain_security_score(
            domain,
        )
        security_data = security_res
        outputs = {
            "Name": domain,
            "Umbrella": {
                "RiskScore": risk_score_data.get("risk_score"),
                "SecureRank": security_data.get("securerank2"),
                "FirstQueriedTime": whois_data.get("created"),
                "ContentCategories": categorization_data.get("content_categories"),
                "MalwareCategories": categorization_data.get("security_categories"),
            },
            "Admin": {
                "Country": whois_data.get("administrativeContactCountry"),
                "Email": whois_data.get("administrativeContactEmail"),
                "Name": whois_data.get("administrativeContactName"),
                "Phone": whois_data.get("administrativeContactTelephone"),
            },
            "Registrant": {
                "Country": whois_data.get("registrantCountry"),
                "Email": whois_data.get("registrantEmail"),
                "Name": whois_data.get("registrantName"),
                "Phone": whois_data.get("registrantTelephone"),
            },
            "CreationDate": whois_data.get("created"),
            "DomainStatus": whois_data.get("status"),
            "UpdatedDate": whois_data.get("updated"),
            "ExpirationDate": whois_data.get("expires"),
            "Registrar": {
                "Name": whois_data.get("registrarName"),
            },
        }
    return orenctl.results({"domain_security_score": outputs})


def get_domain_who_is_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "domain": orenctl.getArg("domain")
    }
    domain = args.get("domain")
    whois_res = client.get_domain_who_is(
        domain,
    )
    whois_data = whois_res
    outputs = {
        "name": domain,
        "Domain": domain,
        "Data": {
            "RegistrarName": whois_data.get("registrantName"),
            "LastRetrieved": whois_data.get("timeOfLatestRealtimeCheck"),
            "Created": whois_data.get("created"),
            "Updated": whois_data.get("updated"),
            "Expires": whois_data.get("expires"),
            "IANAID": whois_data.get("registrarIANAID"),
            "LastObserved": whois_data.get("auditUpdatedDate"),
            "Nameservers": [
                {
                    "Name": nameserver,
                }
                for nameserver in whois_data.get("nameServers", [])
            ],
            "Emails": [
                {
                    "Name": emails,
                }
                for emails in whois_data.get("emails", [])
            ],
        },
    }
    return orenctl.results({"domain_who_is": outputs})


def list_domain_timeline_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "domain": orenctl.getArg("domain"),
        "all_results": orenctl.getArg("all_results"),
        "limit": orenctl.getArg("limit")
    }
    domain = args.get("domain")
    data = client.list_timeline(domain)

    limit = None if args.get("all_results") else args.get("limit") or DEFAULT_LIMIT

    outputs = {
        "input_type": domain,
        "Data": [
            {
                "MalwareCategories": obj.get("categories"),
                "Attacks": obj.get("attacks"),
                "ThreatTypes": obj.get("threatTypes"),
                "Timestamp": obj.get("timestamp"),
            }
            for obj in (data[:limit] if limit else data)
        ],
    }

    return orenctl.results({"list_timeline": outputs})


def list_ip_timeline_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "all_results": orenctl.getArg("all_results"),
        "limit": orenctl.getArg("limit"),
        "ip": orenctl.getArg("ip")
    }
    ip = args.get("ip")
    data = client.list_timeline(ip)

    limit = None if args.get("all_results") else args.get("limit") or DEFAULT_LIMIT

    outputs = {
        "input_type": ip,
        "Data": [
            {
                "MalwareCategories": obj.get("categories"),
                "Attacks": obj.get("attacks"),
                "ThreatTypes": obj.get("threatTypes"),
                "Timestamp": obj.get("timestamp"),
            }
            for obj in (data[:limit] if limit else data)
        ],
    }

    return orenctl.results({"list_timeline": outputs})


def list_url_timeline_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "all_results": orenctl.getArg("all_results"),
        "limit": orenctl.getArg("limit"),
        "ip": orenctl.getArg("url")
    }
    url = args.get("url")
    data = client.list_timeline(url)

    limit = None if args.get("all_results") else args.get("limit") or DEFAULT_LIMIT

    outputs = {
        "input_type": url,
        "Data": [
            {
                "MalwareCategories": obj.get("categories"),
                "Attacks": obj.get("attacks"),
                "ThreatTypes": obj.get("threatTypes"),
                "Timestamp": obj.get("timestamp"),
            }
            for obj in (data[:limit] if limit else data)
        ],
    }

    return orenctl.results({"list_timeline": outputs})


def search_domain_command():
    client = CiscoUmbrellaInvestigate()
    args = {
        "regex": orenctl.getArg("regex"),
        "start": orenctl.getArg("start"),
        "stop": orenctl.getArg("stop"),
        "include_category": orenctl.getArg("include_category"),
        "type": orenctl.getArg("type"),
        "page": orenctl.getArg("page"),
        "page_size": orenctl.getArg("page_size"),
        "limit": orenctl.getArg("limit")
    }
    limit, offset = get_pagination_args(
        page=args.get("page") or DEFAULT_PAGE,
        page_size=args.get("page_size"),
        limit=args.get("limit") or DEFAULT_LIMIT,
    )
    regex = args.get("page")
    res = client.search_domain(
        expression=regex,
        start=args.get("start"),
        stop=args.get("stop"),
        include_category=args.get("include_category"),
        type_=args.get("type"),
        limit=limit,
        offset=offset,
    )
    outputs = [
        {
            "Name": match["name"],
            "FirstSeen": match["firstSeen"],
            "FirstSeenISO": match["firstSeenISO"],
            "SecurityCategories": match["securityCategories"],
        }
        for match in res.get("matches", [])
    ]
    return orenctl.results({"searched_domain": outputs})


if orenctl.command() == "umbrella_domain_search":
    search_domain_command()
elif orenctl.command() == "domain":
    domain_command()
elif orenctl.command() == "umbrella_get_whois_for_domain":
    get_domain_who_is_command()
elif orenctl.command() == "umbrella_get_domain_timeline":
    list_domain_timeline_command()
elif orenctl.command() == "umbrella_get_ip_timeline":
    list_ip_timeline_command()
elif orenctl.command() == "umbrella_get_url_timeline":
    list_url_timeline_command()
