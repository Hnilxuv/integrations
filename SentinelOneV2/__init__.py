import requests

import orenctl


def assign_params(keys_to_ignore=None, values_to_ignore=None, **kwargs):
    if values_to_ignore is None:
        values_to_ignore = (None, "", [], {}, ())
    if keys_to_ignore is None:
        keys_to_ignore = tuple()
    return {
        key: value for key, value in kwargs.items()
        if value not in values_to_ignore and key not in keys_to_ignore
    }


class SentinelOneV2(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.token = orenctl.getParam("token")
        self.block_site_ids = orenctl.getParam("block_site_ids")
        self.api_version = orenctl.getParam("api_version") or "2.1"
        self.session = requests.session()
        self.session.headers = {
            "Authorization": "ApiToken " + self.token if self.token else "ApiToken",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + f"/web/api/v{self.api_version}/" + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise Exception(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_hash_verdict_request(self, hash_):
        endpoint_url = f"hashes/{hash_}/verdict"
        return self.http_request(method="GET", url_suffix=endpoint_url)

    def get_events_request(self, query_id=None, limit=None, cursor=None):
        endpoint_url = "dv/events"

        params = {
            "query_id": query_id,
            "cursor": cursor,
            "limit": limit
        }

        response = self.http_request(method="GET", url_suffix=endpoint_url, params=params)
        events = response.get("data", {})
        pagination = response.get("pagination")
        return events, pagination

    def create_query_request(self, query, from_date, to_date):
        endpoint_url = "dv/init-query"
        payload = {
            "query": query,
            "fromDate": from_date,
            "toDate": to_date
        }

        response = self.http_request(method="POST", url_suffix=endpoint_url, json=payload)
        return response.get("data", {}).get("queryId")

    def get_processes_request(self, query_id=None, limit=None):
        endpoint_url = "dv/events/process"
        params = {
            "query_id": query_id,
            "limit": limit
        }

        response = self.http_request(method="GET", url_suffix=endpoint_url, params=params)
        return response.get("data", {})

    def get_blocklist_request(self, tenant: bool, group_ids, site_ids, account_ids,
                              skip, limit, os_type, sort_by,
                              sort_order, value_contains):
        """
        We use the `value_contains` instead of `value` parameter because in our testing
        (API 2.1) the `value` parameter is case sensitive. So if an analyst put in the hash with uppercase entries
        and it"s searched using lowercase, this search will not find it
        """
        params = assign_params(
            tenant=tenant,
            groupIds=group_ids,
            siteIds=site_ids,
            accountIds=account_ids,
            skip=skip,
            limit=limit,
            osTypes=os_type,
            sortBy=sort_by,
            sortOrder=sort_order,
            value__contains=value_contains,
        )

        response = self.http_request(method="GET", url_suffix="restrictions", params=params)
        return response.get("data", [])

    def add_hash_to_blocklists_request(self, value, os_type, site_ids, description="", source="") -> dict:
        """
        Supports adding hashes to multiple scoped site blocklists
        """
        # We do not use the assign_params function, because if these values are empty or None, we still want them
        # sent to the server
        for site_id in site_ids:
            data = {
                "value": value,
                "source": source,
                "osType": os_type,
                "type": "black_hash",
                "description": description
            }

            filt = {
                "siteIds": [site_id],
                "tenant": True
            }

            body = {
                "data": data,
                "filter": filt
            }

            response = self.http_request(method="POST", url_suffix="restrictions", json=body)
        return response.get("data") or {}

    def add_hash_to_blocklist_request(self, value, os_type, description="", source="") -> dict:
        """
        Only supports adding to the Global block list
        """
        # We do not use the assign_params function, because if these values are empty or None, we still want them
        # sent to the server

        data = {
            "value": value,
            "source": source,
            "osType": os_type,
            "type": "black_hash",
            "description": description
        }

        filt = {
            "tenant": True
        }

        body = {
            "data": data,
            "filter": filt
        }

        response = self.http_request(method="POST", url_suffix="restrictions", json_data=body)
        return response.get("data") or {}

    def update_alert_status_request(self, alert_ids, status):
        endpoint_url = "cloud-detection/alerts/incident"

        payload = {
            "data": {
                "incidentStatus": status
            },
            "filter": {
                "ids": alert_ids
            }
        }
        response = self.http_request(method="POST", url_suffix=endpoint_url, json=payload)
        return response.get("data", {})

    def get_alerts_request(self, query_params):
        endpoint_url = "cloud-detection/alerts"

        response = self.http_request(method="GET", url_suffix=endpoint_url, params=query_params)
        alerts = response.get("data", {})
        pagination = response.get("pagination")
        return alerts, pagination

    def get_installed_applications_request(self, query_params):
        endpoint_url = "agents/applications"
        response = self.http_request(method="GET", url_suffix=endpoint_url, params=query_params)
        return response.get("data", [])

    def initiate_endpoint_scan_request(self, agent_ids):
        endpoint_url = "agents/actions/initiate-scan"
        payload = {
            "filter": {
                "ids": agent_ids
            },
            "data": {}
        }
        response = self.http_request(method="POST", url_suffix=endpoint_url, json_data=payload)
        return response.get("data", {})


def get_hash_command():
    client = SentinelOneV2()
    hash_ = orenctl.getArg("hash")
    hash_verdict = client.get_hash_verdict_request(hash_)
    reputation = hash_verdict.get("data", {})
    orenctl.results({
        "hash_result": reputation
    })
    return


def get_events():
    client = SentinelOneV2()
    query_id = orenctl.getArg("query_id")
    cursor = orenctl.getArg("cursor")
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 50
    events, pagination = client.get_events_request(query_id, limit, cursor)
    orenctl.results({
        "events": events,
        "pagination": pagination
    })
    return


def create_query():
    client = SentinelOneV2()
    query = orenctl.getArg("query")
    from_date = orenctl.getArg("from_date")
    to_date = orenctl.getArg("to_date")
    query_id = client.create_query_request(query, from_date, to_date)
    orenctl.results({
        "query_id": query_id
    })
    return


def get_processes():
    client = SentinelOneV2()
    query_id = orenctl.getArg("query_id")
    limit = orenctl.getArg("limit")
    processes = client.get_processes_request(query_id, limit)
    orenctl.results({
        "processes": processes
    })
    return


def get_blocklist():
    client = SentinelOneV2()
    tenant = orenctl.getArg("tenant")
    limit = int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 100
    offset = int(orenctl.getArg("offset")) if orenctl.getArg("offset") else 0
    group_ids = orenctl.getArg("group_ids")
    site_ids = orenctl.getArg("site_ids")
    account_ids = orenctl.getArg("account_ids")
    value = orenctl.getArg("hash")
    sort_by = "updatedAt"
    sort_order = "desc"
    block_list = client.get_blocklist_request(tenant=tenant, group_ids=group_ids, site_ids=site_ids,
                                              account_ids=account_ids, skip=offset, limit=limit,
                                              sort_by=sort_by, sort_order=sort_order, value_contains=value,
                                              os_type=None)
    orenctl.results({
        "block_list": block_list
    })
    return


def add_hash_to_blocklist():
    client = SentinelOneV2()
    sha1 = orenctl.getArg("sha1")
    description = orenctl.getArg("description")
    os_type = orenctl.getArg("os_type")
    source = orenctl.getArg("source")
    if sites := client.block_site_ids:
        result = client.add_hash_to_blocklists_request(value=sha1, description=description,
                                                       os_type=os_type, site_ids=sites,
                                                       source=source)
        orenctl.results({
            "command_status": "Added to scoped blocklist",
            "result": result
        })
        return
    result = client.add_hash_to_blocklist_request(value=sha1, description=description,
                                                  os_type=os_type, source=source)
    orenctl.results({
        "command_status": "Added to scoped blocklist",
        "result": result
    })
    return


def update_alert_status():
    client = SentinelOneV2()
    alert_id = orenctl.getArg("alert_id")
    status = orenctl.getArg("status")
    updated_alert = client.update_alert_status_request(alert_id, status)
    orenctl.results({
        "updated_alert": updated_alert
    })
    return


def get_alerts():
    client = SentinelOneV2()
    query_params = assign_params(
        ruleName__contains=orenctl.getArg("rule_name"),
        incidentStatus=orenctl.getArg("incident_status"),
        analystVerdict=orenctl.getArg("analyst_verdict"),
        createdAt__lte=orenctl.getArg("created_until"),
        createdAt__gte=orenctl.getArg("created_from"),
        ids=orenctl.getArg("alert_ids"),
        limit=int(orenctl.getArg("limit")) if orenctl.getArg("limit") else 1000,
        siteIds=orenctl.getArg("site_ids"),
        cursor=orenctl.getArg("cursor"),
    )
    alerts, pagination = client.get_alerts_request(query_params)
    orenctl.results({
        "alerts": alerts,
        "pagination": pagination
    })
    return


def get_installed_applications():
    client = SentinelOneV2()
    agent_ids = orenctl.getArg("agent_ids")
    applications = client.get_installed_applications_request(query_params={"ids": agent_ids})
    orenctl.results({
        "applications": applications
    })
    return


def initiate_endpoint_scan():
    client = SentinelOneV2()
    agent_ids = orenctl.getArg("agent_ids")
    initiated = client.initiate_endpoint_scan_request(agent_ids)
    orenctl.results({
        "initiated": initiated
    })
    return


if orenctl.command() == "sentinelone_get_hash":
    get_hash_command()
if orenctl.command() == "sentinelone_get_events":
    get_events()
if orenctl.command() == "sentinelone_create_query":
    create_query()
if orenctl.command() == "sentinelone_get_processes":
    get_processes()
if orenctl.command() == "sentinelone_get_blocklist":
    get_blocklist()
if orenctl.command() == "sentinelone_add_hash_to_blocklist":
    add_hash_to_blocklist()
if orenctl.command() == "sentinelone_update_alerts_status":
    update_alert_status()
if orenctl.command() == "sentinelone_get_alerts":
    get_alerts()
if orenctl.command() == "sentinelone_get_installed_applications":
    get_installed_applications()
if orenctl.command() == "sentinelone_initiate_endpoint_scan":
    initiate_endpoint_scan()
