import json

import requests
from requests import HTTPError

import orenctl

value_error = "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this message repeats, please contact Illusive Networks support"
all_police = "All Policies"


class IllusiveNetworks(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.api_key = orenctl.getParam("api_key")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.has_forensics = orenctl.getParam("has_forensics")
        self.fetch_time = orenctl.getParam("fetch_time")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_forensics_timeline(self, incident_id, start_date, end_date):
        url_suffix = '/api/v1/forensics/timeline?incident_id={}'.format(incident_id)
        if end_date:
            url_suffix += "&end_date={}".format(end_date)
        if start_date:
            url_suffix += "&start_date={}".format(start_date)
        return self.http_request("GET", url_suffix=url_suffix, ok_codes=(200,))

    def get_asm_host_insight(self, hostname_or_ip):
        url_suffix = '/api/v1/attack-surface/machine-insights?hostNameOrIp={}'.format(hostname_or_ip)
        return self.http_request("GET", url_suffix=url_suffix)

    def is_deceptive_user(self, username):
        url_suffix = '/api/v1/deceptive-entities/user?userName={}'.format(username)
        return self.http_request("GET", url_suffix=url_suffix, resp_type='text')

    def is_deceptive_server(self, hostname):
        url_suffix = '/api/v1/deceptive-entities/server?hostName={}'.format(hostname)
        return self.http_request("GET", url_suffix=url_suffix, resp_type='text')

    def add_deceptive_users(self, body):
        url_suffix = '/api/v1/deceptive-entities/users'
        return self.http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def add_deceptive_servers(self, body):
        url_suffix = '/api/v1/deceptive-entities/servers'
        return self.http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def assign_host_to_policy(self, policy_name, body):
        url_suffix = '/api/v1/policy/domain_hosts/assign?policy_name={}'.format(policy_name)
        return self.http_request('POST', url_suffix=url_suffix, data=json.dumps(body), ok_codes=(200,))

    def run_forensics_on_demand(self, hostname_or_ip):
        url_suffix = '/api/v1/event/create-external-event?hostNameOrIp={}'.format(hostname_or_ip)
        return self.http_request("POST", url_suffix=url_suffix)

    def get_incident(self, incident_id):
        url_suffix = '/api/v2/incidents/incident?incident_id={}'.format(incident_id)
        return self.http_request("GET", url_suffix=url_suffix)

    def list_all_incidents(self, has_forensics, host_names, limit, offset, start_date):
        url_suffix = '/api/v1/incidents?limit={}&offset={}'.format(limit, offset)
        if has_forensics is not None:
            url_suffix += "&has_forensics={}".format(has_forensics)
        if start_date:
            url_suffix += "&start_date={}".format(start_date)
        if host_names:
            url_suffix += "&host_names=" + '&host_names='.join(host_names)
        return self.http_request("GET", url_suffix=url_suffix)

    def get_event_incident_id(self, event_id):
        url_suffix = '/api/v1/incidents/id?event_id={}'.format(event_id)
        return self.http_request("GET", url_suffix=url_suffix, ok_codes=(200,))

    def get_incident_events(self, incident_id, limit, offset):
        url_suffix = '/api/v1/incidents/events?incident_id={}&limit={}&offset={}'.format(incident_id, limit, offset)
        return self.http_request("GET", url_suffix=url_suffix)


def get_forensics_timeline_command():
    client = IllusiveNetworks()
    incident_id = orenctl.getArg("incident_id")
    start_date = orenctl.getArg("start_date")
    end_date = orenctl.getArg("end_date")
    try:
        result = client.get_forensics_timeline(incident_id, start_date, end_date)
        for evidence in result:
            evidence['date'] = evidence.get('details').get('date')
        outputs = {
            'Illusive.Forensics(val.IncidentId == obj.IncidentId)': {
                'IncidentId': incident_id,
                'Status': 'Done',
                'Evidence': result
            }
        }
    except Exception as e:
        if "404" in e.args[0]:
            raise ValueError("Incident id {} doesn't not exist".format(incident_id))
        elif "429" in e.args[0]:
            raise ValueError(value_error)
        elif "202" in e.args[0]:
            outputs = {
                'Illusive.Forensics(val.IncidentId == obj.IncidentId)': {
                    'IncidentId': incident_id,
                    'Status': 'InProgress',
                    'Evidence': []
                }
            }
        else:
            raise ValueError("{}".format(e.args[0]))

    return orenctl.results({"forensics_timeline": outputs})


def get_asm_host_insight_command():
    client = IllusiveNetworks()
    hostname_or_ip = orenctl.getArg("hostnameOrIp")
    try:
        result = client.get_asm_host_insight(hostname_or_ip)
    except Exception as e:
        if "404" in e.args[0]:
            result = []
        elif "429" in e.args[0]:
            raise ValueError(
                "The allowed amount of API calls per minute in Illusive Attack Management has exceeded. In case this"
                " message repeats, please contact Illusive Networks support")
        else:
            raise ValueError("{}".format(e.args[0]))
    outputs = {
        'Illusive.AttackSurfaceInsightsHost(val.ipAddresses == obj.ipAddresses)': result
    }

    return orenctl.results({"asm_host_insight": outputs})


def is_deceptive_user_command():
    client = IllusiveNetworks()
    username = orenctl.getArg("username")
    is_deceptive_user = False
    is_deceptive_user = True if client.is_deceptive_user(username) else is_deceptive_user
    result = {
        'Username': username,
        'IsDeceptiveUser': is_deceptive_user
    }
    outputs = {
        'Illusive.IsDeceptive(val.Username == obj.Username)': result
    }
    return orenctl.results({"deceptive_user": outputs})


def is_deceptive_server_command():
    client = IllusiveNetworks()
    hostname = orenctl.getArg("hostname")
    is_deceptive_server = False
    is_deceptive_server = True if client.is_deceptive_server(hostname) else is_deceptive_server
    result = {
        'Hostname': hostname,
        'IsDeceptiveServer': is_deceptive_server
    }
    outputs = {
        'Illusive.IsDeceptive(val.Hostname == obj.Hostname)': result
    }
    return orenctl.results({"deceptive_server": outputs})


def add_deceptive_users_command():
    client = IllusiveNetworks()
    user_name = orenctl.getArg("username")
    domain_name = orenctl.getArg("domain_name")
    password = orenctl.getArg("password")
    policy_names = orenctl.getArg('policy_names')

    request_body = [
        {'domainName': domain_name, 'password': password, 'policyNames': policy_names, 'username': user_name}]
    try:
        client.add_deceptive_users(request_body)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))

    result = {
        'userName': user_name,
        'domainName': domain_name,
        'policyNames': all_police if policy_names == [] else policy_names,
        'password': password
    }
    outputs = {
        'Illusive.DeceptiveUser(val.userName == obj.userName)': result
    }
    return orenctl.results({"add_deceptive_users": outputs})


def add_deceptive_servers_command():
    client = IllusiveNetworks()
    host_name = orenctl.getArg("host") if orenctl.getArg("host") else ""
    service_types = orenctl.getArg("service_types")
    policy_names = orenctl.getArg('policy_names'), all_police

    if len(host_name.split('.')) < 2:
        raise ValueError("host name must have the following pattern: <host>.<domain>")

    request_body = [{'host': host_name, 'serviceTypes': service_types, 'policyNames': policy_names}]
    try:
        client.add_deceptive_servers(request_body)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))

    result = {
        'host': host_name,
        'serviceTypes': service_types,
        'policyNames': all_police if not policy_names else policy_names
    }
    outputs = {
        'Illusive.DeceptiveServer(val.host == obj.host)': result
    }
    return orenctl.results({"add_deceptive_servers": outputs})


def assign_host_to_policy_command():
    client = IllusiveNetworks()
    policy_name = orenctl.getArg("policy_name")
    host_names = orenctl.getArg("hosts")
    host_names = host_names[:1000]
    request_body = []
    for host_name in host_names:
        host_name_split = host_name.split('@')
        if len(host_name_split) != 2:
            raise ValueError('bad hostname format: {}. Should be  <machineName>@<domainName> '.format(host_name))
        request_body.append({"machineName": host_name_split[0], "domainName": host_name_split[1]})
    try:
        client.assign_host_to_policy(policy_name, request_body)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))
    result = []
    for host in host_names:
        result.append({
            'isAssigned': True,
            'hosts': host,
            'policy_name': policy_name
        })

    outputs = {
        'Illusive.DeceptionPolicy.isAssigned(val.hosts == obj.hosts)': result
    }
    return orenctl.results({"assign_host_to_policy": outputs})


def run_forensics_on_demand_command():
    client = IllusiveNetworks()
    fqdn_or_ip = orenctl.getArg("fqdn_or_ip")
    try:
        result = client.run_forensics_on_demand(fqdn_or_ip)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))
    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': result
    }
    return orenctl.results({"run_forensics_on_demand": outputs})


def get_incidents_command():
    client = IllusiveNetworks()
    incident_id = orenctl.getArg("incident_id")
    has_forensics = orenctl.getArg("has_forensics")
    host_names = orenctl.getArg('hostnames')
    limit = orenctl.getArg("limit") if orenctl.getArg("limit") else 10
    offset = orenctl.getArg("offset") if orenctl.getArg("offset") else 0
    start_date = orenctl.getArg("start_date")

    try:
        if incident_id:
            incident = client.get_incident(incident_id)
        else:
            limit = "100" if int(limit) > 100 else limit
            incident = client.list_all_incidents(has_forensics, host_names, limit, offset, start_date)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))

    outputs = {
        'Illusive.Incident(val.incidentId == obj.incidentId)': incident
    }
    return orenctl.results({"incidents": outputs})


def get_event_incident_id_command():
    client = IllusiveNetworks()
    event_id = int(orenctl.getArg("event_id"))
    status = "Done"
    try:
        incident = client.get_event_incident_id(event_id)
    except Exception as e:
        if "404" in e.args[0]:
            raise ValueError("Event id {} doesn't not exist".format(event_id))
        elif "202" in e.args[0]:
            incident = "-"
            status = "InProgress"
        elif "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))
    result = [{
        'eventId': event_id,
        'incidentId': incident,
        'status': status
    }]
    outputs = {
        'Illusive.Event(val.eventId == obj.eventId)': result
    }

    return orenctl.results({"event_incident_id": outputs})


def get_incident_events_command():
    client = IllusiveNetworks()
    incident_id = orenctl.getArg("incident_id") if orenctl.getArg("incident_id") else 0
    limit = orenctl.getArg("limit") if orenctl.getArg("limit") else 100
    limit = "1000" if int(limit) > 1000 else limit
    offset = orenctl.getArg("offset") if orenctl.getArg("offset") else 0
    try:
        events = client.get_incident_events(incident_id, limit, offset)
    except Exception as e:
        if "429" in e.args[0]:
            raise ValueError(value_error)
        else:
            raise ValueError("{}".format(e.args[0]))

    outputs = {
        'Illusive.Incident(val.incidentId == obj.incidentId)': {
            'eventsNumber': len(events),
            'incidentId': int(incident_id),
            'Event': events
        }
    }
    return orenctl.results({"incident_events": outputs})


if orenctl.command() == "illusive_get_forensics_timeline":
    get_forensics_timeline_command()
elif orenctl.command() == "illusive_get_asm_host_insight":
    get_asm_host_insight_command()
elif orenctl.command() == "illusive_get_asm_cj_insight":
    get_forensics_timeline_command()
elif orenctl.command() == "illusive_is_deceptive_user":
    is_deceptive_user_command()
elif orenctl.command() == "illusive_is_deceptive_server":
    is_deceptive_server_command()
elif orenctl.command() == "illusive_add_deceptive_users":
    add_deceptive_users_command()
elif orenctl.command() == "illusive_add_deceptive_servers":
    add_deceptive_servers_command()
elif orenctl.command() == "illusive_assign_host_to_policy":
    assign_host_to_policy_command()
elif orenctl.command() == "illusive_run_forensics_on_demand":
    run_forensics_on_demand_command()
elif orenctl.command() == "illusive_get_incidents":
    get_incidents_command()
elif orenctl.command() == "illusive_get_event_incident_id":
    get_event_incident_id_command()
elif orenctl.command() == "illusive_get_incident_events":
    get_incident_events_command()
