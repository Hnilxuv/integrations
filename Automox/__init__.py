import requests
from requests import HTTPError

import orenctl

ORG_IDENTIFIER = 'org_id'
DEVICE_IDENTIFIER = 'device_id'
GROUP_IDENTIFIER = 'group_id'
LIMIT_IDENTIFIER = 'limit'
PAGE_IDENTIFIER = 'page'

DEFAULT_ORG_ID = orenctl.getParam(ORG_IDENTIFIER) if orenctl.getParam(ORG_IDENTIFIER) else None


def remove_key(keys_to_traverse, data):
    try:
        key = keys_to_traverse[0]

        if len(keys_to_traverse) == 1:
            del data[key]
            return data

        if isinstance(data[key], dict):
            data[key] = remove_key(keys_to_traverse[1:], data[key])
        elif isinstance(data[key], list):
            for i in range(len(data[key])):
                data[key][i] = remove_key(keys_to_traverse[1:], data[key][i])
        else:
            del data[key]

    except Exception:
        return ValueError(f"Key '{key}' not found in Automox response.")

    return data


def remove_keys(excluded_keys_list, data):
    for key_string in excluded_keys_list:
        keys = key_string.split(".")
        data = remove_key(keys, data)

    return data


def get_default_server_group_id(client, org_id):
    default_server_group_id = None
    page = 0

    while default_server_group_id is None:
        groups = client.list_group(org_id, 250, page)

        for group in groups:
            if not group.get("name"):
                default_server_group_id = group.get("id")
                break

        page += 1

    return default_server_group_id


def body_update_group(original_group):
    color = (orenctl.getArg("color") if orenctl.getArg("color") else None) or original_group['ui_color']
    name = (orenctl.getArg("name") if orenctl.getArg("name") else None) or original_group['name']
    notes = (orenctl.getArg("notes") if orenctl.getArg("notes") else None) or original_group['notes']
    parent_server_group_id = (orenctl.getArg("parent_server_group_id") if orenctl.getArg(
        "parent_server_group_id") else None) or original_group['parent_server_group_id']
    refresh_interval = (orenctl.getArg("refresh_interval") if orenctl.getArg("refresh_interval") else None) or \
                       original_group['refresh_interval']
    return color, name, notes, parent_server_group_id, refresh_interval


class Automox(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")

        self.session = requests.session()
        self.session.headers = {
            "Authorization": f"Bearer {self.api_key}"
        }
        self.proxy = orenctl.getParam("proxy")

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_list_results(self, method, url_suffix, params):
        results = []

        result_limit = int(params['limit'])
        page_limit = 250 if int(params['limit']) > 250 else int(params['limit'])

        params['limit'] = page_limit

        while result_limit > 0:
            response = self.http_request(
                method=method,
                url_suffix=url_suffix,
                params=params
            )

            if isinstance(response, dict) and isinstance(response['data'], list):
                response = response['data']

            if result_limit < page_limit:
                results += response[:result_limit]
            else:
                results += response

            if len(response) < page_limit:
                break

            result_limit -= len(response)

            params['page'] += 1

        return results

    def list_device(self, org_id, group_id, limit, page):
        params = {
            "o": org_id,
            "groupId": group_id,
            "limit": limit,
            "page": page,
        }

        results = self.get_list_results(method="GET", url_suffix="/servers", params=params)

        return results

    def list_organization(self, limit, page):
        params = {
            "limit": limit,
            "page": page,
        }

        results = self.get_list_results(
            method="GET",
            url_suffix="/orgs",
            params=params
        )

        return results

    def action_on_vulnerability_sync_batch(self, org_id, batch_id, action):
        url_suffix = f"/orgs/{org_id}/tasks/batches/{batch_id}/"

        if action in ["accept", "reject"]:
            url_suffix += f"{action}"
        else:
            raise ValueError("Action argument must be a string equal to either 'accept' or 'reject'")

        return self.http_request(
            method='POST',
            url_suffix=url_suffix,
            resp_type="response",
        )

    def action_on_vulnerability_sync_task(self, org_id, task_id, action):
        payload = {
            "action": action,
        }

        return self.http_request(
            method="PATCH",
            url_suffix=f"/orgs/{org_id}/tasks/{task_id}",
            data=payload,
            resp_type="response",
        )

    def get_vulnerability_sync_batch(self, org_id, batch_id):
        return self.http_request(
            method="GET",
            url_suffix=f"/orgs/{org_id}/tasks/batches/{batch_id}",
        )

    def list_vulnerability_sync_batche(self, org_id, limit, page):
        params = {
            "limit": limit,
            "page": page,
        }

        results = self.get_list_results(
            method="GET",
            url_suffix=f"/orgs/{org_id}/tasks/batches",
            params=params,
        )

        return results

    def list_vulnerability_sync_task(self, org_id, batch_id, status, limit, page):
        params = {
            "limit": limit,
            "page": page,
            "batch_id": batch_id,
            "status": status
        }

        results = self.get_list_results(
            method="GET",
            url_suffix=f"/orgs/{org_id}/tasks",
            params=params,
        )

        return results

    def list_policie(self, org_id, limit, page):
        params = {
            "limit": limit,
            "page": page,
            "o": org_id,
        }

        results = self.get_list_results(
            method="GET",
            url_suffix="/policies",
            params=params,
        )

        return results

    def update_device(self, org_id, device_id, payload):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="PUT",
            url_suffix=f"/servers/{device_id}",
            params=params,
            json_data=payload,
            resp_type="response",
        )

    def get_device(self, org_id, device_id):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="GET",
            url_suffix=f"/servers/{device_id}",
            params=params
        )

    def list_group(self, org_id, limit, page):
        params = {
            "o": org_id,
            "limit": limit,
            "page": page,
        }

        results = self.get_list_results(
            method="GET",
            url_suffix="/servergroups",
            params=params
        )

        return results

    def create_group(self, org_id, payload):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="POST",
            url_suffix="/servergroups",
            params=params,
            data=payload,
        )

    def update_group(self, org_id, group_id, payload):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="PUT",
            url_suffix=f"/servergroups/{group_id}",
            params=params,
            json_data=payload,
            resp_type="response",
        )

    def get_group(self, org_id, group_id):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="GET",
            url_suffix=f"/servergroups/{group_id}",
            params=params
        )

    def delete_group(self, org_id, group_id):
        params = {
            "o": org_id,
        }

        return self.http_request(
            method="DELETE",
            url_suffix=f"/servergroups/{group_id}",
            params=params,
            resp_type="response",
        )


def list_devices():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    group_id = orenctl.getParam(GROUP_IDENTIFIER) if orenctl.getArg(GROUP_IDENTIFIER) else None
    limit = orenctl.getParam(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None
    page = orenctl.getParam(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None

    result = client.list_device(org_id, group_id, limit, page)

    excluded_keys = [
        'compatibility_checks',
        'os_version_id',
        'instance_id',
        'detail',
        'total_count',
    ]

    for i in range(len(result)):
        result[i] = remove_keys(excluded_keys, result[i])

    results = {
        "outputs_prefix": "Automox.Devices",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def list_organizations():
    client = Automox()
    limit = int(orenctl.getArg(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None)
    page = int(orenctl.getArg(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None)
    result = client.list_organization(limit, page)

    excluded_keys = [
        'addr1',
        'bill_overages',
        'addr2',
        'access_key',
        'legacy_billing',
        'sub_systems',
        'stripe_cust',
        'sub_plan',
        'cc_brand',
        'billing_interval',
        'billing_phone',
        'cc_name',
        'city',
        'zipcode',
        'billing_name',
        'metadata',
        'sub_end_time',
        'state',
        'sub_create_time',
        'cc_last',
        'country',
        'billing_email',
        'next_bill_time',
        'billing_interval_count',
        'rate_id',
        'trial_end_time',
        'trial_expired',
        'cc_exp',
    ]

    for i in range(len(result)):
        result[i] = remove_keys(excluded_keys, result[i])

    results = {
        "outputs_prefix": "Automox.Organizations",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def action_on_vulnerability_sync_batchs():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    batch_id = orenctl.getArg('batch_id') if orenctl.getArg('batch_id') else None
    action = orenctl.getArg('action') if orenctl.getArg('action') else None

    client.action_on_vulnerability_sync_batch(org_id, batch_id, action)

    results = {
        "mark_as_note": True,
        "readable_output": f"Action: {action} successfully performed on Automox batch ID: {batch_id}"
    }
    orenctl.results(results)


def action_on_vulnerability_sync_tasks():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    task_id = orenctl.getArg('task_id') if orenctl.getArg('task_id') else None
    action = orenctl.getArg('action') if orenctl.getArg('action') else None

    client.action_on_vulnerability_sync_task(org_id, task_id, action)

    results = {
        "mark_as_note": True,
        "readable_output": f"Action: {action} successfully performed on Automox task ID: {task_id}"
    }
    orenctl.results(results)


def get_vulnerability_sync_batchs():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    batch_id = orenctl.getArg('batch_id') if orenctl.getArg('batch_id') else None

    result = client.get_vulnerability_sync_batch(org_id, batch_id)

    results = {
        "outputs_prefix": "Automox.VulnSyncBatch",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def list_vulnerability_sync_batches():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    limit = int(orenctl.getArg(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None)
    page = int(orenctl.getArg(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None)

    result = client.list_vulnerability_sync_batche(org_id, limit, page)

    results = {
        "outputs_prefix": "Automox.VulnSyncBatches",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def list_vulnerability_sync_tasks():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    batch_id = orenctl.getArg('batch_id') if orenctl.getArg('batch_id') else None
    status = orenctl.getArg('status') if orenctl.getArg('status') else None
    limit = int(orenctl.getArg(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None)
    page = int(orenctl.getArg(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None)

    result = client.list_vulnerability_sync_task(org_id, batch_id, status, limit, page)

    excluded_keys = [
        'partner_user_id',
    ]

    for i in range(len(result)):
        result[i] = remove_keys(excluded_keys, result[i])

    results = {
        "outputs_prefix": "Automox.VulnSyncTasks",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def list_policies():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    limit = int(orenctl.getArg(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None)
    page = int(orenctl.getArg(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None)

    excluded_keys = [
        "configuration",
        "schedule_days",
        "schedule_weeks_of_month",
        "schedule_months",
        "schedule_time",
    ]

    result = client.list_policie(org_id, limit, page)

    for i in range(len(result)):
        result[i] = remove_keys(excluded_keys, result[i])

    results = {
        "outputs_prefix": "Automox.Policies",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def update_devices():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    device_id = orenctl.getArg(DEVICE_IDENTIFIER) if orenctl.getArg(DEVICE_IDENTIFIER) else None

    original_device = client.get_device(org_id, device_id)

    tag_list = orenctl.getArg('tags') if orenctl.getArg('tags') else None
    if tag_list is not None:
        tag_list = tag_list.split(",")
        map(str.strip, tag_list)

    ip_list = orenctl.getArg('ip_addrs') if orenctl.getArg('ip_addrs') else None
    if ip_list is not None:
        ip_list = ip_list.split(",")
        map(str.strip, ip_list)

    server_group_id = (orenctl.getArg('server_group_id') if orenctl.getArg('server_group_id') else None) or \
                      original_device['server_group_id']
    custom_name = (orenctl.getArg('custom_name') if orenctl.getArg('custom_name') else None) or original_device[
        'custom_name']
    tags = tag_list or original_device['tags']
    ip_addrs = ip_list or original_device['ip_addrs']
    exception = (orenctl.getArg('exception') if orenctl.getArg('exception') else None) or original_device['exception']

    payload = {
        "server_group_id": server_group_id,
        "ip_addrs": ip_addrs,
        "exception": bool(exception),
        "tags": tags,
        "custom_name": custom_name,
    }

    client.update_device(org_id, device_id, payload)

    results = {
        "mark_as_note": True,
        "readable_output": f"Device: {device_id} successfully updated in Automox"
    }
    orenctl.results(results)


def list_groups():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    limit = int(orenctl.getArg(LIMIT_IDENTIFIER) if orenctl.getArg(LIMIT_IDENTIFIER) else None)
    page = int(orenctl.getArg(PAGE_IDENTIFIER) if orenctl.getArg(PAGE_IDENTIFIER) else None)

    result = client.list_group(org_id, limit, page)

    excluded_keys = [
        "wsus_config",
    ]

    for i in range(len(result)):
        result[i] = remove_keys(excluded_keys, result[i])
        result[i]['deleted'] = False

    results = {
        "outputs_prefix": "Automox.Groups",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def create_groups():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    color = orenctl.getArg("color") if orenctl.getArg("color") else None
    name = orenctl.getArg("name") if orenctl.getArg("name") else None
    notes = orenctl.getArg("notes") if orenctl.getArg("notes") else None
    refresh_interval = orenctl.getArg("refresh_interval") if orenctl.getArg("refresh_interval") else None
    parent_server_group_id = (orenctl.getArg("parent_server_group_id") if orenctl.getArg(
        "parent_server_group_id") else None) or get_default_server_group_id(client, org_id)

    policy_list = (orenctl.getArg("policies") if orenctl.getArg("policies") else "").split(",")
    map(str.strip, policy_list)

    payload = {
        "color": color,
        "name": name,
        "notes": notes,
        "parent_server_group_id": parent_server_group_id,
        "policies": policy_list,
        "refresh_interval": refresh_interval,
    }

    result = client.create_group(org_id, payload)

    results = {
        "outputs_prefix": "Automox.CreatedGroups",
        "outputs_key_field": 'id',
        "outputs": result
    }
    orenctl.results(results)


def update_groups():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    group_id = orenctl.getArg(GROUP_IDENTIFIER) if orenctl.getArg(GROUP_IDENTIFIER) else None

    original_group = client.get_group(org_id, group_id)

    color, name, notes, parent_server_group_id, refresh_interval = body_update_group(original_group)

    policies = orenctl.getArg("policies") if orenctl.getArg("policies") else None
    if policies is not None:
        policies = policies.split(",")

    map(str.strip, policies) if policies else original_group['policies']

    payload = {
        "color": color,
        "name": name,
        "notes": notes,
        "parent_server_group_id": parent_server_group_id,
        "policies": policies,
        "refresh_interval": refresh_interval,
    }

    client.update_group(org_id, group_id, payload)

    results = {
        "mark_as_note": True,
        "readable_output": f"Group: {group_id} ({name}) successfully updated in Automox."
    }
    orenctl.results(results)


def delete_groups():
    client = Automox()
    org_id = (orenctl.getArg(ORG_IDENTIFIER) if orenctl.getArg(ORG_IDENTIFIER) else None) or DEFAULT_ORG_ID
    group_id = orenctl.getArg(GROUP_IDENTIFIER) if orenctl.getArg(GROUP_IDENTIFIER) else None

    client.delete_group(org_id, group_id)

    result = {
        "id": group_id,
        "deleted": True,
    }

    results = {
        "outputs_prefix": "Automox.Groups",
        "outputs_key_field": "id",
        "outputs": result,
        "mark_as_note": True,
        "readable_output": f"Group: {group_id} successfully deleted from Automox"
    }
    orenctl.results(results)


if orenctl.command() == 'automox_devices_list':
    list_devices()
elif orenctl.command() == 'automox_organizations_list':
    list_organizations()
elif orenctl.command() == 'automox_vulnerability_sync_batch_action':
    action_on_vulnerability_sync_batchs()
elif orenctl.command() == 'automox_vulnerability_sync_task_action':
    action_on_vulnerability_sync_tasks()
elif orenctl.command() == 'automox_vulnerability_sync_batch_get':
    get_vulnerability_sync_batchs()
elif orenctl.command() == 'automox_vulnerability_sync_batches_list':
    list_vulnerability_sync_batches()
elif orenctl.command() == 'automox_vulnerability_sync_tasks_list':
    list_vulnerability_sync_tasks()
elif orenctl.command() == 'automox_policies_list':
    list_policies()
elif orenctl.command() == 'automox_device_update':
    update_devices()
elif orenctl.command() == 'automox_groups_list':
    list_groups()
elif orenctl.command() == 'automox_group_create':
    create_group()
elif orenctl.command() == 'automox_group_update':
    update_group()
elif orenctl.command() == 'automox_group_delete':
    delete_group()
