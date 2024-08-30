import requests
from requests import HTTPError

import orenctl

GLOBAL_VAR = 'global'


def get_global_or_adom(args):
    client = FortiManager()
    adom = args.get('adom') if args.get('adom') else client.adom
    if adom == GLOBAL_VAR:
        return GLOBAL_VAR
    else:
        return f"adom/{adom}"


def get_specific_entity(entity_name):
    if entity_name:
        return f"/{entity_name}"
    else:
        return ""


def get_range_for_list_command(args):
    first_index = args.get('offset', 0)
    last_index = int(args.get('limit', 50)) - 1
    list_range = []

    if int(first_index) == 0:
        list_range.append(0)
        list_range.append(int(last_index) + 1)

    else:
        list_range.append(int(first_index))
        list_range.append(int(last_index))

    return list_range


def setup_request_data(args, excluded_args):
    return {key.replace('_', '-'): args.get(key) for key in args if key not in excluded_args}


def split_param(args, name, default_val='', skip_if_none=False):
    if not skip_if_none or (skip_if_none and args.get(name)):
        args[name] = args.get(name, default_val).split(',')


class FortiManager(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.session_token = self.get_session_token()
        self.adom = orenctl.getParam("adom")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def fortimanager_http_request(self, method: str, url: str, data_in_list=None, json_data=None,
                                  range_info=None, other_params=None, add_session_token: bool = True):
        body = {
            "id": 1,
            "method": method,
            "verbose": 1,
            "params": [{
                "option": "object member",
                "url": url
            }],
        }

        if add_session_token:
            body['session'] = self.session_token

        if data_in_list:
            body['params'][0]['data'] = [data_in_list]

        if json_data:
            body['params'][0]['data'] = json_data

        if range_info:
            body['params'][0]['range'] = range_info

        if other_params:
            for param in other_params:
                body['params'][0][param] = other_params.get(param)

        response = self.http_request(
            method='POST',
            url_suffix='jsonrpc',
            json_data=body
        )
        return response

    def get_session_token(self):
        response = self.fortimanager_http_request('exec', "/sys/login/user",
                                                  json_data={'user': self.username, 'passwd': self.password},
                                                  add_session_token=False)

        if response.get('result')[0].get('status', {}).get('code') != 0:
            raise ValueError(f"Unable to get new session token. Reason - "
                             f"{response.get('result')[0].get('status').get('message')}")

        return response.get('session')

    def fortimanager_api_call(self, method: str, url: str, data_in_list=None, json_data=None, range_info=None,
                              other_params=None):
        response = self.fortimanager_http_request(method, url, data_in_list=data_in_list, range_info=range_info,
                                                  other_params=other_params, json_data=json_data)

        if response.get('result')[0].get('status', {}).get('code') == -11:
            self.session_token = self.get_session_token()
            response = self.fortimanager_http_request(method, url, data_in_list=data_in_list, range_info=range_info,
                                                      other_params=other_params, json_data=json_data)

        if response.get('result')[0].get('status', {}).get('code') != 0:
            raise ValueError(response.get('result')[0].get('status').get('message'))

        return response.get('result')[0].get('data')


def list_adom_devices_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "device": orenctl.getArg("device"),
        "offset": orenctl.getArg("offset"),
        "limit": orenctl.getArg("limit")
    }
    devices_data = client.fortimanager_api_call("get", f"/dvmdb/{get_global_or_adom(args)}/device"
                                                       f"{get_specific_entity(args.get('device'))}",
                                                range_info=get_range_for_list_command(args))

    return orenctl.results({"devices_data": devices_data})


def list_firewall_addresses_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "address": orenctl.getArg("address"),
        "offset": orenctl.getArg("offset"),
        "limit": orenctl.getArg("limit")
    }
    firewall_addresses = client.fortimanager_api_call("get", f"/pm/config/{get_global_or_adom(args)}"
                                                             f"/obj/firewall/address"
                                                             f"{get_specific_entity(args.get('address'))}",
                                                      range_info=get_range_for_list_command(args))

    return orenctl.results({"firewall_addresses": firewall_addresses})


def create_address_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "name": orenctl.getArg("name"),
        "type": orenctl.getArg("type"),
        "policy_group": orenctl.getArg("policy_group"),
        "comment": orenctl.getArg("comment"),
        "associated_interface": orenctl.getArg("associated_interface"),
        "fqdn": orenctl.getArg("fqdn"),
        "start_ip": orenctl.getArg("start_ip"),
        "end_ip": orenctl.getArg("end_ip"),
        "subnet": orenctl.getArg("subnet"),
        "subnet_name": orenctl.getArg("subnet_name"),
        "sdn": orenctl.getArg("sdn"),
        "wildcard": orenctl.getArg("wildcard"),
        "wildcard_fqdn": orenctl.getArg("wildcard_fqdn"),
        "country": orenctl.getArg("country")
    }
    client.fortimanager_api_call("add", f"/pm/config/{get_global_or_adom(args)}/obj/firewall/address",
                                 data_in_list=setup_request_data(args, ['adom']))

    return orenctl.results({"created_address": f"Created new Address {args.get('name')}"})


def update_address_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "name": orenctl.getArg("name"),
        "type": orenctl.getArg("type"),
        "policy_group": orenctl.getArg("policy_group"),
        "comment": orenctl.getArg("comment"),
        "associated_interface": orenctl.getArg("associated_interface"),
        "fqdn": orenctl.getArg("fqdn"),
        "start_ip": orenctl.getArg("start_ip"),
        "end_ip": orenctl.getArg("end_ip"),
        "subnet": orenctl.getArg("subnet"),
        "subnet_name": orenctl.getArg("subnet_name"),
        "sdn": orenctl.getArg("sdn"),
        "wildcard": orenctl.getArg("wildcard"),
        "wildcard_fqdn": orenctl.getArg("wildcard_fqdn"),
        "country": orenctl.getArg("country")
    }
    client.fortimanager_api_call("update", f"/pm/config/{get_global_or_adom(args)}/obj/firewall/address",
                                 data_in_list=setup_request_data(args, ['adom']))

    return orenctl.results({"update_address": f"Updated Address {args.get('name')}"})


def list_policy_packages_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "policy_package": orenctl.getArg("policy_package"),
        "offset": orenctl.getArg("offset"),
        "limit": orenctl.getArg("limit")
    }
    policy_packages = client.fortimanager_api_call("get", f"pm/pkg/{get_global_or_adom(args)}"
                                                          f"{get_specific_entity(args.get('policy_package'))}")

    from_val = int(args.get('offset', 0))
    to_val = args.get('limit')
    if not args.get('limit'):
        policy_packages = policy_packages[from_val:]
    else:
        policy_packages = policy_packages[from_val:int(to_val)]

    return orenctl.results({"list_policy_packages": policy_packages})


def update_policy_package_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "name": orenctl.getArg("name"),
        "type": orenctl.getArg("type"),
        "central_nat": orenctl.getArg("central_nat"),
        "consolidated_firewall_mode": orenctl.getArg("consolidated_firewall_mode"),
        "fwpolicy_implicit_log": orenctl.getArg("fwpolicy_implicit_log"),
        "fwpolicy6_implicit_log": orenctl.getArg("fwpolicy6_implicit_log"),
        "inspection_mode": orenctl.getArg("inspection_mode"),
        "ngfw_mode": orenctl.getArg("ngfw_mode"),
        "ssl_ssh_profile": orenctl.getArg("ssl_ssh_profile")
    }
    package_settings = {
        'central-nat': args.get('central_nat'),
        'consolidated-firewall': args.get('consolidated_firewall'),
        'fwpolicy-implicit-log': args.get('fwpolicy_implicit_log'),
        'fwpolicy6-implicit-log': args.get('fwpolicy6_implicit_log'),
        'inspection-mode': args.get('inspection_mode'),
        'ngfw-mode': args.get('ngfw_mode'),
        'ssl-ssh-profile': args.get('ssl_ssh_profile')
    }

    args['package settings'] = package_settings
    client.fortimanager_api_call("update", f"pm/pkg/{get_global_or_adom(args)}",
                                 data_in_list=setup_request_data(args, ['adom', 'central_nat', 'consolidated_firewall',
                                                                        'fwpolicy_implicit_log',
                                                                        'fwpolicy6_implicit_log', 'inspection_mode',
                                                                        'ngfw_mode', 'ssl_ssh_profile']))

    return f"Update Policy Package {args.get('name')}"


def list_policies_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "policy_id": orenctl.getArg("policy_id"),
        "offset": orenctl.getArg("offset"),
        "limit": orenctl.getArg("limit"),
        "package": orenctl.getArg("package")
    }
    policies = client.fortimanager_api_call("get", f"/pm/config/"
                                                   f"{get_global_or_adom(args)}"
                                                   f"/pkg/{args.get('package')}/firewall/policy"
                                                   f"{get_specific_entity(args.get('policy_id'))}",
                                            range_info=get_range_for_list_command(args))

    return orenctl.results({"list_policies": policies})


def update_policy_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "package": orenctl.getArg("package"),
        "action": orenctl.getArg("action"),
        "comments": orenctl.getArg("comments"),
        "dstaddr": orenctl.getArg("dstaddr"),
        "dstaddr6": orenctl.getArg("dstaddr6"),
        "dstaddr_negate": orenctl.getArg("dstaddr_negate"),
        "dstintf": orenctl.getArg("dstintf"),
        "srcaddr": orenctl.getArg("srcaddr"),
        "srcaddr6": orenctl.getArg("srcaddr6"),
        "srcaddr_negate": orenctl.getArg("srcaddr_negate"),
        "srcintf": orenctl.getArg("srcintf"),
        "additional_params": orenctl.getArg("additional_params"),
        "name": orenctl.getArg("name"),
        "logtraffic": orenctl.getArg("logtraffic"),
        "schedule": orenctl.getArg("schedule"),
        "service": orenctl.getArg("service"),
        "status": orenctl.getArg("status"),
        "policyid": orenctl.getArg("policyid")
    }
    if args.get('additional_params'):
        for additional_param in args.get('additional_params').split(','):
            field_and_value = additional_param.split('=')
            args[field_and_value[0]] = field_and_value[1]

    data = setup_request_data(args, ['adom', 'package', 'additional_params'])
    split_param(data, 'dstaddr', 'all', skip_if_none=True)
    split_param(data, 'dstaddr6', 'all', skip_if_none=True)
    split_param(data, 'dstintf', 'any', skip_if_none=True)
    split_param(data, 'schedule', 'always', skip_if_none=True)
    split_param(data, 'service', 'ALL', skip_if_none=True)
    split_param(data, 'srcaddr', 'all', skip_if_none=True)
    split_param(data, 'srcaddr6', 'all', skip_if_none=True)
    split_param(data, 'srcintf', 'any', skip_if_none=True)

    policies = client.fortimanager_api_call("update", f"/pm/config/"
                                                      f"{get_global_or_adom(args)}"
                                                      f"/pkg/{args.get('package')}/firewall/policy",
                                            data_in_list=data)

    return orenctl.results({"updated_policy": f"Updated policy with ID {policies.get('policyid')}"})


def install_policy_package_command():
    client = FortiManager()
    args = {
        "adom": orenctl.getArg("adom"),
        "adom_rev_comment": orenctl.getArg("adom_rev_comment"),
        "adom_rev_name": orenctl.getArg("adom_rev_name"),
        "dev_rev_comment": orenctl.getArg("dev_rev_comment"),
        "package": orenctl.getArg("package"),
        "name": orenctl.getArg("name"),
        "vdom": orenctl.getArg("vdom")
    }
    response = client.fortimanager_api_call('exec', "/securityconsole/install/package",
                                            json_data={
                                                'adom_rev_comment': args.get('adom_rev_comment'),
                                                'adom_rev_name': args.get('adom_rev_name'),
                                                'dev_rev_comment': args.get('dev_rev_comment'),
                                                'adom': get_global_or_adom(args).replace('adom/', ''),
                                                'pkg': args.get('package'),
                                                'scope': [{
                                                    "name": args.get('name'),
                                                    "vdom": args.get('vdom')
                                                }]
                                            })
    formatted_response = {'id': response.get('task')}
    return orenctl.results({"installed_policy_package": formatted_response})


def install_policy_package_status_command():
    client = FortiManager()
    args = {
        "task_id": orenctl.getArg("task_id")
    }
    task_data = client.fortimanager_api_call('get', f"/task/task/{args.get('task_id')}")

    return orenctl.results({"installed_policy_package_status": task_data})


if orenctl.command() == "fortimanager-devices-list":
    list_adom_devices_command()
elif orenctl.command() == "fortimanager-address-list":
    list_firewall_addresses_command()
elif orenctl.command() == "fortimanager-address-create":
    create_address_command()
elif orenctl.command() == "fortimanager-address-update":
    update_address_command()
elif orenctl.command() == "fortimanager-firewall-policy-package-list":
    list_policy_packages_command()
elif orenctl.command() == "fortimanager-firewall-policy-package-update":
    update_policy_package_command()
elif orenctl.command() == "fortimanager-firewall-policy-list":
    list_policies_command()
elif orenctl.command() == "fortimanager-firewall-policy-update":
    update_policy_command()
elif orenctl.command() == "fortimanager-firewall-policy-package-install":
    install_policy_package_command()
elif orenctl.command() == "fortimanager-firewall-policy-package-install-status":
    install_policy_package_status_command()
