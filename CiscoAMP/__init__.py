import copy
import json
import math
import re
from collections import namedtuple
from typing import List, MutableMapping, MutableSequence

import requests
from requests import HTTPError

import orenctl

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
MAX_PAGE_SIZE = 100
Pagination = namedtuple(
    "Pagination",
    (
        "page",
        "page_size",
        "limit",
        "offset",
        "number_of_requests",
        "offset_multiplier",
        "is_automatic",
        "is_manual",
    ),
    defaults=(None, None, None, None, None, None, None, None),
)
regexFlags = re.M
sha256Regex = re.compile(r'\b[0-9a-fA-F]{64}\b', regexFlags)
ipv4Regex = (
    r"(?P<ipv4>(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))[:]?(?P<port>\d+)?"
)
urlRegex = re.compile(
    r'^(https?|ftp):\/\/'
    r'(\w+(:\w+)?@)?'
    r'([a-zA-Z0-9.-]+)'
    r'(\.[a-zA-Z]{2,})'
    r'(:\d+)?'
    r'(\/[^\s]*)?$'
)
FILENAME_REGEX = r"[\w\-\.]+[\w\-\. ]*"
CISCO_ISOLATION = "CiscoAMP.ComputerIsolation"


def encode_string_results(text):
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def arg_to_number(arg, arg_name=None, required=False):
    if not arg:
        if required:
            raise ValueError(f'Missing "{arg_name}"' if arg_name else 'Missing required argument')
        return None

    arg = encode_string_results(arg)

    try:
        if isinstance(arg, str):
            return int(arg) if arg.isdigit() else int(float(arg))
        elif isinstance(arg, int):
            return arg
    except ValueError:
        pass

    raise ValueError(f'Invalid number: "{arg_name}"="{arg}"' if arg_name else f'"{arg}" is not a valid number')


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


def get_pagination_parameters(page=0, page_size=0, limit=0):
    is_automatic: bool = limit != 0
    is_manual: bool = page != 0 or page_size != 0

    if is_manual and is_automatic:
        raise ValueError("page or page_size can not be entered with limit.")

    if is_automatic:
        if limit > MAX_PAGE_SIZE:
            number_of_requests = math.ceil(limit / MAX_PAGE_SIZE)
            limit = MAX_PAGE_SIZE
            offset = MAX_PAGE_SIZE
            offset_multiplier = 0

        else:
            number_of_requests = 1
            offset = None
            offset_multiplier = 1

    # Manual Pagination
    elif is_manual:
        page = page or 1
        page_size = page_size or 1
        number_of_requests = 1
        limit = page_size
        offset = (page - 1) * page_size
        offset_multiplier = 1

    # No Pagination
    else:
        number_of_requests = 1
        limit = MAX_PAGE_SIZE
        offset = None
        offset_multiplier = 1

    return Pagination(
        page,
        page_size,
        limit,
        offset,
        number_of_requests,
        offset_multiplier,
        is_automatic,
        is_manual,
    )


def pagination_range(pagination):
    return range(
        pagination.offset_multiplier,
        pagination.number_of_requests + pagination.offset_multiplier,
    )


def remove_empty_elements(data):
    return {k: v for k, v in data.items() if v not in [None, [], '']}


def dict_safe_get(dict_object, keys, default_return_value=None, return_type=None, raise_return_type=True):
    return_value = dict_object

    for key in keys:
        try:
            return_value = return_value[key]
        except (KeyError, TypeError, IndexError, AttributeError):
            return_value = default_return_value
            break

    if return_type and not isinstance(return_value, return_type):
        if raise_return_type:
            raise TypeError("Safe get Error:\nDetails: Return Type Error Excepted return type {0},"
                            " but actual type from nested dict/list is {1} with value {2}.\n"
                            "Query: {3}\nQueried object: {4}".format(return_type, type(return_value),
                                                                     return_value, keys, dict_object))
        return_value = default_return_value

    return return_value


def combine_response_results(raw_response_list, is_automatic=False):
    concatenated_raw_response = raw_response_list[0]

    if not is_automatic:
        return concatenated_raw_response

    for raw_response in raw_response_list[1:]:
        concatenated_raw_response["metadata"]["results"][
            "current_item_count"
        ] += dict_safe_get(raw_response, ["metadata", "results", "current_item_count"])
        concatenated_raw_response["data"].extend(raw_response["data"])

    concatenated_raw_response["metadata"]["results"][
        "items_per_page"
    ] = concatenated_raw_response["metadata"]["results"]["current_item_count"]

    return concatenated_raw_response


def delete_keys_from_dict(dictionary, keys_to_delete):
    keys_set = set(keys_to_delete)
    modified_dict = {}

    for key, value in dictionary.items():
        if key not in keys_set:
            if isinstance(value, MutableMapping):
                modified_dict[key] = delete_keys_from_dict(value, keys_set)

            elif (
                    isinstance(value, MutableSequence)
                    and len(value) > 0
                    and isinstance(value[0], MutableMapping)
            ):
                modified_dict[key] = [
                    delete_keys_from_dict(val, keys_set) for val in value
                ]

            else:
                modified_dict[key] = copy.deepcopy(value)

    return modified_dict


def get_context_output(response, contexts_to_delete, item_to_add=None):
    data_list = response.get("data")

    if not isinstance(data_list, list):
        data_list = [data_list]

    context_outputs = []

    for data in data_list:
        modified_data = delete_keys_from_dict(data, contexts_to_delete)
        context_outputs.append(modified_data)

    if item_to_add:
        for item in context_outputs:
            item.update({item_to_add[0]: item_to_add[1]})

    return context_outputs


def validate_query(accept_ipv4, accept_url, accept_sha256, accept_filename, query=None):
    if not query:
        return True

    is_sha256 = accept_sha256 and sha256Regex.match(query)
    is_ipv4 = accept_ipv4 and re.match(ipv4Regex, query)
    is_url = accept_url and re.match(urlRegex, query)
    is_filename = accept_filename and re.match(FILENAME_REGEX, query)

    return any(
        (
            is_sha256,
            is_ipv4,
            is_url,
            is_filename,
        )
    )


def add_item_to_all_dictionaries(dictionaries, key, value):
    for dictionary in dictionaries:
        dictionary[key] = value


def extract_pagination_from_response(pagination, raw_response):
    if pagination.is_manual:
        start = (pagination.page - 1) * pagination.page_size
        stop = pagination.page * pagination.page_size

        raw_response["data"]["events"] = raw_response["data"]["events"][start:stop]

    else:
        raw_response["data"]["events"] = raw_response["data"]["events"][
                                         : pagination.limit
                                         ]

    context_output = get_context_output(raw_response, ["links"])
    context_output = context_output[0]["events"]
    add_item_to_all_dictionaries(
        context_output,
        "connector_guid",
        dict_safe_get(raw_response, ["data", "computer", "connector_guid"]),
    )

    return context_output


def computer_isolation_get_command():
    client = CiscoAMP()
    connector_guid = orenctl.getArg("connector_guid")

    raw_response = client.computer_isolation_get_request(
        connector_guid=connector_guid,
    )

    context_output = get_context_output(
        response=raw_response,
        contexts_to_delete=["links"],
        item_to_add=("connector_guid", connector_guid),
    )[0]

    return dict(
        outputs_prefix=CISCO_ISOLATION,
        outputs_key_field="connector_guid",
        outputs=context_output,
        raw_response=raw_response,
    )


def computer_isolation_polling_command(args, computer_isolation_command, result_isolation_status):
    if "status" not in args:
        command_results = computer_isolation_command(args)

    else:
        command_results = computer_isolation_get_command()

    status = dict_safe_get(command_results.raw_response, ["data", "status"])

    if status in result_isolation_status:
        return dict(
            response=command_results,
            continue_to_poll=False,
        )

    args_for_next_run = {"status": status, **args}

    return dict(
        response=command_results,
        continue_to_poll=True,
        args_for_next_run=args_for_next_run,
    )


def computer_isolation_create_command(args):
    client = CiscoAMP()
    connector_guid = args["connector_guid"]
    comment = args["comment"]
    unlock_code = args["unlock_code"]

    raw_response = client.computer_isolation_create_request(
        connector_guid=connector_guid,
        comment=comment,
        unlock_code=unlock_code,
    )

    context_output = get_context_output(
        response=raw_response,
        contexts_to_delete=["links"],
        item_to_add=("connector_guid", connector_guid),
    )[0]

    return dict(
        outputs_prefix=CISCO_ISOLATION,
        outputs_key_field="connector_guid",
        outputs=context_output,
        raw_response=raw_response,
    )


def check_endpoint_ids(client, endpoint_hostnames, endpoint_ids, endpoint_ips):
    responses = []
    if endpoint_ids:
        for endpoint_id in endpoint_ids:
            response = client.computer_get_request(connector_guid=endpoint_id)

            responses.append(response)

    elif endpoint_ips:
        response = ""
        for endpoint_ip in endpoint_ips:
            response = client.computer_list_request(internal_ip=endpoint_ip)

        responses.append(response)

    else:
        responses.append(client.computer_list_request(hostnames=endpoint_hostnames))
    return responses


def get_hash_type(file_hash):
    hash_length = len(file_hash)

    if hash_length == 32:
        return 'MD5'
    elif hash_length == 40:
        return 'SHA-1'
    elif hash_length == 64:
        return 'SHA-256'
    else:
        return 'Unknown'


class CiscoAMP(object):
    def __init__(self):
        self.server_url = orenctl.getParam("server_url")
        self.client_id = orenctl.getParam("client_id")
        self.api_key = orenctl.getParam("api_key")
        self.reliability = orenctl.getParam("integrationReliability")
        self.proxy = orenctl.getParam("proxy") if orenctl.getParam("proxy") else False
        self.insecure = True if orenctl.getParam("insecure") else False
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        response = self.session.request(method=method, url=url_suffix, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def computer_list_request(self, limit=None, offset=None, hostnames=None, internal_ip=None, external_ip=None,
                              group_guids=None, last_seen_within=None, last_seen_over=None):
        params = remove_empty_elements(
            {
                "limit": limit,
                "offset": offset,
                "hostname[]": hostnames,
                "internal_ip": internal_ip,
                "external_ip": external_ip,
                "group_guid[]": group_guids,
                "last_seen_within": last_seen_within,
                "last_seen_over": last_seen_over,
            }
        )

        return self.http_request(
            method="GET",
            url_suffix="/computers",
            params=params,
        )

    def computer_get_request(self, connector_guid):
        return self.http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}",
        )

    def computer_trajectory_list_request(self, connector_guid, limit=None, query_string=None):
        params = remove_empty_elements(
            {
                "limit": limit,
                "q": query_string,
            }
        )

        return self.http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/trajectory",
            params=params,
        )

    def computer_user_activity_get_request(self, username, limit=None, offset=None):
        params = remove_empty_elements(
            {"q": username, "limit": limit, "offset": offset}
        )

        return self.http_request(
            method="GET",
            url_suffix="/computers/user_activity",
            params=params,
        )

    def computer_vulnerabilities_list_request(self, connector_guid, start_time=None, end_time=None, limit=None,
                                              offset=None):
        params = remove_empty_elements(
            {
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "offset": offset,
            }
        )

        return self.http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/vulnerabilities",
            params=params,
        )

    def computer_isolation_get_request(self, connector_guid):
        return self.http_request(
            method="GET",
            url_suffix=f"/computers/{connector_guid}/isolation",
        )

    def computer_isolation_create_request(self, connector_guid, comment, unlock_code):
        body = remove_empty_elements(
            {
                "comment": comment,
                "unlock_code": unlock_code,
            }
        )

        return self.http_request(
            method="PUT",
            url_suffix=f"/computers/{connector_guid}/isolation",
            json_data=body,
        )

    def event_list_request(self, detection_sha256=None, application_sha256=None, connector_guids=None, group_guids=None,
                           start_date=None, event_types=None, limit=None, offset=None):
        params = remove_empty_elements(
            {
                "detection_sha256": detection_sha256,
                "application_sha256": application_sha256,
                "connector_guid[]": connector_guids,
                "group_guid[]": group_guids,
                "start_date": start_date,
                "event_type[]": event_types,
                "limit": limit,
                "offset": offset,
            }
        )

        return self.http_request(
            method="GET",
            url_suffix="/events",
            params=params,
        )


def computer_list_command():
    client = CiscoAMP()
    page = arg_to_number(orenctl.getArg("page") if orenctl.getArg("page") else 0)
    page_size = arg_to_number(orenctl.getArg("page_size") if orenctl.getArg("page_size") else 0)
    limit = arg_to_number(orenctl.getArg("limit") if orenctl.getArg("limit") else 0)
    connector_guid = orenctl.getArg("connector_guid") if orenctl.getArg("connector_guid") else ""
    hostnames = arg_to_list(orenctl.getArg("hostnames"))
    internal_ip = orenctl.getArg("internal_ip")
    external_ip = orenctl.getArg("external_ip")
    group_guids = arg_to_list(orenctl.getArg("group_guids"))
    last_seen_within = arg_to_number(orenctl.getArg("last_seen_within"))
    last_seen_over = arg_to_number(orenctl.getArg("last_seen_over"))

    is_get_request = bool(connector_guid)
    is_list_request = any(
        (
            page,
            page_size,
            limit,
            hostnames,
            internal_ip,
            external_ip,
            group_guids,
            last_seen_within,
            last_seen_over,
        )
    )

    raw_response = check_is_get_request(client, connector_guid, external_ip, group_guids, hostnames, internal_ip,
                                        is_get_request, is_list_request, last_seen_over, last_seen_within, limit, page,
                                        page_size)

    context_outputs = get_context_output(raw_response, ["links"])

    command_results = []

    for context_output in context_outputs:
        endpoint_indicator = dict(
            id=context_output["connector_guid"],
            ip_address=context_output["internal_ips"][0],
            hostname=context_output["hostname"],
            mac_address=context_output["network_addresses"][0]["mac"],
            os=context_output["operating_system"],
            os_version=context_output["os_version"],
            status="Online" if context_output["active"] else "Offline",
            vendor="CiscoAMP Response",
        )
        results = {
            "outputs_prefix": "CiscoAMP.Computer",
            "outputs_key_field": "connector_guid",
            "outputs": context_output,
            "raw_response": raw_response,
            "indicator": endpoint_indicator,
        }
        command_results.append(results)

    orenctl.results(command_results)


def check_is_get_request(client, connector_guid, external_ip, group_guids, hostnames, internal_ip, is_get_request,
                         is_list_request, last_seen_over, last_seen_within, limit, page, page_size):
    if is_get_request and is_list_request:
        raise ValueError(
            "connector_guid must be the only input, when fetching a specific computer."
        )
    if not is_get_request:
        pagination = get_pagination_parameters(page, page_size, limit)
        raw_response_list = []

        for request_number in pagination_range(pagination):
            raw_response_list.append(
                client.computer_list_request(
                    limit=pagination.limit,
                    offset=None
                    if pagination.offset is None
                    else pagination.offset * request_number,
                    hostnames=hostnames,
                    internal_ip=internal_ip,
                    external_ip=external_ip,
                    group_guids=group_guids,
                    last_seen_within=last_seen_within,
                    last_seen_over=last_seen_over,
                )
            )

            if not raw_response_list[-1]["data"]:
                break

        raw_response = combine_response_results(
            raw_response_list, pagination.is_automatic
        )

    else:
        raw_response = client.computer_get_request(
            connector_guid=connector_guid,
        )
    return raw_response


def computer_trajectory_list_command():
    client = CiscoAMP()
    connector_guid = orenctl.getArg("connector_guid")
    page = arg_to_number(orenctl.getArg("page") if orenctl.getArg("page") else 0)
    page_size = arg_to_number(orenctl.getArg("page_size") if orenctl.getArg("page_size") else 0)
    limit = arg_to_number(orenctl.getArg("limit") if orenctl.getArg("limit") else 0)
    query_string = orenctl.getArg("query_string")

    if not validate_query(
            query=query_string,
            accept_ipv4=True,
            accept_sha256=True,
            accept_url=True,
            accept_filename=False,
    ):
        raise ValueError("query_string must be: SHA-256/IPv4/URL")

    pagination = get_pagination_parameters(page, page_size, limit)

    raw_response = client.computer_trajectory_list_request(
        connector_guid=connector_guid,
        limit=pagination.page * pagination.page_size
        if pagination.is_manual
        else (limit or None),
        query_string=query_string,
    )

    context_output = extract_pagination_from_response(pagination, raw_response)

    results = {
        "outputs_prefix": "CiscoAMP.ComputerTrajectory",
        "outputs_key_field": "id",
        "outputs": context_output,
        "raw_response": raw_response,
    }
    orenctl.results(results)


def computer_user_activity_list_command():
    client = CiscoAMP()
    username = orenctl.getArg("username")
    page = arg_to_number(orenctl.getArg("page") if orenctl.getArg("page") else 0)
    page_size = arg_to_number(orenctl.getArg("page_size") if orenctl.getArg("page_size") else 0)
    limit = arg_to_number(orenctl.getArg("limit") if orenctl.getArg("limit") else 0)

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list = []

    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.computer_user_activity_get_request(
                username=username,
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

        if not raw_response_list[-1]["data"]:
            break

    raw_response = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_output = get_context_output(raw_response, ["links"])

    results = {
        "outputs_prefix": "CiscoAMP.ComputerUserActivity",
        "outputs_key_field": "connector_guid",
        "outputs": context_output,
        "raw_response": raw_response,
    }
    orenctl.results(results)


def computer_vulnerabilities_list_command():
    client = CiscoAMP()
    connector_guid = orenctl.getArg("connector_guid")
    start_time = orenctl.getArg("start_time")
    end_time = orenctl.getArg("end_time")
    page = arg_to_number(orenctl.getArg("page") if orenctl.getArg("page") else 0)
    page_size = arg_to_number(orenctl.getArg("page_size") if orenctl.getArg("page_size") else 0)
    limit = arg_to_number(orenctl.getArg("limit") if orenctl.getArg("limit") else 0)

    pagination = get_pagination_parameters(page, page_size, limit)
    raw_response_list = []

    for request_number in pagination_range(pagination):
        raw_response_list.append(
            client.computer_vulnerabilities_list_request(
                connector_guid=connector_guid,
                start_time=start_time,
                end_time=end_time,
                limit=pagination.limit,
                offset=None
                if pagination.offset is None
                else pagination.offset * request_number,
            )
        )

        if not raw_response_list[-1]["data"]:
            break

    raw_response = combine_response_results(
        raw_response_list, pagination.is_automatic
    )

    context_output = get_context_output(raw_response, ["links"])
    context_output = context_output[0]["vulnerabilities"]
    add_item_to_all_dictionaries(
        context_output,
        "connector_guid",
        dict_safe_get(raw_response, ["data", "connector_guid"]),
    )

    results = {
        "outputs_prefix": "CiscoAMP.ComputerVulnerability",
        "outputs_key_field": "connector_guid",
        "outputs": context_output,
        "raw_response": raw_response,
    }
    orenctl.results(results)


def computer_isolation_create_polling_command():
    args = {
        "interval_in_seconds": orenctl.getArg("interval_in_seconds") if orenctl.getArg("interval_in_seconds") else 30,
        "timeout_in_seconds": orenctl.getArg("timeout_in_seconds") if orenctl.getArg("timeout_in_seconds") else 600,
        "connector_guid": orenctl.getArg("connector_guid") if orenctl.getArg("connector_guid") else None,
        "comment": orenctl.getArg("comment") if orenctl.getArg("comment") else None,
        "unlock_code": orenctl.getArg("unlock_code") if orenctl.getArg("unlock_code") else None,
        "status": orenctl.getArg("status") if orenctl.getArg("status") else None
    }
    return computer_isolation_polling_command(
        args=args,
        computer_isolation_command=computer_isolation_create_command,
        result_isolation_status=("isolated", "pending_start")
    )


def endpoint_command():
    client = CiscoAMP()
    endpoint_ids = arg_to_list(orenctl.getArg("endpoint_ids"))
    endpoint_ips = arg_to_list(orenctl.getArg("ip"))
    endpoint_hostnames = arg_to_list(orenctl.getArg("hostname"))

    if not any((endpoint_ids, endpoint_ips, endpoint_hostnames)):
        raise orenctl.results(
            orenctl.error("CiscoAMP - In order to run this command, please provide a valid id, ip or hostname"))

    responses = check_endpoint_ids(client, endpoint_hostnames, endpoint_ids, endpoint_ips)

    endpoints = []

    for response in responses:
        data_list = response.get("data")

        if endpoint_ids:
            data_list = [data_list]

        for data in data_list:
            endpoint = dict(
                id=data["connector_guid"],
                ip_address=data["internal_ips"][0],
                hostname=data["hostname"],
                mac_address=data["network_addresses"][0]["mac"],
                os=data["operating_system"],
                os_version=data["os_version"],
                status="Online" if data["active"] else "Offline",
                vendor="CiscoAMP Response",
            )

            endpoints.append(
                dict(
                    raw_response=response,
                    outputs_key_field="_id",
                    indicator=endpoint,
                )
            )

    orenctl.results({"endpoints": endpoints})


def file_command():
    client = CiscoAMP()
    files = arg_to_list(orenctl.getArg("file"))
    command_results = []

    for file_hash in files:
        hash_type = get_hash_type(file_hash)

        if hash_type != "SHA-256":
            raise ValueError(f'Cisco AMP: Hash "{file_hash}" is not of type SHA-256')

        raw_response = client.event_list_request(detection_sha256=file_hash)

        data_list = raw_response["data"]

        file_indicator = dict(
            md5=dict_safe_get(data_list[0], ["file", "identity", "md5"]),
            sha1=dict_safe_get(data_list[0], ["file", "identity", "sha1"]),
            sha256=file_hash,
            path=dict_safe_get(data_list[0], ["file", "file_path"]),
            name=dict_safe_get(data_list[0], ["file", "file_name"]),
            hostname=dict_safe_get(data_list[0], ["computer", "hostname"]),
        )

        for data in data_list[1:]:
            file_indicator.md5 = file_indicator.md5 or dict_safe_get(
                data, ["file", "identity", "md5"]
            )
            file_indicator.sha1 = file_indicator.sha1 or dict_safe_get(
                data, ["file", "identity", "sha1"]
            )
            file_indicator.path = file_indicator.path or dict_safe_get(
                data, ["file", "file_path"]
            )
            file_indicator.name = file_indicator.name or dict_safe_get(
                data, ["file", "file_name"]
            )
            file_indicator.hostname = file_indicator.hostname or dict_safe_get(
                data, ["computer", "hostname"]
            )

            is_all_filled = (
                    file_indicator.md5
                    and file_indicator.sha1
                    and file_indicator.path
                    and file_indicator.name
                    and file_indicator.hostname
            )

            if is_all_filled:
                break

        command_results.append(
            dict(
                outputs_prefix="",
                raw_response=raw_response,
                outputs_key_field="SHA256",
                indicator=file_indicator,
            )
        )

    orenctl.results({"command_results": command_results})


if orenctl.command() == "cisco_amp_computer_list":
    computer_list_command()
elif orenctl.command() == "cisco_amp_computer_trajectory_list":
    computer_trajectory_list_command()
elif orenctl.command() == "cisco_amp_computer_user_activity_list":
    computer_user_activity_list_command()
elif orenctl.command() == "cisco_amp_computer_vulnerabilities_list":
    computer_vulnerabilities_list_command()
elif orenctl.command() == "cisco_amp_computer_isolation_get":
    computer_isolation_get_command()
elif orenctl.command() == "cisco_amp_computer_isolation_create":
    computer_isolation_create_polling_command()
elif orenctl.command() == "endpoint":
    endpoint_command()
elif orenctl.command() == "file":
    file_command()
