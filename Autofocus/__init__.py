import json
import re
import sys
import time
from datetime import datetime
from typing import Optional

import pytz
import requests
import socket
import orenctl

entryTypes = {'note': 1, 'error': 2, 'pending': 3}
formats = {'html': 'html', 'table': 'table', 'json': 'json', 'text': 'text', 'markdown': 'markdown'}

IS_IN_THE_RANGE = 'is in the range'
SESSION_TSTAMP = 'session.tstamp'

HEADERS = {
    'Content-Type': 'application/json'
}
SERVER = 'https://autofocus.paloaltonetworks.com'
BASE_URL = SERVER + '/api/v1.0'

ERROR_DICT = {
    404: 'Invalid URL.',
    408: 'Invalid URL.',
    409: 'Invalid message or missing parameters.',
    500: 'Internal error.',
    503: 'Rate limit exceeded.'
}

outputPaths = {
    'file': 'File(val.MD5 && val.MD5 == obj.MD5 || val.SHA1 && val.SHA1 == obj.SHA1 || '
            'val.SHA256 && val.SHA256 == obj.SHA256 || val.SHA512 && val.SHA512 == obj.SHA512 || '
            'val.CRC32 && val.CRC32 == obj.CRC32 || val.CTPH && val.CTPH == obj.CTPH || '
            'val.SSDeep && val.SSDeep == obj.SSDeep)',
    'ip': 'IP(val.Address && val.Address == obj.Address)',
    'url': 'URL(val.Data && val.Data == obj.Data)',
    'domain': 'Domain(val.Name && val.Name == obj.Name)',
    'cve': 'CVE(val.ID && val.ID == obj.ID)',
    'email': 'Account.Email(val.Address && val.Address == obj.Address)',
    'dbotscore': 'DBotScore'
}

API_PARAM_DICT = {
    'scope': {
        'Private': 'private',
        'Public': 'public',
        'Global': 'global'
    },
    'order': {
        'Ascending': 'asc',
        'Descending': 'desc'
    },
    'artifact': 'artifactSource',
    'sort': {
        'App Name': 'app_name',
        'App Packagename': 'app_packagename',
        'File type': 'filetype',
        'Size': 'size',
        'Finish Date': 'finish_date',
        'First Seen (Create Date)': 'create_date',
        'Last Updated (Update Date)': 'update_date',
        'MD5': 'md5',
        'SHA1': 'sha1',
        'SHA256': 'sha256',
        'Ssdeep Fuzzy Hash': 'ssdeep',
        'Application': 'app',
        'Device Country': 'device_country',
        'Device Country Code': 'device_countrycode',
        'Device Hostname': 'device_hostname',
        'Device Serial': 'device_serial',
        'Device vsys': 'vsys',
        'Destination Country': 'dst_country',
        'Destination Country Code': 'dst_countrycode',
        'Destination IP': 'dst_ip',
        'Destination Port': 'dst_port',
        'Email Charset': 'emailsbjcharset',
        'Industry': 'device_industry',
        'Source Country': 'src_country',
        'Source Country Code': 'src_countrycode',
        'Source IP': 'src_ip',
        'Source Port': 'src_port',
        'Time': 'tstamp',
        'Upload source': 'upload_srcPossible'
    },
    'tag_class': {
        'Actor': 'actor',
        'Campaign': 'campaign',
        'Exploit': 'exploit',
        'Malicious Behavior': 'malicious_behavior',
        'Malware Family': 'malware_family'

    },
    'search_arguments': {
        'file_hash': {
            'api_name': 'alias.hash_lookup',
            'operator': 'is'
        },
        'domain': {
            'api_name': 'alias.domain',
            'operator': 'contains'
        },
        'ip': {
            'api_name': 'alias.ip_address',
            'operator': 'contains'
        },
        'url': {
            'api_name': 'alias.url',
            'operator': 'contains'
        },
        'wildfire_verdict': {
            'api_name': 'sample.malware',
            'operator': 'is',
            'translate': {
                'Malware': 1,
                'Grayware': 2,
                'Benign': 3,
                'Phishing': 4,
            }
        },
        'first_seen': {
            'api_name': 'sample.create_date',
            'operator': IS_IN_THE_RANGE
        },
        'last_updated': {
            'api_name': 'sample.update_date',
            'operator': IS_IN_THE_RANGE
        },
        'time_range': {
            'api_name': IS_IN_THE_RANGE,
            'operator': IS_IN_THE_RANGE
        },
        'time_after': {
            'api_name': IS_IN_THE_RANGE,
            'operator': 'is after'
        },
        'time_before': {
            'api_name': IS_IN_THE_RANGE,
            'operator': 'is before'
        }
    },

    'file_indicators': {
        'Size': 'Size',
        'SHA1': 'SHA1',
        'SHA256': 'SHA256',
        'FileType': 'Type',
        'Tags': 'Tags',
        'FileName': 'Name'
    },
    'search_results': {
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'filetype': 'FileType',
        'malware': 'Verdict',
        'size': 'Size',
        'create_date': 'Created',
        'finish_date': 'Finished',
        'md5': 'MD5',
        'region': 'Region',
        'tag': 'Tags',
        '_id': 'ID',
        'tstamp': 'Seen',
        'filename': 'FileName',
        'device_industry': 'Industry',
        'upload_src': 'UploadSource',
        'fileurl': 'FileURL',
        'artifact': 'Artifact',
    }
}

SAMPLE_ANALYSIS_LINE_KEYS = {
    'behavior': {
        'display_name': 'behavior',
        'indexes': {
            'risk': 0,
            'behavior': -1
        }
    },
    'process': {
        'display_name': 'processes',
        'indexes': {
            'parent_process': 0,
            'action': 1
        }
    },
    'file': {
        'display_name': 'files',
        'indexes': {
            'parent_process': 0,
            'action': 1
        }
    },
    'registry': {
        'display_name': 'registry',
        'indexes': {
            'action': 1,
            'parameters': 2
        }
    },
    'dns': {
        'display_name': 'DNS',
        'indexes': {
            'query': 0,
            'response': 1
        }
    },
    'http': {
        'display_name': 'HTTP',
        'indexes': {
            'host': 0,
            'method': 1,
            'url': 2
        }
    },
    'connection': {
        'display_name': 'connections',
        'indexes': {
            'destination': 2
        }
    },
    'mutex': {
        'display_name': 'mutex',
        'indexes': {
            'process': 0,
            'action': 1,
            'parameters': 2
        }
    }
}

SAMPLE_ANALYSIS_COVERAGE_KEYS = {
    'wf_av_sig': {
        'display_name': 'wildfire_signatures',
        'fields': ['name', 'create_date']
    },
    'fileurl_sig': {
        'display_name': 'fileurl_signatures',
        'fields': ['name', 'create_date']
    },
    'dns_sig': {
        'display_name': 'dns_signatures',
        'fields': ['name', 'create_date']
    },
    'url_cat': {
        'display_name': 'url_categories',
        'fields': ['url', 'cat']
    }
}

IS_PY3 = sys.version_info[0] == 3
if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)

else:
    STRING_TYPES = (str, unicode)  # type: ignore # noqa: F821
    STRING_OBJ_TYPES = STRING_TYPES


def get_hash_type(hash_file):
    hash_len = len(hash_file)
    if hash_len == 32:
        return 'md5'
    elif hash_len == 40:
        return 'sha1'
    elif hash_len == 64:
        return 'sha256'
    elif hash_len == 128:
        return 'sha512'
    else:
        return 'Unknown'


def argToList(arg, separator=',', transform=None):
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
            except ValueError:
                demisto.debug('Failed to load {} as JSON, trying to split'.format(arg))  # type: ignore[str-bytes-safe]
        if is_comma_separated:
            result = [s.strip() for s in arg.split(separator)]
    else:
        result = [arg]

    if transform:
        return [transform(s) for s in result]

    return result


def validate_no_query_and_indicators(query, arg_list):
    if query and any(arg_list):
        raise Exception(
            'The search command can either run a search using a custom query '
            'or use the builtin arguments, but not both'
        )


def validate_no_multiple_indicators_for_search(arg_dict):
    used_arg = None
    for arg, val in arg_dict.items():
        if val and used_arg:
            raise Exception(
                f'The search command can receive one indicator type at a time, two were given: {used_arg}, {arg}.'
                ' For multiple indicator types use the custom query')
        elif val:
            used_arg = arg
    if not used_arg:
        raise Exception('In order to perform a samples/sessions search, a query or an indicator must be given.')
    return used_arg


def build_indicator_children_query(used_indicator, indicators_values):
    children_list = []
    if indicators_values:
        field_api_name = API_PARAM_DICT['search_arguments'][used_indicator]['api_name']  # type: ignore
        operator = API_PARAM_DICT['search_arguments'][used_indicator]['operator']  # type: ignore
        children_list = children_list_generator(field_api_name, operator, indicators_values)
    return children_list


def children_list_generator(field_name, operator, val_list):
    query_list = []
    for value in val_list:
        query_list.append({
            'field': field_name,
            'operator': operator,
            'value': value
        })
    return query_list


def build_logic_query(logic_operator, condition_list):
    return {
        'operator': {'AND': 'all', 'OR': 'any'}.get(logic_operator),
        'children': condition_list
    }


def build_sample_search_query(used_indicator, indicators_values, wildfire_verdict, first_seen, last_updated):
    indicator_list = build_indicator_children_query(used_indicator, indicators_values)
    indicator_query = build_logic_query('OR', indicator_list)
    filtering_args_for_search = {}

    if wildfire_verdict:
        wildfire_verdict_value = API_PARAM_DICT.get('search_arguments', {}).get('wildfire_verdict', {}).get('translate',
                                                                                                            {}).get(
            wildfire_verdict)
        if wildfire_verdict_value:
            filtering_args_for_search['wildfire_verdict'] = wildfire_verdict_value

    if first_seen:
        filtering_args_for_search['first_seen'] = first_seen
    if last_updated:
        filtering_args_for_search['last_updated'] = last_updated

    filters_list = build_children_query(filtering_args_for_search)
    filters_list.append(indicator_query)
    logic_query = build_logic_query('AND', filters_list)

    return json.dumps(logic_query)


def build_children_query(args_for_query):
    children_list = []  # type: ignore
    for key, val in args_for_query.items():
        field_api_name = API_PARAM_DICT['search_arguments'][key]['api_name']  # type: ignore
        operator = API_PARAM_DICT['search_arguments'][key]['operator']  # type: ignore
        children_list += children_list_generator(field_api_name, operator, [val])
    return children_list


def run_search(search_object: str, query: str, scope: Optional[str] = None, size: str = None, sort: str = None,
               order: str = None, artifact_source: str = None):
    autofocus = Autofocus()
    result = autofocus.do_search(search_object, query=json.loads(query), scope=scope, size=size, sort=sort, order=order,
                                 artifact_source=artifact_source, err_operation='Search operation failed')
    in_progress = result.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    search_info = {
        'AFCookie': result.get('af_cookie'),
        'Status': status,
        'SessionStart': datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    }
    return search_info


def batch(iterable, batch_size=1):
    current_batch = iterable[:batch_size]
    not_batched = iterable[batch_size:]
    while current_batch:
        yield current_batch
        current_batch = not_batched[:batch_size]
        not_batched = not_batched[batch_size:]


def search_samples(query=None, scope=None, size=None, sort=None, order=None, file_hash=None, domain=None,
                   ip=None,
                   url=None, wildfire_verdict=None, first_seen=None, last_updated=None, artifact_source=None):
    validate_no_query_and_indicators(query,
                                     [file_hash, domain, ip, url, wildfire_verdict, first_seen, last_updated])
    if not query:
        indicator_args_for_query = {
            'file_hash': file_hash,
            'domain': domain,
            'ip': ip,
            'url': url
        }
        used_indicator = validate_no_multiple_indicators_for_search(indicator_args_for_query)
        search_result = []
        for _batch in batch(indicator_args_for_query[used_indicator], batch_size=100):
            query = build_sample_search_query(used_indicator, _batch, wildfire_verdict, first_seen, last_updated)
            search_result.append(run_search('samples', query=query, scope=scope, size=size, sort=sort, order=order,
                                            artifact_source=artifact_source))
        return search_result
    return run_search('samples', query=query, scope=scope, size=size, sort=sort, order=order,
                      artifact_source=artifact_source)


def createContextSingle(obj, id=None, keyTransform=None, removeNull=False):
    res = {}  # type: dict
    if keyTransform is None:
        def keyTransform(s): return s  # noqa
    keys = obj.keys()
    for key in keys:
        if removeNull and obj[key] in ('', None, [], {}):
            continue
        values = key.split('.')
        current = res
        for v in values[:-1]:
            current.setdefault(v, {})
            current = current[v]
        current[keyTransform(values[-1])] = obj[key]

    if id is not None:
        res.setdefault('ID', id)

    return res


def createContext(data, id=None, keyTransform=None, removeNull=False):
    if isinstance(data, (list, tuple)):
        return [createContextSingle(d, id, keyTransform, removeNull) for d in data]
    else:
        return createContextSingle(data, id, keyTransform, removeNull)


def validate_sort_and_order_and_artifact(sort: Optional[str] = None, order: Optional[str] = None,
                                         artifact_source: Optional[str] = None) -> bool:
    if artifact_source == 'true' and sort:
        raise Exception('Please remove or disable one of sort or artifact,'
                        ' As they are not supported in the api together.')
    elif sort and not order:
        raise Exception('Please specify the order of sorting (Ascending or Descending).')
    elif order and not sort:
        raise Exception('Please specify a field to sort by.')
    return bool(sort and order)


def search_sessions(query=None, size=None, sort=None, order=None, file_hash=None, domain=None, ip=None, url=None,
                    from_time=None, to_time=None):
    validate_no_query_and_indicators(query, [file_hash, domain, ip, url, from_time, to_time])
    if not query:
        indicator_args_for_query = {
            'file_hash': file_hash,
            'domain': domain,
            'ip': ip,
            'url': url
        }
        used_indicator = validate_no_multiple_indicators_for_search(indicator_args_for_query)
        search_result = []
        for _batch in batch(indicator_args_for_query[used_indicator], batch_size=100):
            query = build_session_search_query(used_indicator, _batch, from_time, to_time)
            search_result.append(run_search('sessions', query=query, size=size, sort=sort, order=order))
        return search_result
    return run_search('sessions', query=query, size=size, sort=sort, order=order)


def build_session_search_query(used_indicator, indicators_batch, from_time, to_time):
    indicator_list = build_indicator_children_query(used_indicator, indicators_batch)
    indicator_query = build_logic_query('OR', indicator_list)
    time_filters_for_search = {}  # type: ignore
    if from_time and to_time:
        time_filters_for_search = {'time_range': [from_time, to_time]}
    elif from_time:
        time_filters_for_search = {'time_after': [from_time]}
    elif to_time:
        time_filters_for_search = {'time_before': [to_time]}

    filters_list = build_children_query(time_filters_for_search)
    filters_list.append(indicator_query)
    logic_query = build_logic_query('AND', filters_list)
    return json.dumps(logic_query)


def get_search_results(search_object, af_cookie):
    autofocus = Autofocus()
    results = autofocus.run_get_search_results(search_object, af_cookie)
    retry_count = 0
    while (not results.get('hits') and (results.get('af_complete_percentage', 0) != 100)) and retry_count < 10:
        time.sleep(5)
        results = autofocus.run_get_search_results(search_object, af_cookie)
        retry_count += 1
    parsed_results = parse_hits_response(results.get('hits'), 'search_results')
    in_progress = results.get('af_in_progress')
    status = 'in progress' if in_progress else 'complete'
    return parsed_results, status


def parse_hits_response(hits, response_dict_name):
    parsed_objects = []  # type: ignore
    if not hits:
        return parsed_objects
    else:
        for hit in hits:
            flattened_obj = {}  # type: ignore
            flattened_obj.update(hit.get('_source'))
            flattened_obj['_id'] = hit.get('_id')
            parsed_obj = get_fields_from_hit_object(flattened_obj, response_dict_name)
            parsed_objects.append(parsed_obj)
        return parsed_objects


def get_fields_from_hit_object(result_object, response_dict_name):
    new_object = {}
    af_params_dict = API_PARAM_DICT.get(response_dict_name)
    for key, value in result_object.items():
        if key in af_params_dict:  # type: ignore
            new_key = af_params_dict.get(key)  # type: ignore
            new_object[new_key] = value
        else:
            new_object[key] = value
    return new_object


def get_files_data_from_results(results):
    files = []
    if results:
        for result in results:
            raw_file = get_fields_from_hit_object(result, 'file_indicators')
            file_data = filter_object_entries_by_dict_values(raw_file, 'file_indicators')
            files.append(file_data)
    return files


def filter_object_entries_by_dict_values(result_object, response_dict_name):
    af_params_dict = API_PARAM_DICT.get(response_dict_name)
    result_object_filtered = {}
    if af_params_dict and isinstance(result_object, dict) and isinstance(af_params_dict, dict):
        for key in result_object:
            if key in af_params_dict.values():  # type: ignore
                result_object_filtered[key] = result_object.get(key)
    return result_object_filtered


def parse_sample_analysis_response(resp, filter_data_flag):
    analysis = {}
    for category_name, category_data in resp.items():
        if category_name in SAMPLE_ANALYSIS_LINE_KEYS:
            new_category = {}
            for os_name, os_data in category_data.items():
                os_sanitized_data = parse_lines_from_os(category_name, os_data, filter_data_flag)
                new_category[os_name] = os_sanitized_data

            category_dict = SAMPLE_ANALYSIS_LINE_KEYS.get(category_name)
            analysis.update({category_dict['display_name']: new_category})  # type: ignore

        elif category_name == 'coverage':
            new_category = parse_coverage_sub_categories(category_data)
            analysis.update(new_category)

    return analysis


def parse_coverage_sub_categories(coverage_data):
    new_coverage = {}
    if isinstance(coverage_data, dict):
        for sub_category_name, sub_category_data in coverage_data.items():
            if sub_category_name in SAMPLE_ANALYSIS_COVERAGE_KEYS and isinstance(sub_category_data, dict):
                new_sub_category_data = get_data_from_coverage_sub_category(sub_category_name, sub_category_data)
                new_sub_category_name = SAMPLE_ANALYSIS_COVERAGE_KEYS.get(sub_category_name, {}).get('display_name', '')
                new_coverage[new_sub_category_name] = new_sub_category_data
    return {'coverage': new_coverage}


def get_data_from_coverage_sub_category(sub_category_name, sub_category_data):
    sub_categories_list = []
    fields_to_extract = (SAMPLE_ANALYSIS_COVERAGE_KEYS.get(sub_category_name) or {}).get('fields', [])

    if not isinstance(sub_category_data, list):
        return sub_categories_list

    for item in sub_category_data:
        new_sub_category = {}
        for field in fields_to_extract:
            new_sub_category[field] = item.get(field)
        sub_categories_list.append(new_sub_category)
    return sub_categories_list


def parse_lines_from_os(category_name, data, filter_data_flag):
    new_lines = []
    for info_line in data:
        if not filter_data_flag or validate_if_line_needed(category_name, info_line):
            new_sub_categories = get_data_from_line(info_line.get('line'), category_name)
            new_lines.append(new_sub_categories)
    return new_lines


def validate_if_line_needed(category, info_line):
    line = info_line.get('line')
    line_values = line.split(',')
    category_indexes = SAMPLE_ANALYSIS_LINE_KEYS.get(category).get('indexes')  # type: ignore
    if category == 'behavior':
        risk_index = category_indexes.get('risk')  # type: ignore
        risk = line_values[risk_index].strip()
        return risk != 'informational'
    elif category == 'registry':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        return action in ('SetValueKey', 'CreateKey', 'RegSetValueEx')
    elif category == 'file':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        benign_count = info_line.get('b') if info_line.get('b') else 0
        malicious_count = info_line.get('m') if info_line.get('m') else 0
        return action in ('Create', 'CreateFileW') and malicious_count > benign_count
    elif category == 'process':
        action_index = category_indexes.get('action')  # type: ignore
        action = line_values[action_index].strip()
        return action in ('created', 'CreateProcessInternalW')
    else:
        return True


def get_data_from_line(line, category_name):
    category_indexes = SAMPLE_ANALYSIS_LINE_KEYS.get(category_name).get('indexes')  # type: ignore
    values = line.split(',')
    sub_categories = {}  # type: ignore
    if not category_indexes:
        return sub_categories
    else:
        for sub_category in category_indexes:  # type: ignore
            sub_category_index = category_indexes.get(sub_category)  # type: ignore
            sub_categories.update({
                sub_category: values[sub_category_index]
            })
        return sub_categories


def string_to_context_key(string):
    if isinstance(string, STRING_OBJ_TYPES):
        return "".join(word.capitalize() for word in string.split('_'))
    else:
        raise Exception('The key is not a string: {}'.format(string))


def is_ipv6_valid(address):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return True


def parse_indicator_response(res, raw_tags, indicator_type):
    indicator = {}
    indicator['IndicatorValue'] = res.get('indicatorValue', '')
    indicator['IndicatorType'] = res.get('indicatorType', '')
    indicator['LatestPanVerdicts'] = res.get('latestPanVerdicts', '')
    indicator['WildfireRelatedSampleVerdictCounts'] = res.get('wildfireRelatedSampleVerdictCounts', '')
    indicator['SeenBy'] = res.get('seenByDataSourceIds', '')

    first_seen = res.get('firstSeenTsGlobal', '')
    last_seen = res.get('lastSeenTsGlobal', '')

    if first_seen:
        indicator['FirstSeen'] = timestamp_to_datestring(first_seen)
    if last_seen:
        indicator['LastSeen'] = timestamp_to_datestring(last_seen)

    if raw_tags:
        tags = []
        for tag in raw_tags:
            tags.append({
                'PublicTagName': tag.get('public_tag_name', ''),
                'TagName': tag.get('tag_name', ''),
                'CustomerName': tag.get('customer_name', ''),
                'Source': tag.get('source', ''),
                'TagDefinitionScopeID': tag.get('tag_definition_scope_id', ''),
                'TagDefinitionStatusID': tag.get('tag_definition_status_id', ''),
                'TagClassID': tag.get('tag_class_id', ''),
                'Count': tag.get('count', ''),
                'Lasthit': tag.get('lasthit', ''),
                'Description': tag.get('description', '')})
        indicator['Tags'] = tags

    if indicator_type == 'Domain':
        indicator['WhoisAdminCountry'] = res.get('whoisAdminCountry', '')
        indicator['WhoisAdminEmail'] = res.get('whoisAdminEmail', '')
        indicator['WhoisAdminName'] = res.get('whoisAdminName', '')
        indicator['WhoisDomainCreationDate'] = res.get('whoisDomainCreationDate', '')
        indicator['WhoisDomainExpireDate'] = res.get('whoisDomainExpireDate', '')
        indicator['WhoisDomainUpdateDate'] = res.get('whoisDomainUpdateDate', '')
        indicator['WhoisRegistrar'] = res.get('whoisRegistrar', '')
        indicator['WhoisRegistrarUrl'] = res.get('whoisRegistrarUrl', '')
        indicator['WhoisRegistrant'] = res.get('whoisRegistrant', '')

    return indicator


def get_tags_for_tags_and_malware_family_fields(tags: Optional[list], is_malware_family=False):
    if not tags:
        return None
    results = []
    for item in tags:
        results.append(item.get('tag_name'))
        results.append(item.get('public_tag_name'))
        for alias in item.get('aliases', []):
            results.append(alias)
        if not is_malware_family:
            for group in item.get('tagGroups', [{}]):
                results.append(group.get('tag_group_name'))
    return list(set(filter(None, results)))


def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=False):
    naive_datetime = datetime.fromtimestamp(int(timestamp) / 1000.0)

    if is_utc or date_format.endswith('Z'):
        utc_datetime = pytz.utc.localize(naive_datetime)
        return utc_datetime.strftime(date_format)
    else:
        local_timezone = pytz.timezone('Local')  # Replace 'Local' with your desired local timezone
        local_datetime = local_timezone.localize(naive_datetime)
        return local_datetime.strftime(date_format)


def convert_url_to_ascii_character(url_name):
    def convert_non_ascii_chars(non_ascii):
        return str(non_ascii.group(0)).encode('idna').decode("utf-8")

    return re.sub('([^a-zA-Z\W]+)', convert_non_ascii_chars, url_name)


class Autofocus(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        self.apikey = orenctl.getParam("password") if orenctl.getParam("password") else orenctl.getParam("api_key")
        self.use_ssl = True if orenctl.getParam("insecure") else False
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)
        self.verify = True

    def http_request(self, method, url, *args, **kwargs):
        response = self.session.request(method=method, url=url, verify=self.verify, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise ValueError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def do_search(self, search_object: str, query: dict, scope: Optional[str], size: Optional[str] = None,
                  sort: Optional[str] = None, order: Optional[str] = None, err_operation: Optional[str] = None,
                  artifact_source: Optional[str] = None) -> dict:
        path = '/samples/search' if search_object == 'samples' else '/sessions/search'
        data = {
            'query': query,
            'size': size
        }
        if scope:
            data.update({'scope': API_PARAM_DICT['scope'][scope]})  # type: ignore
        if validate_sort_and_order_and_artifact(sort, order, artifact_source):
            data.update(
                {'sort': {API_PARAM_DICT['sort'][sort]: {'order': API_PARAM_DICT['order'][order]}}})  # type: ignore
        if artifact_source == 'true':
            data.update({'artifactSource': 'af'})
            data.update({'type': 'scan'})
        # Remove nulls
        data = createContext(data, removeNull=True)
        result = self.http_request(path, data=data, err_operation=err_operation)
        return result

    def run_get_search_results(self, search_object, af_cookie):
        path = f'/samples/results/{af_cookie}' if search_object == 'samples' else f'/sessions/results/{af_cookie}'
        results = self.http_request(path, err_operation='Fetching search results failed')
        return results

    def get_session_details(self, session_id):
        path = f'/session/{session_id}'
        result = self.http_request(path, err_operation='Get session failed')
        parsed_result = parse_hits_response(result.get('hits'), 'search_results')
        return parsed_result

    def sample_analysis(self, sample_id, os, filter_data_flag):
        path = f'/sample/{sample_id}/analysis'
        data = {
            'coverage': 'true'
        }
        if os:
            data['platforms'] = [os]  # type: ignore

        result = self.http_request(path, data=data, err_operation='Sample analysis failed')
        if 'error' in result:
            return orenctl.results(result['error'])
        analysis_obj = parse_sample_analysis_response(result, filter_data_flag)

        return analysis_obj

    def search_indicator(self, indicator_type, indicator_value):
        headers = HEADERS.copy()  # Make a copy of HEADERS
        headers.update({'apiKey': self.apikey})  # Add or update the apiKey
        params = {
            'indicatorType': indicator_type,
            'indicatorValue': indicator_value,
            'includeTags': 'true',
        }

        return self.http_request(
            method='GET',
            url=f'{BASE_URL}/tic',
            verify=self.use_ssl,
            headers=headers,
            params=params
        )


def search_samples_command():
    file_hash = argToList(orenctl.getArg('file_hash'))
    domain = argToList(orenctl.getArg('domain'))
    ip = argToList(orenctl.getArg('ip'))
    url = argToList(orenctl.getArg('url'))
    wildfire_verdict = orenctl.getArg('wildfire_verdict')
    first_seen = argToList(orenctl.getArg('first_seen'))
    last_updated = argToList(orenctl.getArg('last_updated'))
    query = orenctl.getArg('query')
    scope = orenctl.getArg('scope').capitalize()
    max_results = orenctl.getArg('max_results')
    sort = orenctl.getArg('sort')
    order = orenctl.getArg('order')
    artifact_source = orenctl.getArg('artifact')
    info = search_samples(query=query, scope=scope, size=max_results, sort=sort, order=order,
                          file_hash=file_hash,
                          domain=domain, ip=ip, url=url, wildfire_verdict=wildfire_verdict,
                          first_seen=first_seen,
                          last_updated=last_updated, artifact_source=artifact_source)

    orenctl.results({
        "outputs": info,
        "outputs_key_field": "AFCookie",
        "outputs_prefix": "AutoFocus.SamplesSearch"
    })


def search_sessions_command():
    file_hash = argToList(orenctl.getArg('file_hash'))
    domain = argToList(orenctl.getArg('domain'))
    ip = argToList(orenctl.getArg('ip'))
    url = argToList(orenctl.getArg('url'))
    from_time = orenctl.getArg('time_after')
    to_time = orenctl.getArg('time_before')
    time_range = orenctl.getArg('time_range')
    query = orenctl.getArg('query')
    max_results = orenctl.getArg('max_results')
    sort = orenctl.getArg('sort')
    order = orenctl.getArg('order')

    if time_range:
        if from_time or to_time:
            raise Exception(
                "The 'time_range' argument cannot be specified with neither 'time_after' nor 'time_before' arguments.")
        else:
            from_time, to_time = time_range.split(',')

    info = search_sessions(query=query, size=max_results, sort=sort, order=order, file_hash=file_hash, domain=domain,
                           ip=ip, url=url, from_time=from_time, to_time=to_time)
    orenctl.results({
        "outputs_prefix": 'AutoFocus.SessionsSearch',
        "outputs_key_field": 'AFCookie',
        "outputs": info,
    })


def samples_search_results_command():
    af_cookie = orenctl.getArg('af_cookie')
    results, status = get_search_results('samples', af_cookie)
    files = get_files_data_from_results(results)

    context = {
        'AutoFocus.SamplesResults(val.ID === obj.ID)': results,
        'AutoFocus.SamplesSearch(val.AFCookie === obj.AFCookie)': {'Status': status, 'AFCookie': af_cookie},
        outputPaths['file']: files
    }

    if not results:
        raw_response = {}
    else:
        raw_response = results

    orenctl.results({
        "outputs": context,
        "raw_response": raw_response
    })

    return None, status


def sessions_search_results_command():
    af_cookie = orenctl.getArg('af_cookie')
    results, status = get_search_results('sessions', af_cookie)
    files = get_files_data_from_results(results)

    context = {
        'AutoFocus.SessionsResults(val.ID === obj.ID)': results,
        'AutoFocus.SessionsSearch(val.AFCookie === obj.AFCookie)': {'Status': status, 'AFCookie': af_cookie},
        outputPaths['file']: files
    }
    orenctl.results({
        "outputs": context,
        "raw_response": results,
        "status": status
    })


def get_session_details_command():
    autofocus = Autofocus()
    session_id = orenctl.getArg('session_id')
    result = autofocus.get_session_details(session_id)
    files = get_files_data_from_results(result)
    context = {
        'AutoFocus.Sessions(val.ID === obj.ID)': result,
        outputPaths['file']: files
    }
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': result,
        'EntryContext': context,
    })


def sample_analysis_command():
    autofocus = Autofocus()
    sample_id = orenctl.getArg('sample_id')
    os = orenctl.getArg('os')
    filter_data = orenctl.getArg('filter_data') != 'False'
    analysis = autofocus.sample_analysis(sample_id, os, filter_data)
    context = createContext(analysis, keyTransform=string_to_context_key)
    orenctl.results({
        'Type': entryTypes['note'],
        'ContentsFormat': formats['text'],
        'Contents': {'ID': sample_id, 'Analysis': analysis},
        'HumanReadable': f'### Sample Analysis results for {sample_id}:',
        'EntryContext': {'AutoFocus.SampleAnalysis(val.ID == obj.ID)': {'ID': sample_id, 'Analysis': context}},
    })


def search_ip_command():
    autofocus = Autofocus()
    indicator_type = 'IP'
    ip_list = argToList(orenctl.getArg("ip"))

    command_results = []

    for ip_address in ip_list:
        ip_type = 'ipv6_address' if is_ipv6_valid(ip_address) else 'ipv4_address'
        raw_res = autofocus.search_indicator(ip_type, ip_address)

        indicator = raw_res.get('indicator')
        if indicator:
            raw_tags = raw_res.get('tags')

            ip = {
                "ip": ip_address,
                "malware_family": get_tags_for_tags_and_malware_family_fields(raw_tags, True)
            }
            autofocus_ip_output = parse_indicator_response(indicator, raw_tags, indicator_type)

        else:

            ip = {
                "ip": ip_address,
            }
            autofocus_ip_output = {'IndicatorValue': ip_address}

        command_results.append({
            "outputs_prefix": 'AutoFocus.IP',
            "outputs_key_field": 'IndicatorValue',
            "outputs": autofocus_ip_output,
            "raw_response": raw_res,
            "indicator": ip,
        })

    return command_results


def search_url_command():
    autofocus = Autofocus()
    indicator_type = 'URL'
    url_list = argToList(orenctl.getArg("url"))

    command_results = []

    for url_name in url_list:
        raw_res = autofocus.search_indicator('url', convert_url_to_ascii_character(url_name))

        indicator = raw_res.get('indicator')
        if indicator:
            indicator['indicatorValue'] = url_name
            raw_tags = raw_res.get('tags')

            url = {
                "url": url_name,
                "malware_family": get_tags_for_tags_and_malware_family_fields(raw_tags, True),
            }

            autofocus_url_output = parse_indicator_response(indicator, raw_tags, indicator_type)
            autofocus_url_output = {k: v for k, v in autofocus_url_output.items() if v}

        else:

            url = {
                "url": url_name,
            }
            autofocus_url_output = {'IndicatorValue': url_name}

        command_results.append({
            "outputs_prefix": 'AutoFocus.URL',
            "outputs_key_field": 'IndicatorValue',
            "outputs": autofocus_url_output,
            "raw_response": raw_res,
            "indicator": url,
        })

    return command_results


def search_file_command():
    autofocus = Autofocus()
    indicator_type = 'File'
    file_list = argToList(orenctl.getArg("file"))

    command_results = []

    for file_hash in file_list:
        raw_res = autofocus.search_indicator('filehash', file_hash.lower())

        indicator = raw_res.get('indicator')
        if indicator:
            raw_tags = raw_res.get('tags')

            autofocus_file_output = parse_indicator_response(indicator, raw_tags, indicator_type)

            hash_type = get_hash_type(file_hash)

            file = {
                "md5": file_hash if hash_type == 'md5' else None,
                "sha1": file_hash if hash_type == 'sha1' else None,
                "sha256": file_hash if hash_type == 'sha256' else None,
                "malware_family": get_tags_for_tags_and_malware_family_fields(raw_tags, True),
            }
        else:

            hash_type = get_hash_type(file_hash)
            hash_val_arg = {hash_type: file_hash}
            file = {
                "hash_val_arg": hash_val_arg
            }
            autofocus_file_output = {'IndicatorValue': file_hash}

        command_results.append({
            "outputs_prefix": 'AutoFocus.File',
            "outputs_key_field": 'IndicatorValue',
            "outputs": autofocus_file_output,
            "raw_response": raw_res,
            "indicator": file,
        })

    return command_results


def search_domain_command():
    autofocus = Autofocus()
    indicator_type = 'Domain'
    domain_name_list = argToList(orenctl.getArg("domain"))

    command_results = []

    for domain_name in domain_name_list:
        raw_res = autofocus.search_indicator('domain', domain_name)
        indicator = raw_res.get('indicator')

        if indicator:
            raw_tags = raw_res.get('tags')
            domain = {
                "domain": domain_name,
                "creation_date": "-".join((indicator.get("whoisDomainCreationDate") or '').split("-")[::-1]),
                "expiration_date": "-".join((indicator.get('whoisDomainExpireDate') or '').split("-")[::-1]),
                "updated_date": "-".join((indicator.get('whoisDomainUpdateDate') or '').split("-")[::-1]),
                "admin_email": indicator.get('whoisAdminEmail'),
                "admin_name": indicator.get('whoisAdminName'),
                "admin_country": indicator.get('whoisAdminCountry'),
                "registrar_name": indicator.get('whoisRegistrar'),
                "registrant_name": indicator.get('whoisRegistrant'),
                "malware_family": get_tags_for_tags_and_malware_family_fields(raw_tags, True),
            }
            autofocus_domain_output = parse_indicator_response(indicator, raw_tags, indicator_type)

        else:

            domain = {
                "domain": domain_name,
            }
            autofocus_domain_output = {'IndicatorValue': domain_name}

        command_results.append({
            "outputs_prefix": 'AutoFocus.Domain',
            "outputs_key_field": 'IndicatorValue',
            "outputs": autofocus_domain_output,
            "raw_response": raw_res,
            "indicator": domain,
        })
    return command_results


if orenctl.command() == "autofocus_search_samples":
    search_samples_command()
elif orenctl.command() == "autofocus_search_sessions":
    search_sessions_command()
elif orenctl.command() == "autofocus_samples_search_results":
    samples_search_results_command()
elif orenctl.command() == "autofocus_sessions_search_results":
    sessions_search_results_command()
elif orenctl.command() == "autofocus_get_session_details":
    get_session_details_command()
elif orenctl.command() == "autofocus_sample_analysis":
    sample_analysis_command()
elif orenctl.command() == "ip":
    search_ip_command()
elif orenctl.command() == "url":
    search_url_command()
elif orenctl.command() == "domain":
    search_domain_command()
elif orenctl.command() == "file":
    search_file_command()
