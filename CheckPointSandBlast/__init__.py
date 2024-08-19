import json
import os
import sys
import uuid
from datetime import datetime
from typing import List, Dict, Any, Optional

import pytz
import requests

import orenctl

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

FEATURE_BY_NAME = {
    'Threat Emulation': 'te',
    'Anti-Virus': 'av',
    'Threat Extraction': 'extraction',
    'All': 'all'
}

MD5_SIZE = 32
SHA1_SIZE = 40
SHA256_SIZE = 64
DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 600

DIGEST_BY_LENGTH = {
    MD5_SIZE: 'md5',
    SHA1_SIZE: 'sha1',
    SHA256_SIZE: 'sha256',
}

EXTRACTED_PARTS_CODE_BY_DESCRIPTION = {
    'Linked Objects': 1025,
    'Macros and Code': 1026,
    'Sensitive Hyperlinks': 1034,
    'PDF GoToR Actions': 1137,
    'PDF Launch Actions': 1139,
    'PDF URI Actions': 1141,
    'PDF Sound Actions': 1142,
    'PDF Movie Actions': 1143,
    'PDF JavaScript Actions': 1150,
    'PDF Submit Form Actions': 1151,
    'Database Queries': 1018,
    'Embedded Objects': 1019,
    'Fast Save Data': 1021,
    'Custom Properties': 1017,
    'Statistic Properties': 1036,
    'Summary Properties': 1037,
}

entryTypes = {'note': 1, 'error': 2, 'pending': 3}
formats = {'html': 'html', 'table': 'table', 'json': 'json', 'text': 'text', 'markdown': 'markdown'}

IS_PY3 = sys.version_info[0] == 3

if IS_PY3:
    STRING_TYPES = (str, bytes)  # type: ignore
    STRING_OBJ_TYPES = (str,)

else:
    STRING_TYPES = (str, unicode)  # type: ignore # noqa: F821
    STRING_OBJ_TYPES = STRING_TYPES  # type: ignore


def getFilePath(id):
    return {'id': id, 'path': 'test/test.txt', 'name': 'test.txt'}


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


def uniqueFile():
    return str(uuid.uuid4())


def investigation():
    return {"id": "1"}


def fileResult(filename, data, file_type=None):
    if file_type is None:
        file_type = entryTypes['file']
    temp = uniqueFile()
    if (IS_PY3 and isinstance(data, str)) or (not IS_PY3 and isinstance(data, unicode)):  # type: ignore # noqa: F821
        data = data.encode('utf-8')
    # pylint: enable=undefined-variable
    with open(investigation()['id'] + '_' + temp, 'wb') as f:
        f.write(data)

    if isinstance(filename, str):
        replaced_filename = filename.replace("../", "")
        if filename != replaced_filename:
            filename = replaced_filename
            orenctl.error(
                "replaced {filename} with new file name {replaced_file_name}".format(
                    filename=filename, replaced_file_name=replaced_filename
                )
            )

    return {'Contents': '', 'ContentsFormat': formats['text'], 'Type': file_type, 'File': filename, 'FileID': temp}


def get_quota_context_output(outputs: Dict[str, Any]):
    response_by_context = {
        'RemainQuotaHour': 'remain_quota_hour',
        'RemainQuotaMonth': 'remain_quota_month',
        'AssignedQuotaHour': 'assigned_quota_hour',
        'AssignedQuotaMonth': 'assigned_quota_month',
        'HourlyQuotaNextReset': 'hourly_quota_next_reset',
        'MonthlyQuotaNextReset': 'monthly_quota_next_reset',
        'QuotaId': 'quota_id',
        'CloudMonthlyQuotaPeriodStart': 'cloud_monthly_quota_period_start',
        'CloudMonthlyQuotaUsageForThisGw': 'cloud_monthly_quota_usage_for_this_gw',
        'CloudHourlyQuotaUsageForThisGw': 'cloud_hourly_quota_usage_for_this_gw',
        'CloudMonthlyQuotaUsageForQuotaId': 'cloud_monthly_quota_usage_for_quota_id',
        'CloudHourlyQuotaUsageForQuotaId': 'cloud_hourly_quota_usage_for_quota_id',
        'MonthlyExceededQuota': 'monthly_exceeded_quota',
        'HourlyExceededQuota': 'hourly_exceeded_quota',
        'CloudQuotaMaxAllowToExceedPercentage': 'cloud_quota_max_allow_to_exceed_percentage',
        'PodTimeGmt': 'pod_time_gmt',
        'QuotaExpiration': 'quota_expiration',
        'Action': 'action',
    }

    context_outputs_with_date = [
        'HourlyQuotaNextReset',
        'MonthlyQuotaNextReset',
        'CloudMonthlyQuotaPeriodStart',
        'PodTimeGmt',
        'QuotaExpiration',
    ]

    output: Dict[str, Any] = {}

    for context_output, response in response_by_context.items():
        output[context_output] = outputs.get(response)

    for key in context_outputs_with_date:
        output[key] = get_date_string(output[key])

    return output


def get_date_string(timestamp_string: str = '0'):
    timestamp = int(timestamp_string) * 1000
    return timestamp_to_datestring(timestamp)


def timestamp_to_datestring(timestamp, date_format="%Y-%m-%dT%H:%M:%S.000Z", is_utc=False):
    naive_datetime = datetime.fromtimestamp(int(timestamp) / 1000.0)

    if is_utc or date_format.endswith('Z'):
        utc_datetime = pytz.utc.localize(naive_datetime)
        return utc_datetime.strftime(date_format)
    else:
        local_timezone = pytz.timezone('Local')  # Replace 'Local' with your desired local timezone
        local_datetime = local_timezone.localize(naive_datetime)
        return local_datetime.strftime(date_format)


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


def arg_to_number(arg, arg_name=None, required=False):
    if is_missing_argument(arg, required):
        raise ValueError(create_missing_argument_message(arg_name))

    arg = encode_string_results(arg)
    if isinstance(arg, str):
        return convert_string_to_number(arg, arg_name)
    elif isinstance(arg, int):
        return arg

    raise ValueError(create_invalid_number_message(arg, arg_name))


def is_missing_argument(arg, required):
    return arg in (None, '') and required


def create_missing_argument_message(arg_name):
    return f'Missing "{arg_name}"' if arg_name else 'Missing required argument'


def convert_string_to_number(arg, arg_name):
    if arg.isdigit():
        return int(arg)
    try:
        return int(float(arg))
    except ValueError:
        raise ValueError(create_invalid_number_message(arg, arg_name))


def create_invalid_number_message(arg, arg_name):
    return f'Invalid number: "{arg_name}"="{arg}"' if arg_name else f'"{arg}" is not a valid number'


def encode_string_results(text):
    if not isinstance(text, STRING_OBJ_TYPES):
        return text
    try:
        return str(text)
    except UnicodeEncodeError:
        return text.encode("utf8", "replace")


def remove_empty_elements(d):
    def empty(x):
        return x is None or x == {} or x == []

    if not isinstance(d, (dict, list)):
        return d
    elif isinstance(d, list):
        return [v for v in (remove_empty_elements(v) for v in d) if not empty(v)]
    else:
        return {k: v for k, v in ((k, remove_empty_elements(v)) for k, v in d.items()) if not empty(v)}


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


def get_analysis_context_output(output: Dict[str, Any]) -> Dict[str, Any]:
    av = dict_safe_get(output, ['av'])
    malware_info = dict_safe_get(av, ['malware_info'])
    extraction = dict_safe_get(output, ['extraction'])
    extraction_data = dict_safe_get(extraction, ['extraction_data'])
    te = dict_safe_get(output, ['te'])

    return remove_empty_elements({
        'Status': dict_safe_get(output, ['status']),
        'MD5': dict_safe_get(output, ['md5']),
        'SHA1': dict_safe_get(output, ['sha1']),
        'SHA256': dict_safe_get(output, ['sha256']),
        'FileType': dict_safe_get(output, ['file_type']),
        'FileName': dict_safe_get(output, ['file_name']),
        'Features': dict_safe_get(output, ['features']),
        'AntiVirus': {
            'SignatureName': dict_safe_get(malware_info, ['signature_name']),
            'MalwareFamily': dict_safe_get(malware_info, ['malware_family']),
            'MalwareType': dict_safe_get(malware_info, ['malware_type']),
            'Severity': dict_safe_get(malware_info, ['severity']),
            'Confidence': dict_safe_get(malware_info, ['confidence']),
            'Status': dict_safe_get(av, ['status']),
        },
        'ThreatExtraction': {
            'Method': dict_safe_get(extraction, ['method']),
            'ExtractResult': dict_safe_get(extraction, ['extract_result']),
            'ExtractedFileDownloadId': dict_safe_get(extraction, ['extracted_file_download_id']),
            'OutputFileName': dict_safe_get(extraction, ['output_file_name']),
            'Time': dict_safe_get(extraction, ['time']),
            'ExtractContent': dict_safe_get(extraction, ['extract_content']),
            'TexProduct': dict_safe_get(extraction, ['tex_product']),
            'Status': dict_safe_get(extraction, ['status']),
            'ExtractionData': {
                'InputExtension': dict_safe_get(extraction_data, ['input_extension']),
                'InputRealExtension': dict_safe_get(extraction_data, ['input_real_extension']),
                'Message': dict_safe_get(extraction_data, ['message']),
                'ProtectionName': dict_safe_get(extraction_data, ['protection_name']),
                'ProtectionType': dict_safe_get(extraction_data, ['protection_type']),
                'ProtocolVersion': dict_safe_get(extraction_data, ['protocol_version']),
                'RealExtension': dict_safe_get(extraction_data, ['real_extension']),
                'Risk': dict_safe_get(extraction_data, ['risk']),
                'ScrubActivity': dict_safe_get(extraction_data, ['scrub_activity']),
                'ScrubMethod': dict_safe_get(extraction_data, ['scrub_method']),
                'ScrubResult': dict_safe_get(extraction_data, ['scrub_result']),
                'ScrubTime': dict_safe_get(extraction_data, ['scrub_time']),
                'ScrubbedContent': dict_safe_get(extraction_data, ['scrubbed_content']),
            },
        },
        'ThreatEmulation': {
            'Trust': dict_safe_get(te, ['trust']),
            'Score': dict_safe_get(te, ['score']),
            'CombinedVerdict': dict_safe_get(te, ['combined_verdict']),
            'Images': dict_safe_get(te, ['images']),
            'Status': dict_safe_get(te, ['status']),
        }
    })


class CheckPointSandBlast(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.reliability = orenctl.getParam("reliability")
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)
        self.verify = True  # or False, depending on your needs

    def http_request(self, method, url, *args, **kwargs):
        response = self.session.request(method=method, url=url, verify=self.verify, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise ValueError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def query_request(
            self,
            features: List[str],
            reports: List[str],
            method: str,
            file_name: str = None,
            extracted_parts_codes: List[int] = None,
            **kwargs
    ):
        json_data = remove_empty_elements({
            'request': {
                'features': features,
                'md5': kwargs.get('md5'),
                'sha1': kwargs.get('sha1'),
                'sha256': kwargs.get('sha256'),
                'file_name': file_name,
                'te': {
                    'reports': reports,
                },
                'extraction': {
                    'extracted_parts_codes': extracted_parts_codes,
                    'method': method
                }
            }
        })

        return self.http_request('POST', url='/query', json_data=json_data)

    def upload_request(
            self,
            file_path: str,
            file_name: str,
            file_type: str,
            features: List[str],
            image_ids: List[str],
            image_revisions: List[Optional[int]],
            reports: List[str],
            method: str,
            extracted_parts_codes: List[int] = None,
    ):
        request = json.dumps(remove_empty_elements({
            'request': {
                'file_name': file_name,
                'file_type': file_type,
                'features': features,
                'te': {
                    'reports': reports,
                    'images': [
                        {'id': image_id, 'image_revision': revision}
                        for image_id, revision in zip(image_ids, image_revisions)
                    ]
                },
                'extraction': {
                    'extracted_parts_codes': extracted_parts_codes,
                    'method': method
                }
            }
        }))

        with open(file_path, 'rb') as file_handler:
            file = (file_name, file_handler.read())

        return self.http_request(
            'POST',
            url='/upload',
            files={
                'request': request,
                'file': file
            }
        )

    def download_request(self, file_id: str):
        return self.http_request(
            'GET',
            url='/download',
            params={
                'id': file_id
            },
            resp_type='response'
        )

    def quota_request(self):
        return self.http_request(
            'POST',
            url='/quota',
        )


def file_command():
    CPSB = CheckPointSandBlast()
    files = argToList(orenctl.getArg('file'))
    command_results = []

    for file_hash in files:
        try:
            hash_type = get_hash_type(file_hash)

            if hash_type not in ('md5', 'sha1', 'sha256'):
                raise ValueError(f'Hash "{file_hash}" is not of type SHA-256, SHA-1 or MD5')

            raw_response = CPSB.query_request(
                features=['te', 'av', 'extraction'],
                reports=['xml', 'summary'],
                method='pdf',
                **{hash_type: file_hash}
            )

            label = dict_safe_get(raw_response, ['response', 'status', 'label'])

            if label not in ('FOUND', 'PARTIALLY_FOUND'):
                message = dict_safe_get(raw_response, ['response', 'status', 'message'])
                command_results.append(f'File not found: "{file_hash}"\n{message}')
                continue

            outputs = remove_empty_elements({
                'MD5': dict_safe_get(raw_response, ['response', 'md5']),
                'SHA1': dict_safe_get(raw_response, ['response', 'sha1']),
                'SHA256': dict_safe_get(raw_response, ['response', 'sha256']),
            })

            command_results.append({
                "outputs_prefix": outputPaths.get('file'),
                "outputs": outputs,
                "raw_response": raw_response,
            })

        except Exception as e:
            command_results.append(f'Could not process file: "{file_hash}"\n{str(e)}')

    orenctl.results(command_results)


def query_command():
    CPSB = CheckPointSandBlast()
    file_name = (orenctl.getArg('file_name') if orenctl.getArg('file_name') else '')
    file_hash = orenctl.getArg('file_hash')
    features = (argToList(orenctl.getArg('features')) if orenctl.getArg('features') else '')
    reports = argToList(orenctl.getArg('reports'))
    method = (orenctl.getArg('method') if orenctl.getArg('method') else '')
    extracted_parts = argToList(orenctl.getArg('extracted_parts'))

    features = [FEATURE_BY_NAME[feature] for feature in features]

    if 'all' in features:
        features = ['te', 'av', 'extraction']

    if 'te' in features and {'pdf', 'summary'}.issubset(reports):
        raise ValueError(
            'Requesting for PDF and summary reports simultaneously is not supported!'
        )

    if method != 'clean':
        extracted_parts_codes = None
    else:
        extracted_parts_codes = [
            EXTRACTED_PARTS_CODE_BY_DESCRIPTION[extracted_part]
            for extracted_part in extracted_parts
        ]

    file_hash_size = len(file_hash)
    digest = DIGEST_BY_LENGTH.get(file_hash_size)

    if digest is None:
        raise ValueError('file_hash is not recognized!')

    raw_output = CPSB.query_request(
        file_name=file_name,
        features=features,
        reports=reports,
        method=method,
        extracted_parts_codes=extracted_parts_codes,
        **{digest: file_hash}
    )

    output = raw_output.get('response', {'': ''})
    output = get_analysis_context_output(output)

    orenctl.results({
        "outputs_prefix": 'SandBlast.Query',
        "outputs_key_field": ['MD5', 'SHA1', 'SHA256'],
        "outputs": output,
        "raw_response": raw_output,
    })


def setup_upload_polling_command():
    args = {}
    return upload_polling_command(args)


def upload_polling_command(args: Dict[str, Any]):
    if 'file_hash' not in args:
        command_results = upload_command()

    else:
        command_results = query_command()

    raw_response = command_results.raw_response

    file_name = dict_safe_get(raw_response, ['response', 'file_name'])
    file_hash = dict_safe_get(raw_response, ['response', 'md5'])
    label = dict_safe_get(raw_response, ['response', 'status', 'label'])

    if label in ('FOUND', 'PARTIALLY_FOUND'):
        orenctl.results({
            "response": command_results,
            "continue_to_poll": False
        })

    polling_args = {
        'file_name': file_name,
        'file_hash': file_hash,
    }

    orenctl.results({
        "response": command_results,
        "continue_to_poll": True,
        "args_for_next_run": polling_args,
        "partial_result": command_results
    })


def upload_command():
    CPSB = CheckPointSandBlast()
    file_id = orenctl.getArg('file_id')
    file_name = orenctl.getArg('file_name')
    features = argToList(orenctl.getArg('features'))
    image_ids = argToList(orenctl.getArg('image_ids'))
    image_revisions = [arg_to_number(image_revision)
                       for image_revision in argToList(orenctl.getArg('image_revisions'))]
    reports = argToList(orenctl.getArg('reports'))
    method = (orenctl.getArg('method') if orenctl.getArg('method') else '')
    extracted_parts = argToList(orenctl.getArg('extracted_parts'))

    file_entry = getFilePath(file_id)

    if not file_name:
        file_name = file_entry['name']

    file_type = os.path.splitext(file_name)[1]

    if file_type != os.path.splitext(file_entry['name'])[1]:
        raise ValueError('New file name must have the same extension as the original file!')

    features = [FEATURE_BY_NAME[feature] for feature in features]

    if 'all' in features:
        features = ['te', 'av', 'extraction']

    if len(image_ids) != len(image_revisions):
        raise ValueError('Image IDs and image revisions must be of same length!')

    if 'te' in features and {'pdf', 'summary'}.issubset(reports):
        raise ValueError(
            'Requesting for PDF and summary reports simultaneously is not supported!'
        )

    if method != 'clean':
        extracted_parts_codes = None
    else:
        extracted_parts_codes = [
            EXTRACTED_PARTS_CODE_BY_DESCRIPTION[extracted_part]
            for extracted_part in extracted_parts
        ]

    raw_output = CPSB.upload_request(
        file_path=file_entry['path'],
        file_name=file_name,
        file_type=file_type,
        features=features,
        image_ids=image_ids,
        image_revisions=image_revisions,
        reports=reports,
        method=method,
        extracted_parts_codes=extracted_parts_codes,
    )

    output = raw_output.get('response', {'': ''})
    output = get_analysis_context_output(output)

    orenctl.results({
        "outputs_prefix": 'SandBlast.Upload',
        "outputs_key_field": ['MD5', 'SHA1', 'SHA256'],
        "outputs": output,
        "raw_response": raw_output
    })


def download_command():
    CPSB = CheckPointSandBlast()
    file_id = orenctl.getArg('file_id')

    output = CPSB.download_request(file_id)

    content_disposition = output.headers.get("Content-Disposition")
    split_content_disposition = content_disposition.split('"') if content_disposition is not None else []

    if len(split_content_disposition) < 2:
        file_name = 'file.pdf'
    else:
        file_name = split_content_disposition[1]

    return fileResult(filename=file_name, data=output.content)


def quota_command():
    CPSB = CheckPointSandBlast()
    raw_outputs = CPSB.quota_request()
    outputs = raw_outputs.get('response')[0]  # type:ignore

    output = get_quota_context_output(outputs)

    orenctl.results({
        "outputs_prefix": 'SandBlast.Quota',
        "outputs_key_field": 'QuotaId',
        "outputs": output,
        "raw_response": raw_outputs,
    })
