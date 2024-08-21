import requests

import orenctl

ENDPOINT = 'Endpoint(val.ID === obj.ID)'


def file_catalog_threat_to_int(threat):
    threat_dict = {
        'Unknown': -1,
        'Clean': 0,
        'Potential risk': 50,
        'Malicious': 100
    }
    return threat_dict.get(threat, threat)


def file_catalog_file_state_to_int(file_state):
    file_state_dict = {
        'Unapproved': 1,
        'Approved': 2,
        'Banned': 3,
        'Approved by Policy': 4,
        'Banned by Policy': 5
    }
    return file_state_dict.get(file_state, file_state)


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


def event_type_to_int(e_type):
    type_dict = {
        'Server Management': 0,
        'Session Management': 1,
        'Computer Management': 2,
        'Policy Management': 3,
        'Policy Enforcement': 4,
        'Discovery': 5,
        'General Management': 6,
        'Internal Events': 8
    }
    return type_dict.get(e_type, e_type)


def event_severity_to_int(severity):
    severity_dict = {
        'Critical': 2,
        'Error': 3,
        'Warning': 4,
        'Notice': 5,
        'Info': 6,
        'Debug': 7
    }
    return severity_dict.get(severity, severity)


def event_type_to_string(e_type):
    type_dict = {
        0: 'Server Management',
        1: 'Session Management',
        2: 'Computer Management',
        3: 'Policy Management',
        4: 'Policy Enforcement',
        5: 'Discovery',
        6: 'General Management',
        8: 'Internal Events'
    }
    return type_dict.get(e_type, e_type)


def event_severity_to_string(severity):
    severity_dict = {
        2: 'Critical',
        3: 'Error',
        4: 'Warning',
        5: 'Notice',
        6: 'Info',
        7: 'Debug'
    }
    return severity_dict.get(severity, severity)


def file_analysis_status_to_int(status):
    status_dict = {
        'scheduled': 0,
        'submitted (file is sent for analysis)': 1,
        'processed (file is processed but results are not available yet)': 2,
        'analyzed (file is processed and results are available)': 3,
        'error': 4,
        'cancelled': 5
    }
    return status_dict.get(status, status)


def file_analysis_result_to_int(result):
    result_dict = {
        'Not yet available': 0,
        'File is clean': 1,
        'File is a potential threat': 2,
        'File is malicious': 3
    }
    return result_dict.get(result, result)


class VMWareCarbonBlackAppControl(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.user_name = orenctl.getParam("user_name")
        self.password = orenctl.getParam("password")
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
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

    def search_file_catalog(self, q=None, limit=None, offset=None, sort=None, group=None, file_name=None,
                            file_type=None,
                            computer_id=None, threat=None, file_state=None, hash_value=None):

        url_params = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "group": group,
            "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
        }
        if file_name:
            url_params['q'].append(f'fileName:{file_name}')
        if file_type:
            url_params['q'].append(f'fileType:{file_type}')
        if computer_id:
            url_params['q'].append(f'computerId:{computer_id}')
        if threat:
            url_params['q'].append(f'threat:{file_catalog_threat_to_int(threat)}')
        if file_state:
            url_params['q'].append(f'fileState:{file_catalog_file_state_to_int(file_state)}')
        if hash_value:
            hash_type = get_hash_type(hash_value)
            if hash_type != 'Unknown':
                url_params['q'].append(f'{hash_type}:{hash_value}')

        return self.http_request('GET', '/fileCatalog', params=url_params)

    def search_computer(self, q=None, limit=None, offset=None, sort=None, group=None, name=None, ip_address=None,
                        mac=None,
                        fields=None):
        url_params = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "group": group,
            "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
        }
        if name:
            url_params['q'].append(f'name:{name}')
        if ip_address:
            url_params['q'].append(f'ipAddress:{ip_address}')
        if mac:
            url_params['q'].append(f'macAddress:{mac}')
        if fields:
            all_fields = [
                'memorySize', 'processorCount', 'processorModel', 'osShortName', 'osName',
                'macAddress', 'machineModel', 'ipAddress', 'name', 'id'
            ]
            all_fields.extend(
                [field for field in fields.split(',') if field not in all_fields])  # add requested unique fields
            url_params['fields'] = ",".join(all_fields)

        return self.http_request('GET', '/Computer', params=url_params)

    def update_computer(self, id, name, computer_tag, description, policy_id, automatic_policy, local_approval,
                        refresh_flags, prioritized, debug_level, kernel_debug_level, debug_flags, debug_duration,
                        cclevel, ccflags, force_upgrade, template):

        body_params = self.get_computer(id)

        update_fields = {
            'id': id,
            'name': name,
            'computerTag': computer_tag,
            'description': description,
            'policyId': policy_id,
            'automaticPolicy': automatic_policy,
            'localApproval': local_approval,
            'refreshFlags': refresh_flags,
            'prioritized': prioritized,
            'debugLevel': debug_level,
            'kernelDebugLevel': kernel_debug_level,
            'debugFlags': debug_flags,
            'debugDuration': debug_duration,
            'ccLevel': cclevel,
            'ccFlags': ccflags,
            'forceUpgrade': force_upgrade,
            'template': template
        }

        for key, value in update_fields.items():
            if value is not None:
                body_params[key] = value

        return self.http_request('POST', '/computer', data=body_params)

    def get_computer(self, id):
        url = f'/Computer/{id}'
        return self.http_request('GET', url)

    def search_event(self, q=None, limit=None, offset=None, sort=None, group=None, e_type=None, computer_id=None,
                     ip_address=None,
                     file_name=None, severity=None, user_name=None, file_catalog_id=None):
        url_params = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "group": group,
            "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
        }
        if e_type:
            url_params['q'].append(f'type:{event_type_to_int(e_type)}')
        if computer_id:
            url_params['q'].append(f'computerId:{computer_id}')
        if ip_address:
            url_params['q'].append(f'ipAddress:{ip_address}')
        if file_name:
            url_params['q'].append(f'fileName:{file_name}')
        if severity:
            url_params['q'].append(f'severity:{event_severity_to_int(severity)}')
        if user_name:
            url_params['q'].append(f'userName:{user_name}')
        if file_catalog_id:
            url_params['q'].append(f'fileCatalogId:{file_catalog_id}')

        return self.http_request('GET', '/event', params=url_params)

    def search_file_analysis(self, q=None, limit=None, offset=None, sort=None, group=None, file_catalog_id=None,
                             connector_id=None, file_name=None, status=None, result=None):
        url_params = {
            "limit": limit,
            "offset": offset,
            "sort": sort,
            "group": group,
            "q": q.split('&') if q else []  # handle multi condition queries in the following formats: a&b
        }
        if file_catalog_id:
            url_params['q'].append(f'fileCatalogId:{file_catalog_id}')
        if connector_id:
            url_params['q'].append(f'connectorId:{connector_id}')
        if file_name:
            url_params['q'].append(f'fileName:{file_name}')
        if status:
            url_params['q'].append(f'analysisStatus:{file_analysis_status_to_int(status)}')
        if result:
            url_params['q'].append(f'analysisResult:{file_analysis_result_to_int(result)}')

        return self.http_request('GET', '/fileAnalysis', params=url_params)


def search_file_catalog_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    raw_catalogs = vmwcbac.search_file_catalog(orenctl.getArg('query'), orenctl.getArg('limit'),
                                               orenctl.getArg('offset'),
                                               orenctl.getArg('sort'),
                                               orenctl.getArg('group'), orenctl.getArg('fileName'),
                                               orenctl.getArg('fileType'),
                                               orenctl.getArg('computerId'), orenctl.getArg('threat'),
                                               orenctl.getArg('fileState'),
                                               orenctl.getArg('hash'))
    catalogs = []
    for catalog in raw_catalogs:
        catalogs.append({
            'Size': catalog.get('fileSize'),
            'Path': catalog.get('pathName'),
            'SHA1': catalog.get('sha1'),
            'SHA256': catalog.get('sha256'),
            'MD5': catalog.get('md5'),
            'Name': catalog.get('fileName'),
            'Type': catalog.get('fileType'),
            'ProductName': catalog.get('productName'),
            'ID': catalog.get('id'),
            'Publisher': catalog.get('publisher'),
            'Company': catalog.get('company'),
            'Extension': catalog.get('fileExtension')
        })
    catalogs = {'File(val.SHA1 === obj.SHA1)': catalogs} if catalogs else None
    orenctl.results({
        "catalogs": catalogs,
        "raw_catalogs": raw_catalogs
    })


def search_computer_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    raw_computers = vmwcbac.search_computer(orenctl.getArg('query'), orenctl.getArg('limit'), orenctl.getArg('offset'),
                                            orenctl.getArg('sort'),
                                            orenctl.getArg('group'), orenctl.getArg('name'),
                                            orenctl.getArg('ipAddress'), orenctl.getArg('macAddress'),
                                            orenctl.getArg('fields'))
    computers = []
    for computer in raw_computers:
        computers.append({
            'Memory': computer.get('memorySize'),
            'Processors': computer.get('processorCount'),
            'Processor': computer.get('processorModel'),
            'OS': computer.get('osShortName'),
            'OSVersion': computer.get('osName'),
            'MACAddress': computer.get('macAddress'),
            'Model': computer.get('machineModel'),
            'IPAddress': computer.get('ipAddress'),
            'Hostname': computer.get('name'),
            'ID': computer.get('id')
        })
    computers = {ENDPOINT: computers} if computers else None
    orenctl.results({
        "computers": computers,
        "raw_computers": raw_computers
    })


def update_computer_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    raw_computers = vmwcbac.update_computer(
        orenctl.getArg('id'),
        orenctl.getArg('name'),
        orenctl.getArg('computerTag'),
        orenctl.getArg('description'),
        orenctl.getArg('policyId'),
        orenctl.getArg('automaticPolicy'),
        orenctl.getArg('localApproval'),
        orenctl.getArg('refreshFlags'),
        orenctl.getArg('prioritized'),
        orenctl.getArg('debugLevel'),
        orenctl.getArg('kernelDebugLevel'),
        orenctl.getArg('debugFlags'),
        orenctl.getArg('debugDuration'),
        orenctl.getArg('cCLevel'),
        orenctl.getArg('cCFlags'),
        orenctl.getArg('forceUpgrade'),
        orenctl.getArg('template'),
    )
    computers = {
        'Memory': raw_computers.get('memorySize'),
        'Processors': raw_computers.get('processorCount'),
        'Processor': raw_computers.get('processorModel'),
        'OS': raw_computers.get('osShortName'),
        'OSVersion': raw_computers.get('osName'),
        'MACAddress': raw_computers.get('macAddress'),
        'Model': raw_computers.get('machineModel'),
        'IPAddress': raw_computers.get('ipAddress'),
        'Hostname': raw_computers.get('name'),
        'ID': raw_computers.get('id')
    }
    orenctl.results({
        ENDPOINT: computers,
        'raw_computers': raw_computers
    })


def get_computer_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    id = orenctl.getArg('id')
    raw_computer = vmwcbac.get_computer(id)
    computer = {
        'Memory': raw_computer.get('memorySize'),
        'Processors': raw_computer.get('processorCount'),
        'Processor': raw_computer.get('processorModel'),
        'OS': raw_computer.get('osShortName'),
        'OSVersion': raw_computer.get('osName'),
        'MACAddress': raw_computer.get('macAddress'),
        'Model': raw_computer.get('machineModel'),
        'IPAddress': raw_computer.get('ipAddress'),
        'Hostname': raw_computer.get('name'),
        'ID': raw_computer.get('id')
    }
    orenctl.results({
        ENDPOINT: computer,
        'raw_computers': raw_computer
    })


def search_event_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    raw_events = vmwcbac.search_event(orenctl.getArg('query'), orenctl.getArg('limit'), orenctl.getArg('offset'),
                                      orenctl.getArg('sort'),
                                      orenctl.getArg('group'), orenctl.getArg('type'), orenctl.getArg('computerId'),
                                      orenctl.getArg('ipAddress'),
                                      orenctl.getArg('fileName'), orenctl.getArg('severity'),
                                      orenctl.getArg('userName'),
                                      orenctl.getArg('fileCatalogId'))
    hr_events = []
    events = []
    if raw_events:
        for event in raw_events:
            event_json = {
                'FilePath': event.get('pathName'),
                'Param1': event.get('param1'),
                'Param2': event.get('param2'),
                'Param3': event.get('param3'),
                'SubTypeName': event.get('subtypeName'),
                'ComputerName': event.get('computerName'),
                'FileName': event.get('fileName'),
                'RuleName': event.get('ruleName'),
                'ProcessFileCatalogID': event.get('processFileCatalogId'),
                'StringID': event.get('stringId'),
                'IPAddress': event.get('ipAddress'),
                'PolicyID': event.get('policyId'),
                'Timestamp': event.get('timestamp'),
                'Username': event.get('userName'),
                'ComputerID': event.get('computerId'),
                'ProcessFileName': event.get('processFileName'),
                'IndicatorName': event.get('indicatorName'),
                'SubType': event.get('subtype'),
                'Type': event.get('type'),
                'ID': event.get('id'),
                'Description': event.get('description'),
                'Severity': event.get('severity'),
                'CommandLine': event.get('commandLine'),
                'ProcessPathName': event.get('processPathName')
            }
            events.append(event_json)
            hr_event_json = dict(event_json)
            hr_event_json['Type'] = event_type_to_string(hr_event_json['Type'])
            hr_event_json['Severity'] = event_severity_to_string(hr_event_json['Severity'])
            hr_events.append(hr_event_json)
    events = {'CBP.Event(val.ID === obj.ID)': events} if events else None
    orenctl.results({
        'CBP.Event(val.ID === obj.ID)': events,
        'raw_events': raw_events
    })


def search_file_analysis_command():
    vmwcbac = VMWareCarbonBlackAppControl()
    raw_file_analysis = vmwcbac.search_file_analysis(orenctl.getArg('query'), orenctl.getArg('limit'),
                                                     orenctl.getArg('offset'), orenctl.getArg('sort'),
                                                     orenctl.getArg('group'), orenctl.getArg('fileCatalogId'),
                                                     orenctl.getArg('connectorId'),
                                                     orenctl.getArg('fileName'), orenctl.getArg('analysisStatus'),
                                                     orenctl.getArg('analysisResult'))
    file_analysis = []
    if raw_file_analysis:
        for analysis in raw_file_analysis:
            file_analysis.append({
                'Priority': analysis.get('priority'),
                'FileName': analysis.get('fileName'),
                'PathName': analysis.get('pathName'),
                'ComputerId': analysis.get('computerId'),
                'DateModified': analysis.get('dateModified'),
                'ID': analysis.get('id'),
                'FileCatalogId': analysis.get('fileCatalogId'),
                'DateCreated': analysis.get('dateCreated'),
                'CreatedBy': analysis.get('createdBy')
            })
    file_analysis = {'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis} if file_analysis else None
    orenctl.results({
        'CBP.FileAnalysis(val.ID === obj.ID)': file_analysis,
        'raw_file_analysis': raw_file_analysis
    })


if orenctl.command() == 'cbp_fileCatalog_search':
    search_file_catalog_command()
elif orenctl.command() == 'cbp_computer_search':
    search_computer_command()
elif orenctl.command() == ' cbp_computer_update':
    update_computer_command()
elif orenctl.command() == ' cbp_computer_get':
    get_computer_command()
elif orenctl.command() == ' cbp_event_search':
    search_event_command()
elif orenctl.command() == ' cbp_fileAnalysis_search':
    search_file_analysis_command()
