import calendar
import json
import re
import time

import requests
from requests import HTTPError

import orenctl

STRING_TYPES = (str, bytes)
STRING_OBJ_TYPES = (str,)
LOGIN_PAGE = "/admin/launch?script=rh&template=login"
LOGIN_ACTION = "/admin/launch?script=rh&template=login&action=login"
LOGOUT_PAGE = "/admin/launch?script=rh&template=logout&action=logout"
TAG = "tag:rotation-file"


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


def date_to_timestamp(date_str_or_dt, date_format='%Y-%m-%dT%H:%M:%S'):
    if isinstance(date_str_or_dt, STRING_OBJ_TYPES):
        return int(time.mktime(time.strptime(date_str_or_dt, date_format)) * 1000)

    # otherwise datetime.datetime
    return int(time.mktime(date_str_or_dt.timetuple()) * 1000)


class EndaceWebSession(object):
    LOGIN_PAGE = "/admin/launch?script=rh&template=login"
    LOGIN_ACTION = "/admin/launch?script=rh&template=login&action=login"
    LOGOUT_PAGE = "/admin/launch?script=rh&template=logout&action=logout"

    def __init__(self, app_url=None, username=None, password=None, cert_verify=False):
        self.app_url = app_url
        self.username = username
        self.password = password
        self.requests = None
        self.verify = cert_verify


class EndaceVisionAPIAdapter(object):
    API_BASE = "/vision2/data"

    def __init__(self, endace_session):
        self.endace_session = endace_session

    def request(self, method, path, **kwargs):
        headers = {}
        if method == "POST":
            csrf_cookie = self.endace_session.requests.cookies.get("vision2_csrf_cookie")
            if csrf_cookie:
                headers = {
                    'XSRF-csrf-token': str(csrf_cookie)
                }
        try:
            r = self.endace_session.requests.request(
                method, self.endace_session.page("{}/{}".format(self.API_BASE, path)), headers=headers, **kwargs)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            return err.response.status_code
        else:
            return r

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self.request("PUT", path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request("DELETE", path, **kwargs)


class EndaceVisionData(object):
    def __init__(self, args=None):
        self.args = args

    def build_search_data(self):
        investigation_data = {
            "type": "TrafficBreakdownNG",
            "breakdown_type": "datasource",
            "datasource_guids": [TAG],
            "start_time": int(self.args['start']) * 1000,
            "end_time": int(self.args['end']) * 1000,
            "filter": self.get_filters(),
            "order_by": "bytes",
            "required_aggregates": ["bytes"],
            "order_direction": "desc",
            "other_required": True,
            "points": 10,
            "auto_pivot": True,
            "disable_uvision": False,
            "disable_mvision": False
        }
        return investigation_data

    def get_filters(self):
        filters = {
            "visionObjectType": "filter",
            "visionObjectValue": {
                "active": "basic",
                "basic": {
                    "visionObjectType": "basicFilter",
                    "visionObjectValue": {
                        "filters": self.get_basicfilters()
                    }
                }
            }
        }

        return filters

    def build_archive_data(self):
        archive_data = {
            "filename": self.args['archive_filename'],
            "deduplication": False,
            "bidirection": False,
            "datasources": self.get_datasources(),
            "timerange": self.get_timerange(),
            "filters": self.get_filters(),
            "individualSessionData": False
        }

        return archive_data

    def get_timerange(self):

        timerange = {
            "visionObjectType": "timerange",
            "visionObjectValue": {
                "start": {
                    "seconds": int(self.args['start']),
                    "nanoseconds": 0
                },
                "end": {
                    "seconds": int(self.args['end']),
                    "nanoseconds": 0
                }
            }
        }
        return timerange

    def get_datasources(self):
        datasources = {
            "key": TAG,
            "datasource": {
                "id": TAG,
                "type": "tag",
                "name": "rotation-file",
                "probeName": "tag",
                "displayName": TAG,
                "status": {
                    "inUse": False,
                    "readers": [],
                    "writers": []
                },
                "vision": True,
                "mplsLevel1": 1,
                "mplsLevel2": "BOTTOM",
                "metadataTimerange": {
                    "visionObjectType": "timerange",
                    "visionObjectValue": {
                        "start": {
                            "seconds": self.args['start'],
                            "nanoseconds": 0
                        },
                        "end": {
                            "seconds": self.args['end'],
                            "nanoseconds": 0
                        }
                    }
                },
                "packetTimerange": {
                    "visionObjectType": "timerange",
                    "visionObjectValue": {
                        "start": {
                            "seconds": self.args['start'],
                            "nanoseconds": 0
                        },
                        "end": {
                            "seconds": self.args['end'],
                            "nanoseconds": 0
                        }
                    }
                },
                "datasourceIds": self.args['ids']
            },
            "missing": False
        }

        return [datasources]

    def get_basicfilters(self):
        allfilterslist = []
        visionobjecttype = "basicFilterDirectionlessIp"
        for filtertype in self.args['filterby']:
            filterlist = []
            visionobjecttype = self.check_filtertype(filterlist, filtertype, visionobjecttype)
            if filtertype == 4:
                visionobjecttype = "basicFilterDestinationPort"
                for dport in self.args['dest_port_list']:
                    filterlist.append(dport)
            if filtertype == 5:
                visionobjecttype = "basicFilterIpProtocol"
                filterlist.append(self.args['protocol'])
            if filtertype == 6:
                visionobjecttype = "basicFilterDirectionlessPort"
                filterlist.append(self.args['port'])
            if filtertype == 7:
                visionobjecttype = "basicFilterVlan"
                for vlan in self.args.vlan1list:
                    filterlist.append(vlan)

            visionfilter = {
                "visionObjectType": visionobjecttype,
                "visionObjectValue": {
                    "version": 1,
                    "include": True,
                    "value": filterlist
                }
            }

            allfilterslist.append(visionfilter)

        return allfilterslist

    def check_filtertype(self, filterlist, filtertype, visionobjecttype):
        if filtertype == 0:
            visionobjecttype = "basicFilterDirectionlessIp"
            filterlist.append(self.args['ip'])
        if filtertype == 1:
            visionobjecttype = "basicFilterSourceIp"
            for sip in self.args['src_host_list']:
                filterlist.append(sip)
        if filtertype == 2:
            visionobjecttype = "basicFilterDestinationIp"
            for dip in self.args['dest_host_list']:
                filterlist.append(dip)
        if filtertype == 3:
            visionobjecttype = "basicFilterSourcePort"
            for sport in self.args['src_port_list']:
                filterlist.append(sport)
        return visionobjecttype


def arg_data():
    args = {
        "start": orenctl.getArg("start") if orenctl.getArg("start") else None,
        "end": orenctl.getArg("end") if orenctl.getArg("end") else None,
        "ip": orenctl.getArg("ip") if orenctl.getArg("ip") else None,
        "port": orenctl.getArg("port") if orenctl.getArg("port") else None,
        "src_host_list": orenctl.getArg("src_host_list") if orenctl.getArg("src_host_list") else None,
        "dest_host_list": orenctl.getArg("dest_host_list") if orenctl.getArg("dest_host_list") else None,
        "src_port_list": orenctl.getArg("src_port_list") if orenctl.getArg("src_port_list") else None,
        "dest_port_list": orenctl.getArg("dest_port_list") if orenctl.getArg("dest_port_list") else None,
        "protocol": orenctl.getArg("protocol") if orenctl.getArg("protocol") else None,
        "timeframe": orenctl.getArg("timeframe") if orenctl.getArg("timeframe") else None
    }
    return args


class Endace(object):
    delta_time = 120
    wait_time = 5

    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.username = orenctl.getParam("username")
        self.password = orenctl.getParam("password")
        self.hostname = orenctl.getParam("hostname")
        self.session = requests.session()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def endace_get_input_arguments(self, args=None):
        timeframe_converter = {'30seconds': 30, '1minute': 60, '5minutes': 300, '10minutes': 600, '30minutes': 1800,
                               '1hour': 3600, '2hours': 7200, '5hours': 18000, '10hours': 36000, '12hours': 43200,
                               '1day': 86400, '3days': 259200, '5days': 432000, '1week': 604800}

        function_args = dict()

        function_args['start'] = args.get("start")
        if args.get("start"):
            function_args['start'] = date_to_timestamp(args.get("start")) / 1000

        function_args['end'] = args.get("end")
        if args.get("end"):
            function_args['end'] = date_to_timestamp(args.get("end")) / 1000

        function_args['timeframe'] = timeframe_converter.get(args.get("timeframe"))

        function_args['ip'] = args.get("ip")
        function_args['port'] = args.get("port")
        function_args['src_host_list'] = list(set(arg_to_list(args.get("src_host_list"))))[:10]
        function_args['dest_host_list'] = list(set(arg_to_list(args.get("dest_host_list"))))[:10]
        function_args['src_port_list'] = list(set(arg_to_list(args.get("src_port_list"))))[:10]
        function_args['dest_port_list'] = list(set(arg_to_list(args.get("dest_port_list"))))[:10]

        function_args['protocol'] = args.get("protocol")

        self.check_value_error(function_args)

        self.check_error_value(args, function_args)

        if function_args['end'] < function_args['start']:
            orenctl.results(orenctl.error('Wrong argument - value of EndTime - cannot be before StartTime'))
        if int(function_args['start']) > (calendar.timegm(time.gmtime()) - 10):
            orenctl.results(
                orenctl.error(f'Wrong argument - value of StartTime - {args.get("start")} UTC cannot be in future'))
        if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
            orenctl.results(
                orenctl.error(f'Wrong argument - value of EndTime - {args.get("end")} UTC cannot be in future'))

        return function_args

    def check_error_value(self, args, function_args):
        if not function_args['start'] and not function_args['end']:
            function_args['end'] = int(calendar.timegm(time.gmtime()) - 10)
            function_args['start'] = (int(function_args['end']) - int(function_args['timeframe']))
        elif function_args['start'] and not function_args['end']:
            if int(function_args['start']) > (calendar.timegm(time.gmtime()) - 10):
                orenctl.results(
                    orenctl.error(f'Wrong argument - value of StartTime - {args.get("start")} UTC cannot be in future'))
            function_args['end'] = int(function_args['start']) + int(function_args['timeframe'])
            if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
                orenctl.results(orenctl.error('Wrong argument - value of EndTime - adjust '
                                              'timeframe argument such that EndTime is not in future'))
        elif not function_args['start'] and function_args['end']:
            if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
                orenctl.results(
                    orenctl.error(f'Wrong argument - value of EndTime - {args.get("end")} UTC cannot be in future'))
            function_args['start'] = (int(function_args['end']) - int(function_args['timeframe']))

    def check_value_error(self, function_args):
        if (len(function_args['src_host_list']) + len(function_args['dest_host_list'])
            + len(function_args['src_port_list']) + len(function_args['dest_port_list'])) > 10:
            orenctl.results(orenctl.error("Wrong number of filters items - Limit search filters to 10 items"))
        if not function_args['ip'] and not function_args['src_host_list'] and not function_args['dest_host_list']:
            orenctl.results(orenctl.error("Wrong or missing value - Src and Dest IP arguments"))
        if not function_args['start'] and not function_args['end'] and not function_args['timeframe']:
            orenctl.results(orenctl.error("Wrong arguments - StartTime, EndTime or TimeFrame is invalid "))
        elif (not function_args['start'] or not function_args['end']) and not function_args['timeframe']:
            orenctl.results(orenctl.error("Wrong arguments - either StartTime or EndTime or Timeframe is invalid "))
        if function_args['start'] and function_args['end']:
            if function_args['start'] == function_args['end']:
                orenctl.results(
                    orenctl.error("Wrong arguments - value of StartTime and EndTime argument - both are same"))

    def create_search_task(self, args=None):
        input_args_dict = args
        input_args_dict.update({"filterby": []})

        result = {"Task": "CreateSearchTask", "Status": "Started", "Error": "NoError", "JobID": ""}

        self.check_input(input_args_dict)

        with EndaceWebSession(app_url=self.url, username=self.username, password=self.password,
                              cert_verify=self.insecure) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/"
                evid = EndaceVisionData(input_args_dict)
                rp = api.post(path, json=evid.build_search_data())
                if rp.status_code == 200:
                    try:
                        response = rp.json()
                    except json.decoder.JSONDecodeError:
                        orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
                    else:
                        meta = response.get("meta", {})
                        payload = response.get("payload")
                        if meta:
                            self.check_meta(meta, path, payload, result)
                        else:
                            result['Status'] = "Failed"
                            result['Error'] = f"ServerError - empty meta data from {path}"
                else:
                    result['Status'] = "Failed"
                    result['Error'] = f"HTTP {rp.status_code} to /{path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"HTTP {rd.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def check_meta(self, meta, path, payload, result):
        meta_error = meta.get("error")
        if meta_error is not None:
            if meta_error is not False:
                result['Status'] = "Failed"
                result['Error'] = str(meta_error)
            else:
                if payload is not None:
                    result['JobID'] = payload
                else:
                    result['Status'] = "Failed"
                    result['Error'] = f"ServerError - empty payload data from {path}"

    def check_input(self, input_args_dict):
        if input_args_dict['ip']:
            input_args_dict['filterby'].append(0)
        if input_args_dict['src_host_list']:
            input_args_dict['filterby'].append(1)
        if input_args_dict['dest_host_list']:
            input_args_dict['filterby'].append(2)
        if input_args_dict['src_port_list']:
            input_args_dict['filterby'].append(3)
        if input_args_dict['dest_port_list']:
            input_args_dict['filterby'].append(4)
        if input_args_dict['protocol']:
            input_args_dict['filterby'].append(5)
        if input_args_dict['port']:
            input_args_dict['filterby'].append(6)

    def handle_error_notifications(self, eperror):
        error_dict = {"common.notAuthorized": "Authorization issue due to incorrect RBAC roles on EndaceProbe",
                      "duration.invalidInput": "Fix Invalid search starttime, endtime or timeframe",
                      "timestamp.invalidInput": "Fix Invalid search starttime, endtime or timeframe",
                      "query.serviceLayerError": "One of the search parameters have invalid syntax",
                      "filter.invalidFilterFormat": "One of the search parameters have invalid syntax",
                      "download.emptyDatasource": "Empty Packet Datasource, this happens when packet data has "
                                                  "rotated out but metadata is still available due to incorrect "
                                                  "datastore sizing configuration. Contact support@endace.com for "
                                                  "any technical assistance on optimal datasource sizing",
                      "FileNotFound": "File not found on EndaceProbe",
                      "SearchTimeOut": "Search query has timed out. Improve search by narrowing search filter "
                                       "items - IP addresses, Port or Timeframe. If problem persists "
                                       "contact support@endace.com to review EndaceProbe configuration",
                      }

        raise orenctl.results(
            orenctl.error(error_dict.get(eperror, f"try again. contact support@endace.com and report {eperror} "
                                                  f"if problem persists")))

    def get_search_status(self, args=None):
        result = {'Task': "GetSearchStatus", "Status": "complete", "Error": "NoError", "JobProgress": '0',
                  "DataSources": [], "TotalBytes": 0, "JobID": args}

        matching_data = 0
        keys = []
        values = []
        id_to_key_dict = dict()
        app_dict = dict()

        with EndaceWebSession(app_url=self.url, username=self.username, password=self.password,
                              cert_verify=self.insecure) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/" + args
                progress_status = True
                query_time = calendar.timegm(time.gmtime())
                while progress_status:
                    current_time = calendar.timegm(time.gmtime())
                    if current_time - query_time > self.delta_time:
                        progress_status = False
                        result['Status'] = "InProgress"
                        result['Error'] = "SearchTimeOut"
                    else:
                        rj = api.get(path)
                        progress_status = self.check_rj(app_dict, id_to_key_dict, keys, matching_data, path,
                                                        progress_status, result, rj, values)
                    time.sleep(self.wait_time)
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rd.status_code} to /{path}"

        if result['Status'] != 'complete':
            self.handle_error_notifications(result['Error'])
        return result

    def check_rj(self, app_dict, id_to_key_dict, keys, matching_data, path, progress_status, result, rj, values):
        if rj.status_code == 200:
            try:
                response = rj.json()
            except json.decoder.JSONDecodeError:
                raise orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
            else:
                meta = response.get("meta", {})
                if meta:
                    meta_error = meta.get("error")
                    progress_status = self.check_meta_error(app_dict, id_to_key_dict, keys,
                                                            matching_data, meta_error, path,
                                                            progress_status, response, result, values)
                else:
                    progress_status = False
                    result['Status'] = "Failed"
                    result['Error'] = f"ServerError - empty meta data from {path}"
        else:
            progress_status = False
            result['Status'] = rj.status_code
            result['Error'] = f"ServerError - HTTP {rj.status_code} to /{path}"
        return progress_status

    def check_meta_error(self, app_dict, id_to_key_dict, keys, matching_data, meta_error, path, progress_status,
                         response, result, values):
        if meta_error is not None:
            if meta_error is not False:
                progress_status = False
                result['Status'] = "complete"
                result['Error'] = str(meta_error)
            else:
                payload = response.get("payload")
                progress_status = self.check_payload(app_dict, id_to_key_dict, keys, matching_data, path, payload,
                                                     progress_status, result, values)
        return progress_status

    def check_payload(self, app_dict, id_to_key_dict, keys, matching_data, path, payload, progress_status, result,
                      values):
        if payload is not None:
            progress = payload.get("progress")
            if progress is not None:
                result['JobProgress'] = str(progress)
                payload_data = payload.get("data")
                if payload_data is not None:
                    progress_status = self.check_payload_data(app_dict, id_to_key_dict,
                                                              keys, matching_data,
                                                              payload, payload_data,
                                                              progress, progress_status,
                                                              result, values)
        else:
            progress_status = False
            result['Status'] = "Failed"
            result['Error'] = f"ServerError - empty payload data from {path}"
        return progress_status

    def check_payload_data(self, app_dict, id_to_key_dict, keys, matching_data, payload, payload_data, progress,
                           progress_status, result, values):
        if int(progress) == 100:
            progress_status = False
            for data_map_dict in payload_data:
                id_to_key_dict[data_map_dict['id']] = \
                    data_map_dict['name']

            for top_key in payload["top_keys"]:
                keys.append(id_to_key_dict[top_key])

            for top_value in payload["top_values"]:
                matching_data = matching_data + int(top_value)
                values.append(str(top_value))

            result['TotalBytes'] = int(matching_data)

            for index in range(len(keys)):
                app_dict[keys[index]] = values[index] + ' Bytes'

            result['Status'] = str(payload['state'])
            result['DataSources'] = keys
        return progress_status

    def create_archive_task(self, args=None):
        input_args_dict = args
        input_args_dict.update({"archive_filename": (args.get('archive_filename')
                                                     + '-' + str(calendar.timegm(time.gmtime())))
                                })
        input_args_dict.update({"filterby": []})
        input_args_dict.update({"ids": ""})

        result = {"Task": "CreateArchiveTask", "Status": "Started", "Error": "NoError", "JobID": "",
                  "Start": args.get('start'), "End": args.get('end'), "P2Vurl": "",
                  "FileName": args['archive_filename']}

        datasource = self.hostname + ":" + input_args_dict['archive_filename']

        start_time_in_ms = str(int(input_args_dict['start']) * 1000)
        end_time_in_ms = str(int(input_args_dict['end']) * 1000)

        p2v_url = f'{self.url}/vision2/pivotintovision/?datasources={datasource}' \
                  f'&title={result["FileName"]}&start={start_time_in_ms}&end={end_time_in_ms}' \
                  f'&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress'

        p2v_url = self.check_input_args_dict(input_args_dict, p2v_url)
        if input_args_dict['dest_port_list']:
            input_args_dict['filterby'].append(4)
            port = ''
            for dport in input_args_dict['dest_port_list']:
                port = port + "," + dport
            port = port[1:]
            p2v_url = p2v_url + "&dport=" + port
        if input_args_dict['protocol']:
            input_args_dict['filterby'].append(5)
        if input_args_dict['port']:
            input_args_dict['filterby'].append(6)
            p2v_url = p2v_url + "&port=" + input_args_dict['port']

        evid = EndaceVisionData(input_args_dict)
        with EndaceWebSession(app_url=self.url, username=self.username, password=self.password,
                              cert_verify=self.insecure) as sess:
            rotfile_ids = []

            api = EndaceVisionAPIAdapter(sess)
            path = "datasources"
            rd = api.get(path)
            try:
                response = rd.json()
            except json.decoder.JSONDecodeError:
                orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
            else:
                self.check_rd(api, evid, input_args_dict, p2v_url, path, rd, response, result, rotfile_ids)

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def check_rd(self, api, evid, input_args_dict, p2v_url, path, rd, response, result, rotfile_ids):
        if rd.status_code == 200:
            payload = response.get("payload")
            for rotfile in payload:
                if rotfile["type"] == "rotation_file_v2":
                    rotfile_ids.append(rotfile["id"])

            input_args_dict['ids'] = rotfile_ids

            path = "archive/"
            rp = api.post(path, json=evid.build_archive_data())
            self.check_rp(p2v_url, path, rd, result, rp)
        else:
            result['Status'] = "Failed"
            result['Error'] = f"HTTP {rd.status_code} to /{path}"

    def check_rp(self, p2v_url, path, rd, result, rp):
        if rp.status_code == 200:
            try:
                response = rp.json()
            except json.decoder.JSONDecodeError:
                orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
            else:
                meta = response.get("meta", {})
                payload = response.get("payload")
                self.check_meta_create_archive_task(meta, p2v_url, path, payload, result)
        else:
            result['Status'] = "Failed"
            result['Error'] = f"HTTP {rd.status_code} to /{path}"

    def check_meta_create_archive_task(self, meta, p2v_url, path, payload, result):
        if meta:
            meta_error = meta.get("error")
            if meta_error is not None:
                if meta_error is not False:
                    result['Status'] = "Failed"
                    result['Error'] = str(meta_error)
                else:
                    if payload is not None:
                        result['JobID'] = payload
                        result['P2Vurl'] = f'[Endace PivotToVision URL]({p2v_url})'
                    else:
                        result['Status'] = "Failed"
                        result['Error'] = f"ServerError - empty payload data from {path}"
        else:
            result['Status'] = "Failed"
            result['Error'] = f"ServerError - empty meta data from {path}"

    def check_input_args_dict(self, input_args_dict, p2v_url):
        if input_args_dict['ip']:
            input_args_dict['filterby'].append(0)
            p2v_url = p2v_url + "&ip=" + input_args_dict['ip']
        if input_args_dict['src_host_list']:
            input_args_dict['filterby'].append(1)
            src_ip = ''
            for ip in input_args_dict['src_host_list']:
                src_ip = src_ip + "," + ip
            src_ip = src_ip[1:]
            p2v_url = p2v_url + "&sip=" + src_ip
        if input_args_dict['dest_host_list']:
            input_args_dict['filterby'].append(2)
            dest_ip = ''
            for ip in input_args_dict['dest_host_list']:
                dest_ip = dest_ip + "," + ip
            dest_ip = dest_ip[1:]
            p2v_url = p2v_url + "&dip=" + dest_ip
        if input_args_dict['src_port_list']:
            input_args_dict['filterby'].append(3)
            port = ''
            for sport in input_args_dict['src_port_list']:
                port = port + "," + sport
            port = port[1:]
            p2v_url = p2v_url + "&sport=" + port
        return p2v_url

    def get_archive_status(self, args=None):
        result = {"Task": "GetArchiveStatus", "Error": "NoError", "Status": "InProgress",
                  "FileName": args['archive_filename'], "FileSize": 0}

        with EndaceWebSession(app_url=self.url, username=self.username, password=self.password,
                              cert_verify=self.insecure) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            progress_status = True
            query_time = calendar.timegm(time.gmtime())

            while progress_status:
                time.sleep(self.wait_time)
                current_time = calendar.timegm(time.gmtime())
                if current_time - query_time > self.delta_time:
                    progress_status = False
                    result['Status'] = "InProgress"

                rf = api.get(path)
                progress_status = self.check_rf(args, path, progress_status, result, rf)

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def check_rf(self, args, path, progress_status, result, rf):
        if rf.status_code == 200:
            try:
                response = rf.json()
            except json.decoder.JSONDecodeError:
                orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
            else:
                meta = response.get("meta", {})
                payload = response.get("payload")
                progress_status = self.check_meta_get_archive_status(args, meta, path, payload, progress_status,
                                                                     result)
        else:
            progress_status = False
            result['Status'] = rf.status_code
            result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"
        return progress_status

    def check_meta_get_archive_status(self, args, meta, path, payload, progress_status, result):
        if meta:
            meta_error = meta["error"]
            if meta_error is not None:
                progress_status = self.check_meta_error_get_archive_status(args, meta_error, payload, progress_status,
                                                                           result)

        else:
            progress_status = False
            result['Status'] = "Failed"
            result['Error'] = f"ServerError - empty meta data from {path}"
        return progress_status

    def check_meta_error_get_archive_status(self, args, meta_error, payload, progress_status, result):
        if meta_error is not False:
            progress_status = False
            result['Status'] = "InProgress"
            result['Error'] = str(meta_error)
        else:
            for file in payload:
                if args['archive_filename'] == file['name']:
                    result['FileName'] = file['name']
                    if not file['status']['inUse']:
                        progress_status = False
                        result['FileSize'] = file['usage']
                        result['Status'] = "Finished"
                    else:
                        result['Status'] = "InProgress"
                    break
        return progress_status

    def download_pcap(self, args=None):
        result = {"Task": "DownloadPCAP", "Error": "NoError", "Status": "FileNotFound", "FileName": args['filename'],
                  "FileSize": 0, "FileType": "UnKnown", "FileURL": 'UnKnown', "FileUser": 'UnKnown'}
        with EndaceWebSession(app_url=self.url, username=self.username, password=self.password,
                              cert_verify=self.insecure) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rf = api.get(path)
            if rf.status_code == 200:
                try:
                    response = rf.json()
                except json.decoder.JSONDecodeError:
                    orenctl.results(orenctl.error(f"JsonDecodeError - path {path}"))
                else:
                    meta = response.get("meta", {})
                    payload = response.get("payload")
                    if meta:
                        meta_error = meta["error"]
                        self.check_meta_error_download_pcap(api, args, meta_error, path, payload, result, rf)
                    else:
                        result['Status'] = "Failed"
                        result['Error'] = f"ServerError - empty meta data from {path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def check_meta_error_download_pcap(self, api, args, meta_error, path, payload, result, rf):
        if meta_error is not None:
            if meta_error is not False:
                result['Status'] = "FileNotFound"
                result['Error'] = str(meta_error)
            else:
                for file in payload:
                    self.check_payload_download(api, args, file, path, result, rf)

    def check_payload_download(self, api, args, file, path, result, rf):
        if result['FileName'] == file['name'] and len(file["id"]):
            file_numerical_part = float(re.findall(r'[\d\.]+', file['usage'])[0])

            if 'KB' in file['usage']:
                filesize = file_numerical_part * 0.001
            elif 'GB' in file['usage']:
                filesize = file_numerical_part * 1000
            elif 'TB' in file['usage']:
                filesize = file_numerical_part * 1000000
            else:
                filesize = file_numerical_part * 1

            self.check_filesize(api, args, file, filesize, path, result, rf)

    def check_filesize(self, api, args, file, filesize, path, result, rf):
        if filesize <= int(args['filesizelimit']):
            result['FileName'] = file['name'] + ".pcap"
            if not file['status']['inUse']:
                #   File available to download
                pcapfile_url_path = ("files/%s/stream?format=pcap" % file["id"])
                d = api.get(pcapfile_url_path)
                if d.status_code == 200:
                    result['FileURL'] = f'[Endace PCAP URL]' \
                                        f'({self.url}/vision2/data/' \
                                        f'{pcapfile_url_path})'

                    result['FileSize'] = file['usage']
                    result['Status'] = "DownloadFinished"
                    result['FileType'] = file['type']
                    result['FileUser'] = file['user']
                else:
                    result['Status'] = "FileNotFound"
                    result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"
            else:
                result['Status'] = "FileInUse"
        else:
            result['Status'] = "FileExceedsSizeLimit"


def endace_create_search_command():
    app = Endace()
    args = arg_data()
    if len(args.values()):

        function_args = app.endace_get_input_arguments(args)

        result = app.create_search_task(function_args)

        output = {'Endace.Search.Task(val.JobID == obj.JobID)': result}
        raw_response = result

        results = {"output": output, "raw_response": raw_response}
        orenctl.results(results)
    else:
        orenctl.results(orenctl.error("No arguments were provided to search by, at least one must be provided"))


def endace_get_search_status_command():
    app = Endace()
    jobid = orenctl.getArg("jobid")
    if len(re.findall(r'([0-9a-fA-F]+)', jobid)) == 5:
        result = app.get_search_status(jobid)

        output = {'Endace.Search.Response(val.JobID == obj.JobID)': result}
        raw_response = result

        results = {"output": output, "raw_response": raw_response}
        orenctl.results(results)

    else:
        orenctl.results(orenctl.error("Wrong JOB ID provided"))


def endace_create_archive_command():
    app = Endace()
    args = arg_data()
    if len(args.values()):
        if re.fullmatch(r'[\w-]+', args.get("archive_filename")) is None:
            raise ValueError("Wrong format of archive_filename. text, numbers, underscore or dash is supported")

        function_args = app.endace_get_input_arguments(args)
        function_args['archive_filename'] = args.get("archive_filename")

        result = app.create_archive_task(function_args)

        output = {'Endace.Archive.Task(val.JobID == obj.JobID)': result}
        raw_response = result
        results = {"output": output, "raw_response": raw_response}
        orenctl.results(results)
    else:
        orenctl.results(orenctl.error("No arguments were provided to search by, at least one Filter item, "
                                      "either start/end time or timeframe is required "))


def endace_get_archive_status_command():
    app = Endace()
    args = arg_data()
    if len(args.values()):
        function_args = dict()
        if re.fullmatch(r'[\w-]+', args.get("archive_filename")) is None:
            raise ValueError("Wrong format of archive_filename. text, numbers, underscore or dash is supported")
        function_args['archive_filename'] = args.get("archive_filename")

        result = app.get_archive_status(function_args)

        output = {'Endace.Archive.Response(val.FileName == obj.FileName)': result}
        raw_response = result
        results = {"output": output, "raw_response": raw_response}
        orenctl.results(results)
    else:
        orenctl.results(orenctl.error("Archived FileName must be provided"))


def endace_download_pcap_command():
    app = Endace()
    args = arg_data()
    if len(args.values()):
        function_args = {"filename": args.get("filename"), "filesizelimit": args.get("filesizelimit")}

        try:
            int(function_args['filesizelimit'])
        except ValueError:
            raise ValueError("Filesize Limit value is incorrect, must be an integer 1  or greater")
        else:
            if int(function_args['filesizelimit']) < 1:
                raise ValueError("Filesize Limit value is incorrect, must be an integer 1  or greater")

            result = app.download_pcap(function_args)

            output = {'Endace.Download.PCAP(val.FileName == obj.FileName)': result}
            raw_response = result
            results = {"output": output, "raw_response": raw_response}
            orenctl.results(results)
    else:
        orenctl.results(orenctl.error("FileName must be provided"))


if orenctl.command() == "endace_create_search":
    endace_create_search_command()
elif orenctl.command() == "endace_get_search_status":
    endace_get_search_status_command()
elif orenctl.command() == "endace_create_archive":
    endace_create_archive_command()
elif orenctl.command() == "endace_get_archive_status":
    endace_get_archive_status_command()
elif orenctl.command() == "endace_download_pcap":
    endace_download_pcap_command()
