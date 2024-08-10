import os
import tempfile

import requests

import orenctl


class CloudConvert(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")
        self.session = requests.session()
        self.session.headers = {
            "Authorization": f"Bearer {self.api_key}"
        }
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, full_url, url_suffix, *args, **kwargs):
        if not full_url:
            full_url = self.url + url_suffix
        response = self.session.request(method=method, url=full_url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise requests.HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def upload_url(self, data):
        return self.http_request(
            method='POST',
            full_url=None,
            url_suffix='import/url',
            data=data,
        )

    def upload_file_by_filename(self, file_dict):

        response_get_form = self.http_request(
            method='POST',
            full_url=None,
            url_suffix='/import/upload'
        )
        form = response_get_form.get("data", {}).get("result", {}).get("form")

        port_url = form.get('url')
        params = form.get('parameters')

        if port_url is None or params is None:
            orenctl.results(orenctl.error('Failed to initiate an upload operation'))
            raise ValueError('Failed to initiate an upload operation')

        self.http_request(
            method='POST',
            url_suffix=None,
            full_url=port_url,
            files=file_dict,
            data=params
        )

    def convert(self, data):
        return self.http_request(
            method='POST',
            full_url=None,
            url_suffix='/convert',
            data=data,
        )

    def check_status(self, task_id):
        return self.http_request(
            method='GET',
            full_url=None,
            url_suffix=f'/tasks/{task_id}'
        )

    def download_url(self, data):
        return self.http_request(
            method='POST',
            full_url=None,
            url_suffix='/export/url',
            data=data
        )


def upload_file_command():
    client = CloudConvert()
    url = orenctl.getArg("url")
    location = orenctl.getArg("location")
    file_name = orenctl.getArg("file_name")
    if url:
        result = client.upload_url({"url": url})
        orenctl.results({
            "command_status": "success",
            "upload_result": result
        })
        return result
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, file_name)
    orenctl.download_file(location, path)
    file_dict = {'file': (file_name, open(path, 'rb'))}
    result = client.upload_file_by_filename(file_dict)
    orenctl.results({
        "command_status": "success",
        "upload_result": result
    })
    return result


def convert_command():
    client = CloudConvert()
    data = {
        "input": orenctl.getArg("task_id"),
        "output_format": orenctl.getArg("output_format")
    }
    results = client.convert(data)
    results_data = results.get('data')
    if not results_data:
        orenctl.results({
            "command_status": "fail",
            "convert_result": results.get('message', 'No response from server')
        })
        return results

    orenctl.results({
        "command_status": "success",
        "convert_result": results_data
    })
    return results


def check_status_command():
    client = CloudConvert()
    task_id = orenctl.getArg("task_id")
    results = client.check_status(task_id)
    results_data = results.get('data')
    if not results_data:
        orenctl.results({
            "task_status": results.get('message', 'No response from server')
        })
        return results

    orenctl.results({
        "task_status": results_data
    })
    return results


def download_command():
    client = CloudConvert()
    results = client.download_url({"input": orenctl.results("task_id")})
    results_data = results.get('data')
    if not results_data:
        orenctl.results({
            "command_status": "fail",
            "download_result": results.get('message', 'No response from server')
        })
        return results

    orenctl.results({
        "command_status": "success",
        "download_result": results_data
    })
    return results


if orenctl.command() == "cloudconvert_upload":
    upload_file_command()
if orenctl.command() == "cloudconvert_convert":
    convert_command()
if orenctl.command() == "cloudconvert_check_status":
    check_status_command()
if orenctl.command() == "cloudconvert_download":
    download_command()
