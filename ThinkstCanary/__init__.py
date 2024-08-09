import requests

import orenctl


class ThinkSTCanary(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")
        self.auth = {"auth_token": self.api_key}
        self.session = requests.session()
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url_suffix, params=None, *args, **kwargs):
        full_url = self.url + "/api/v1/" + url_suffix
        if not params:
            params = self.auth
        else:
            params.update(self.auth)
        response = self.session.request(method=method, url=full_url, params=params, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise requests.HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def list_canaries(self):
        return self.http_request(method="GET", url_suffix="devices/all")

    def list_tokens(self):
        return self.http_request(method="GET", url_suffix="canarytokens/fetch")

    def check_whitelist(self, params):
        return self.http_request(method="GET",
                                 url_suffix="settings/is_ip_whitelisted",
                                 params=params)

    def get_token(self, params):
        return self.http_request(method="GET",
                                 url_suffix="canarytoken/fetch",
                                 params=params)

    def whitelist_ip(self, params):
        return self.http_request(method="GET",
                                 url_suffix="settings/whitelist_ip_port",
                                 params=params)

    def edit_alert_status(self, status, params):
        if status == "Acknowledge":
            return self.http_request(method="POST",
                                     url_suffix="incident/acknowledge",
                                     params=params)
        return self.http_request(method="POST",
                                 url_suffix="incident/unacknowledge",
                                 params=params)


def get_token_command():
    client = ThinkSTCanary()
    token = orenctl.getParam("")
