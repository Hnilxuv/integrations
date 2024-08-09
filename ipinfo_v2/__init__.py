import requests
import orenctl


class IPInfoV2(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")
        self.session = requests.session()
        self.session.headers = {
            "accept": "application/json",
            "Content-Type": "application/json"
        }
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=self.insecure, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise Exception(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def ipinfo_ip(self, ip_address):
        return self.http_request(
            method="GET",
            url_suffix=f"/{ip_address}/json",
            params={"token": self.api_key}
        )


def ipinfo_command():
    ipinfo = IPInfoV2()
    ip_address = orenctl.getArg("ip_address")
    if not ip_address:
        orenctl.results(orenctl.error("IP address is required"))
        return

    result = ipinfo.ipinfo_ip(ip_address)

    orenctl.results({
        "ip_info": result
    })
    return


if orenctl.command() == "ipinfo_ip":
    ipinfo_command()