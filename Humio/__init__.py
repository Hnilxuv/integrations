import requests
from requests import HTTPError

import orenctl

res_error = "Error: response from server was: "
args_url = "/api/v1/repositories/"
app_json = "application/json"
output = "Humio.Alert(val.id == obj.id)"

class Humio(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.api_key = orenctl.getParam("api_key")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.proxy = orenctl.getParam("proxy")
        self.session = requests.session()
        self.session.headers = {
            "Content-Type": app_json,
            "Authorization": f"Bearer {self.api_key}"
        }

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise HTTPError(f"Http request error: {response.status_code} {response.content}")
        return response.json()


def humio_query():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "queryString": orenctl.getArg("queryString"),
        "start": orenctl.getArg("start"),
        "end": orenctl.getArg("end"),
        "isLive": orenctl.getArg("isLive"),
        "timeZoneOffsetMinutes": orenctl.getArg("timeZoneOffsetMinutes"),
        "arguments": orenctl.getArg("arguments")
    }
    data = {"queryString": args.get("queryString")}
    try:
        data["start"] = int(args.get("start"))
    except ValueError:
        data["start"] = args.get("start")
    try:
        data["end"] = int(args.get("end"))
    except ValueError:
        data["end"] = args.get("end")
    data["isLive"] = args.get("isLive").lower() in ["true", "1", "t", "y", "yes"]
    data["timeZoneOffsetMinutes"] = int(args.get("timeZoneOffsetMinutes", 0))
    if args.get("arguments"):
        data["arguments"] = args.get("arguments")
    url = args_url + args.get("repository") + "/query"
    header = client.session.headers["Accept"] = app_json
    response = client.http_request("POST", url, data, header)
    if response.status_code == 200:
        result = response.json()
        outputs = {"Humio.Query": [result]}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_query_job():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "queryString": orenctl.getArg("queryString"),
        "start": orenctl.getArg("start"),
        "end": orenctl.getArg("end"),
        "isLive": orenctl.getArg("isLive"),
        "timeZoneOffsetMinutes": orenctl.getArg("timeZoneOffsetMinutes"),
        "arguments": orenctl.getArg("arguments")
    }
    data = {"queryString": args.get("queryString"),
            "start": args.get("start"), "end": args.get("end"),
            "isLive": args.get("isLive").lower() in ["true", "1", "t", "y", "yes"],
            "timeZoneOffsetMinutes": int(args.get("timeZoneOffsetMinutes"))}

    if args.get("arguments"):
        data["arguments"] = args.get("arguments")
    url = args_url + args.get("repository") + "/queryjobs"
    header = client.session.headers["Accept"] = app_json
    response = client.http_request("POST", url, data, header)
    if response.status_code == 200:
        result = response.json()
        outputs = {"Humio.Job": result}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_poll():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "id": orenctl.getArg("id")
    }
    data = {}
    url = (
            args_url
            + args.get("repository")
            + "/queryjobs/"
            + args.get("id")
    )
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        result["job_id"] = args.get("id")
        outputs = {"Humio.Result(val.job_id == obj.job_id)": result}
        return orenctl.results({"outputs": outputs})
    elif response.status_code == 404:
        return orenctl.results(orenctl.error(response.text))
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_delete_job():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "id": orenctl.getArg("id")
    }
    data = {}
    url = (
            args_url
            + args.get("repository")
            + "/queryjobs/"
            + args.get("id")
    )
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("DELETE", url, data, headers)
    if response.status_code == 204:
        results = "Command executed. Status code " + str(response), None, None
        return orenctl.results({"deleted": results})
    elif response.status_code == 404:
        return orenctl.results(orenctl.error(response.text))
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_list_alerts():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository")
    }
    data = {}
    url = args_url + args.get("repository") + "/alerts"
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        outputs = {output: result}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_get_alert_by_id():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "id": orenctl.getArg("id")
    }
    data = {}
    url = args_url + args.get("repository") + "/alerts/" + args.get("id")
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("GET", url, data, headers)
    if response.status_code == 200:
        if not response.text:
            raise ValueError("Alert with id " + str(args.get("id")) + " not found")
        result = response.json()
        outputs = {output: result}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_create_alert():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "name": orenctl.getArg("name"),
        "queryString": orenctl.getArg("queryString"),
        "start": orenctl.getArg("start"),
        "description": orenctl.getArg("description"),
        "throttleTimeMillis": orenctl.getArg("throttleTimeMillis"),
        "silenced": orenctl.getArg("silenced"),
        "notifiers": orenctl.getArg("notifiers"),
        "labels": orenctl.getArg("labels")
    }

    data = {
        "queryString": args.get("queryString"),
        "start": args.get("start"),
        "end": "now",
        "isLive": True
    }
    full_data = {
        "name": args.get("name"),
        "description": args.get("description", ""),
        "throttleTimeMillis": int(args.get("throttleTimeMillis")),
        "silenced": args.get("silenced", "false").lower() in [
            "true",
            "1",
            "t",
            "y",
            "yes",
        ],
        "notifiers": [notifier for notifier in args.get("notifiers").split(",") if notifier],
        "labels": [label for label in args.get("labels", "").split(",") if label],
        "query": data
    }
    url = args_url + args.get("repository") + "/alerts"
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("POST", url, full_data, headers)
    if response.status_code == 201:
        result = response.json()
        outputs = {output: result}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_list_notifiers():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository")
    }
    url = "/graphql"
    headers = client.session.headers["Accept"] = app_json

    graphql_query = """
        query{{searchDomain(name:"{repoName}"){{actions{{__typename, id , name
            ... on EmailAction{{id, name, recipients, subjectTemplate, emailBodyTemplate: bodyTemplate, useProxy, attachCsv}}
            ... on SlackAction{{url, fields{{fieldName, value}}, useProxy}}
            ... on SlackPostMessageAction{{apiToken, channels, fields{{fieldName, value}}, useProxy}}
            ... on WebhookAction{{method, url, webhookBodyTemplate: bodyTemplate, headers{{header,value}}, ignoreSSL, useProxy}}
            ... on OpsGenieAction{{apiUrl, genieKey, useProxy}}
            ... on VictorOpsAction{{messageType, notifyUrl, useProxy}}
            ... on PagerDutyAction{{severity, routingKey, useProxy}}
            ... on HumioRepoAction{{ingestToken}}
            ... on UploadFileAction{{fileName}}
            }}}}}}
        """.format(repoName=args.get("repository"))

    data = {"query": graphql_query}

    response = client.http_request("POST", url, data, headers)

    if response.status_code == 200:
        result = response.json()
        if not result.get("data"):
            raise ValueError(f"Failed to execute request: {response['errors'][0]['message']}")

        actions = result.get('data', {}).get('searchDomain', {}).get('actions', [])
        outputs = {"Humio.Notifier(val.id == obj.id)": actions}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error("Error:" + " response from server was: " + str(response.text)))


def humio_delete_alert():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "id": orenctl.getArg("id")
    }
    data = {}
    url = args_url + args.get("repository") + "/alerts/" + args.get("id")
    headers = client.session.headers["Accept"] = app_json
    response = client.http_request("DELETE", url, data, headers)
    if response.status_code == 204:
        results = "Command executed. Status code " + str(response), None, None
        return orenctl.results({"deleted": results})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


def humio_get_notifier_by_id():
    client = Humio()
    args = {
        "repository": orenctl.getArg("repository"),
        "id": orenctl.getArg("id")
    }
    url = "/graphql"
    graphql_query = """
        query{{searchDomain(name:"{repoName}"){{action(id:"{id}"){{__typename, id, name
            ... on EmailAction{{id, name, recipients, subjectTemplate, emailBodyTemplate: bodyTemplate, useProxy, attachCsv}}
            ... on SlackAction{{url, fields{{fieldName, value}}, useProxy}}
            ... on SlackPostMessageAction{{apiToken, channels, fields{{fieldName, value}}, useProxy}}
            ... on WebhookAction{{method, url, webhookBodyTemplate: bodyTemplate, headers{{header,value}}, ignoreSSL, useProxy}}
            ... on OpsGenieAction{{apiUrl, genieKey, useProxy}}
            ... on VictorOpsAction{{messageType, notifyUrl, useProxy}}
            ... on PagerDutyAction{{severity, routingKey, useProxy}}
            ... on HumioRepoAction{{ingestToken}}
            ... on UploadFileAction{{fileName}}}}}}}}
        """.format(repoName=args.get("repository"), id=args.get("id"))

    headers = client.session.headers["Accept"] = app_json

    data = {"query": graphql_query}

    response = client.http_request("POST", url, data, headers)
    if response.status_code == 200:
        result = response.json()
        if not result.get("data"):
            raise ValueError(f"Failed to execute request: {response['errors'][0]['message']}")
        actions = result.get('data', {}).get('searchDomain', {}).get('action')
        outputs = {"Humio.Notifier(val.id == obj.id)": actions}
        return orenctl.results({"outputs": outputs})
    else:
        return orenctl.results(orenctl.error(res_error + str(response.text)))


if orenctl.command() == "humio-query":
    humio_query()
elif orenctl.command() == "humio-query-job":
    humio_query_job()
elif orenctl.command() == "humio-poll":
    humio_poll()
elif orenctl.command() == "humio-delete-job":
    humio_delete_job()
elif orenctl.command() == "humio-list-alerts":
    humio_list_alerts()
elif orenctl.command() == "humio-get-alert-by-id":
    humio_get_alert_by_id()
elif orenctl.command() == "humio-create-alert":
    humio_create_alert()
elif orenctl.command() == "humio-list-notifiers":
    humio_list_notifiers()
elif orenctl.command() == "humio_delete_alert":
    humio_delete_alert()
elif orenctl.command() == "humio-get-notifier-by-id":
    humio_get_notifier_by_id()
