import requests

import orenctl


class TheHiveProject(object):
    def __init__(self):
        self.url = orenctl.getParam("url")
        self.domain = orenctl.getParam("domain")
        self.insecure = True if orenctl.getParam("insecure") else False
        self.api_key = orenctl.getParam("api_key")

        self.session = requests.session()
        self.session.headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        self.proxy = orenctl.getParam("proxy")
        proxies = {
            "http": self.proxy,
            "https": self.proxy
        }
        self.session.proxies.update(proxies)
        self.version = self.get_version()

    def http_request(self, method, url_suffix, *args, **kwargs):
        url = self.url + "/api" + url_suffix
        response = self.session.request(method=method, url=url, verify=False, *args, **kwargs)
        if response.status_code < 200 or response.status_code > 299:
            orenctl.results(orenctl.error(f"Http request error: {response.status_code} {response.content}"))
            raise Exception(f"Http request error: {response.status_code} {response.content}")
        return response.json()

    def get_version(self):
        res = self.http_request('GET', '/status')
        if "versions" in res:
            if "TheHive" in res['versions']:
                return res['versions']['TheHive']
            else:
                return "Unknown"
        return None

    def get_cases(self, limit: int = 50, start_time: int = 0):
        query = {
            "query": [
                {
                    "_name": "listCase",
                },
                {
                    "_name": "filter",
                    "_gte": {
                        "_field": "_createdAt",
                        "_value": start_time
                    },
                },
                {
                    "_name": "sort",
                    "_fields": [{"_createdAt": "asc"}]
                },
                {
                    "_name": "page",
                    "from": 0,
                    "to": limit
                },

            ]
        }
        return self.http_request("POST", "/v1/query",
                                 json=query, params={"name": "list-cases"})

    def get_case(self, case_id):
        return self.http_request("GET", f"/case/{case_id}")

    def update_case(self, case_id: str = None, updates: dict = None):
        return self.http_request("PATCH", f"/case/{case_id}", json=updates)

    def create_case(self, details: dict = None):
        return self.http_request("POST", "/case", json=details)

    def create_task(self, case_id: str = None, data: dict = None):
        return self.http_request(
            "POST",
            f"/case/{case_id}/task",
            data=data
        )

    def update_task(self, task_id: str = None, updates: dict = None):
        return self.http_request(
            "PATCH",
            f"/case/task/{task_id}",
            data=updates
        )

    def get_task(self, task_id: str = None):
        if self.version[0] == "4":
            query = {
                "query": [{
                    "_name": "getTask",
                    "idOrName": task_id
                }, {
                    "_name": "page",
                    "from": 0,
                    "to": 1
                }]
            }
            return self.http_request(
                'POST',
                '/v1/query',
                params={"name": f"get-task-{task_id}"},
                json=query
            )

        return self.http_request(
            'GET',
            f'/case/task/{task_id}',
        )


def list_cases_command():
    client = TheHiveProject()
    limit = orenctl.getArg("limit")
    res = client.get_cases(limit=limit)
    orenctl.results({
        "cases": res
    })
    return


def get_case_command():
    client = TheHiveProject()
    case_id = orenctl.getArg("case_id")
    res = client.get_case(case_id=case_id)
    orenctl.results({
        "case": res
    })
    return


def update_case_command():
    client = TheHiveProject()
    case_id = orenctl.getArg("case_id")
    arg_fields = [
        "title",
        "description",
        "severity",
        "startDate",
        "owner",
        "flag",
        "tlp",
        "tags",
        "resolutionStatus",
        "impactStatus",
        "summary",
        "endDate",
        "metrics",
        "status"]

    original_case = client.get_case(case_id)
    if not original_case:
        orenctl.results({
            "updated_case": f"Could not find case ID {case_id}.",
            "command_status": "Fail"
        })
        return
    for field in arg_fields:
        original_case[field] = orenctl.getArg(field)
    case = client.update_case(case_id, original_case)

    orenctl.results({
        "updated_case": case,
        "command_status": "Success"
    })
    return


def create_case_command():
    client = TheHiveProject()
    arg_fields = [
        "title",
        "description",
        "severity",
        "startDate",
        "owner",
        "flag",
        "tlp",
        "tags",
        "resolutionStatus",
        "impactStatus",
        "summary",
        "endDate",
        "metrics"]

    detail_case = {}
    for field in arg_fields:
        detail_case[field] = orenctl.getArg(field)
    case = client.create_case(detail_case)

    orenctl.results({
        "created_case": case,
        "command_status": "Success"
    })
    return


def create_task_command():
    client = TheHiveProject()
    case_id = orenctl.getArg("case_id")
    arg_fields = [
        "title",
        "description",
        "startDate",
    ]

    detail_task = {}
    for field in arg_fields:
        detail_task[field] = orenctl.getArg(field)
    task = client.create_task(case_id, detail_task)

    orenctl.results({
        "created_task": task,
        "command_status": "Success"
    })
    return


def update_task_command():
    client = TheHiveProject()
    task_id = orenctl.getArg("task_id")
    arg_fields = [
        "title",
        "startDate",
        "endDate",
        "flag",
        "status",
        "owner"
    ]

    task = client.get_task(task_id)
    if not task:
        orenctl.results({
            "updated_task": f"No task found with id: {task_id}.",
            "command_status": "Fail"
        })
        return
    for field in arg_fields:
        task[field] = orenctl.getArg(field)
    case = client.update_task(task_id, task)

    orenctl.results({
        "updated_task": case,
        "command_status": "Success"
    })
    return


if orenctl.command == "thehive_list_cases":
    list_cases_command()
if orenctl.command == "thehive_get_case":
    get_case_command()
if orenctl.command == "thehive_update_case":
    update_case_command()
if orenctl.command == "thehive_create_case":
    create_case_command()
if orenctl.command == "thehive_create_task":
    create_task_command()
if orenctl.command == "thehive_update_task":
    update_task_command()
