"""Where the reports get their data from.

Users, assets, incidents and threats belong to other services, so the report
service asks those services for their records through their REST APIs. The
caller's own token is forwarded, which means a report can only show what the
caller is allowed to see in each service.
"""
from common.errors import ApiError
from common.service_client import fetch_resource

# the list endpoint of each service (see the BASE_ROUTE of that service)
USERS_PATH = "/users/AdamYahya"
ASSETS_PATH = "/assets/AdamYahya"
INCIDENTS_PATH = "/Youssef-Al-Hajj-Youness/incidents"
THREATS_PATH = "/leen-abdallah/threats"


def _fetch_list(service, path):
    """Return the list of records a service sends back for ``path``.

    :raises ApiError: 503 if the service is down, refuses the request or does
        not answer with a list.
    """
    records = fetch_resource(service, path)
    if not isinstance(records, list):
        raise ApiError(f"The {service} service did not return a list of records", 503)
    return records


def get_users():
    return _fetch_list("users", USERS_PATH)


def get_assets():
    return _fetch_list("assets", ASSETS_PATH)


def get_incidents():
    return _fetch_list("incidents", INCIDENTS_PATH)


def get_threats():
    return _fetch_list("threats", THREATS_PATH)
