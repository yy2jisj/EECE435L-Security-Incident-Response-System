import requests
from flask import request

from common import config
from common.errors import ApiError

TIMEOUT_SECONDS = 5


def fetch_resource(service, path):
    """GET a resource from another service.

    :param service: key of ``config.PORTS``, for example ``"users"``.
    :param path: URL path, for example ``"/users"``.
    :return: the ``data`` part of the response, or ``None`` if it answered 404.
    :raises ApiError: 503 if the service cannot be reached or answers with an
        unexpected error.
    """
    url = config.service_url(service) + path
    headers = {}
    if "Authorization" in request.headers:
        headers["Authorization"] = request.headers["Authorization"]
    try:
        response = requests.get(url, headers=headers, timeout=TIMEOUT_SECONDS)
    except requests.RequestException:
        raise ApiError(f"The {service} service is unavailable", 503)

    if response.status_code == 404:
        return None
    if response.status_code != 200:
        raise ApiError(
            f"The {service} service answered with status {response.status_code}", 503
        )
    try:
        payload = response.json()
    except ValueError:
        raise ApiError(f"The {service} service sent an invalid response", 503)
    if not isinstance(payload, dict) or payload.get("status") != "success" or "data" not in payload:
        raise ApiError(f"The {service} service sent an invalid response", 503)
    return payload["data"]
