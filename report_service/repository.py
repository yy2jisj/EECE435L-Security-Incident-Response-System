"""Read-only queries used by the reports.

The report service never changes data. It reads the tables that the other
services write to (users, assets, incidents, ...) and turns them into counts.
"""
from asset_service.models import ASSET_TYPES, CRITICALITY_LEVELS
from common.db import fetch_all, fetch_one
from incident_service.models import SEVERITIES as INCIDENT_SEVERITIES
from incident_service.models import STATUSES as INCIDENT_STATUSES
from threat_service.models import SEVERITY_LEVELS as THREAT_SEVERITIES
from threat_service.models import THREAT_TYPES

# an incident counts as open until it is resolved or closed
CLOSED_INCIDENT_STATUSES = ("Resolved", "Closed")

# the vulnerability service is not built yet, so its allowed values (see the
# vulnerabilities table in schema.sql) are listed here
VULNERABILITY_SEVERITIES = ("Low", "Medium", "High", "Critical")
VULNERABILITY_STATUSES = ("Open", "Under Investigation", "In Progress", "Resolved", "Closed")

RECENT_THREAT_LIMIT = 5
CRITICAL_VULNERABILITY_LIMIT = 10


def count_by(table, column, categories, where="", params=()):
    """Count the rows of a table for each value of a column.

    Every known category is listed, with 0 when there are no rows, so the
    report always has the same shape. Values not in ``categories`` are added
    at the end so no row is ever left out of the totals.

    :param table: table name (from our own code, never from a request).
    :param column: the column to group by (from our own code).
    :param categories: the expected values, in the order to show them.
    :param where: optional SQL condition, for example ``"WHERE x = ?"``.
    :param params: values for the placeholders in ``where``.
    :return: dictionary of value -> number of rows.
    """
    rows = fetch_all(
        f"SELECT {column} AS name, COUNT(*) AS total FROM {table} {where} "
        f"GROUP BY {column}", params)
    found = {row["name"]: row["total"] for row in rows}
    counts = {category: found.pop(category, 0) for category in categories}
    counts.update(found)
    return counts


def _count(query, params=()):
    return fetch_one(query, params)["total"]


# ---- users ----
def count_users():
    return _count("SELECT COUNT(*) AS total FROM users")


# ---- assets ----
def count_assets():
    return _count("SELECT COUNT(*) AS total FROM assets")


def count_critical_assets():
    return _count("SELECT COUNT(*) AS total FROM assets WHERE criticality_level = 'Critical'")


def assets_by_type():
    return count_by("assets", "asset_type", ASSET_TYPES)


def assets_by_criticality():
    return count_by("assets", "criticality_level", CRITICALITY_LEVELS)


# ---- incidents ----
def count_incidents():
    return _count("SELECT COUNT(*) AS total FROM incidents")


def count_open_incidents():
    placeholders = ", ".join("?" for _ in CLOSED_INCIDENT_STATUSES)
    return _count(
        f"SELECT COUNT(*) AS total FROM incidents WHERE status NOT IN ({placeholders})",
        CLOSED_INCIDENT_STATUSES)


def incidents_by_severity():
    return count_by("incidents", "severity_level", INCIDENT_SEVERITIES)


def incidents_by_status():
    return count_by("incidents", "status", INCIDENT_STATUSES)


# ---- threats ----
def count_threats():
    return _count("SELECT COUNT(*) AS total FROM threats")


def count_critical_threats():
    return _count("SELECT COUNT(*) AS total FROM threats WHERE severity_level = 'Critical'")


def threats_by_severity():
    return count_by("threats", "severity_level", THREAT_SEVERITIES)


def threats_by_type():
    return count_by("threats", "threat_type", THREAT_TYPES)


def recent_threats(limit=RECENT_THREAT_LIMIT):
    """Return the most recently added threats, newest first."""
    return fetch_all(
        "SELECT threat_id, threat_type, threat_value, severity_level, source, date_added "
        "FROM threats ORDER BY date_added DESC, threat_id DESC LIMIT ?", (limit,))


# ---- vulnerabilities ----
def count_vulnerabilities():
    return _count("SELECT COUNT(*) AS total FROM vulnerabilities")


def count_critical_vulnerabilities():
    return _count(
        "SELECT COUNT(*) AS total FROM vulnerabilities WHERE severity_level = 'Critical'")


def vulnerabilities_by_severity():
    return count_by("vulnerabilities", "severity_level", VULNERABILITY_SEVERITIES)


def vulnerabilities_by_status():
    return count_by("vulnerabilities", "status", VULNERABILITY_STATUSES)


def critical_vulnerabilities(limit=CRITICAL_VULNERABILITY_LIMIT):
    """Return the critical vulnerabilities with the highest CVSS score first."""
    return fetch_all(
        "SELECT vulnerability_id, title, cve_id, cvss_score, status, asset_id "
        "FROM vulnerabilities WHERE severity_level = 'Critical' "
        "ORDER BY cvss_score DESC, vulnerability_id LIMIT ?", (limit,))
