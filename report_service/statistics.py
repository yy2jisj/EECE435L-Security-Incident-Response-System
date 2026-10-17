"""Turn the records sent by the other services into report numbers.

Every function here is pure: it only reads the list it is given.
"""
from asset_service.models import ASSET_TYPES, CRITICALITY_LEVELS
from incident_service.models import SEVERITIES as INCIDENT_SEVERITIES
from incident_service.models import STATUSES as INCIDENT_STATUSES
from threat_service.models import SEVERITY_LEVELS as THREAT_SEVERITIES
from threat_service.models import THREAT_TYPES
from vulnerability_service.models import SEVERITY_LEVELS as VULNERABILITY_SEVERITIES
from vulnerability_service.models import STATUSES as VULNERABILITY_STATUSES

# an incident counts as open until it is resolved or closed
CLOSED_INCIDENT_STATUSES = ("Resolved", "Closed")
RECENT_THREAT_LIMIT = 5
TOP_VULNERABILITY_LIMIT = 10
TOP_ACTION_LIMIT = 5
RECENT_ACTIVITY_LIMIT = 5

# the actions the user service writes to the audit log for logins
LOGIN_SUCCESS_ACTION = "Successful login"
LOGIN_FAILURE_ACTION = "Failed login"


def tally(records, field, categories):
    """Count the records for each value of a field.

    Every known category is listed, with 0 when there are none, so the report
    always has the same shape. Values not in ``categories`` are added at the
    end so no record is ever left out of the totals.

    :param records: list of dictionaries.
    :param field: the key to group by.
    :param categories: the expected values, in the order to show them.
    :return: dictionary of value -> number of records.
    """
    counts = {category: 0 for category in categories}
    for record in records:
        value = record.get(field)
        counts[value] = counts.get(value, 0) + 1
    return counts


def count_where(records, field, value):
    return sum(1 for record in records if record.get(field) == value)


# ---- assets ----
def assets_by_type(assets):
    return tally(assets, "asset_type", ASSET_TYPES)


def assets_by_criticality(assets):
    return tally(assets, "criticality_level", CRITICALITY_LEVELS)


def count_critical_assets(assets):
    return count_where(assets, "criticality_level", "Critical")


# ---- incidents ----
def incidents_by_severity(incidents):
    return tally(incidents, "severity_level", INCIDENT_SEVERITIES)


def incidents_by_status(incidents):
    return tally(incidents, "status", INCIDENT_STATUSES)


def count_open_incidents(incidents):
    return sum(1 for incident in incidents
               if incident.get("status") not in CLOSED_INCIDENT_STATUSES)


# ---- threats ----
def threats_by_severity(threats):
    return tally(threats, "severity_level", THREAT_SEVERITIES)


def threats_by_type(threats):
    return tally(threats, "threat_type", THREAT_TYPES)


def count_critical_threats(threats):
    return count_where(threats, "severity_level", "Critical")


def recent_threats(threats, limit=RECENT_THREAT_LIMIT):
    """Return the most recently added threats, newest first (ties: higher id first)."""
    newest = sorted(threats, key=lambda t: (t["date_added"], t["threat_id"]), reverse=True)
    return [
        {key: threat[key] for key in ("threat_id", "threat_type", "threat_value",
                                      "severity_level", "source", "date_added")}
        for threat in newest[:limit]
    ]


# ---- vulnerabilities ----
def vulnerabilities_by_severity(vulnerabilities):
    return tally(vulnerabilities, "severity_level", VULNERABILITY_SEVERITIES)


def vulnerabilities_by_status(vulnerabilities):
    return tally(vulnerabilities, "status", VULNERABILITY_STATUSES)


def count_critical_vulnerabilities(vulnerabilities):
    return count_where(vulnerabilities, "severity_level", "Critical")


def top_critical_vulnerabilities(vulnerabilities, limit=TOP_VULNERABILITY_LIMIT):
    """Return the critical vulnerabilities with the highest CVSS score first."""
    critical = [v for v in vulnerabilities if v.get("severity_level") == "Critical"]
    critical.sort(key=lambda v: (-v["cvss_score"], v["vulnerability_id"]))
    return [
        {key: vulnerability[key] for key in ("vulnerability_id", "title", "cve_id",
                                             "cvss_score", "status", "asset_id")}
        for vulnerability in critical[:limit]
    ]


# ---- activity (audit logs) ----
def count_login_attempts(logs):
    """Count successful and failed login attempts together."""
    return (count_where(logs, "action", LOGIN_SUCCESS_ACTION)
            + count_where(logs, "action", LOGIN_FAILURE_ACTION))


def count_successful_logins(logs):
    return count_where(logs, "action", LOGIN_SUCCESS_ACTION)


def count_failed_logins(logs):
    return count_where(logs, "action", LOGIN_FAILURE_ACTION)


def most_performed_actions(logs, limit=TOP_ACTION_LIMIT):
    """Return the most frequent actions, most frequent first (ties by name)."""
    counts = tally(logs, "action", ())
    ranked = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    return [{"action": action, "total": total} for action, total in ranked[:limit]]


def recent_activities(logs, limit=RECENT_ACTIVITY_LIMIT):
    """Return the latest audit log records, newest first."""
    newest = sorted(logs, key=lambda log: log["log_id"], reverse=True)
    return [
        {key: log[key] for key in ("log_id", "user_id", "action", "severity_level",
                                   "related_service", "timestamp")}
        for log in newest[:limit]
    ]
