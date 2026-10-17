"""Turn the records sent by the other services into report numbers.

Every function here is pure: it only reads the list it is given.
"""
from asset_service.models import ASSET_TYPES, CRITICALITY_LEVELS
from incident_service.models import SEVERITIES as INCIDENT_SEVERITIES
from incident_service.models import STATUSES as INCIDENT_STATUSES
from threat_service.models import SEVERITY_LEVELS as THREAT_SEVERITIES
from threat_service.models import THREAT_TYPES

# an incident counts as open until it is resolved or closed
CLOSED_INCIDENT_STATUSES = ("Resolved", "Closed")
RECENT_THREAT_LIMIT = 5


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
