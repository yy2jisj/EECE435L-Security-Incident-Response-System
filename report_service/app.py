from datetime import datetime, timezone

from flask import Flask

from common import config
from common.auth import roles_required
from common.errors import register_error_handlers, success_response
from report_service import sources, statistics

SERVICE = "reports"
BASE_ROUTE = "/leen-abdallah/reports"

app = Flask(__name__)
register_error_handlers(app)


def report_access(view):
    """Only a Security Administrator or an Auditor may generate reports."""
    return roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)(view)


def generated_at():
    """The moment a report was generated, in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@app.get(BASE_ROUTE + "/summary")
@report_access
def summary_report():
    """Overview of the current security status.

    Implemented by: Leen Abdallah
    """
    incidents = sources.get_incidents()
    threats = sources.get_threats()
    data = {
        "generated_at": generated_at(),
        "users": len(sources.get_users()),
        "assets": len(sources.get_assets()),
        "total_incidents": len(incidents),
        "open_incidents": statistics.count_open_incidents(incidents),
        "total_threats": len(threats),
        "critical_threats": statistics.count_critical_threats(threats),
    }
    return success_response("Security summary report generated successfully", data)


@app.get(BASE_ROUTE + "/incidents")
@report_access
def incident_report():
    """Incident statistics: total, by severity and by status.

    Implemented by: Leen Abdallah
    """
    incidents = sources.get_incidents()
    data = {
        "generated_at": generated_at(),
        "total_incidents": len(incidents),
        "open_incidents": statistics.count_open_incidents(incidents),
        "incidents_by_severity": statistics.incidents_by_severity(incidents),
        "incidents_by_status": statistics.incidents_by_status(incidents),
    }
    return success_response("Incident report generated successfully", data)


@app.get(BASE_ROUTE + "/assets")
@report_access
def asset_report():
    """Asset statistics: total, critical assets and assets by type.

    Implemented by: Leen Abdallah
    """
    assets = sources.get_assets()
    data = {
        "generated_at": generated_at(),
        "total_assets": len(assets),
        "critical_assets": statistics.count_critical_assets(assets),
        "assets_by_type": statistics.assets_by_type(assets),
        "assets_by_criticality": statistics.assets_by_criticality(assets),
    }
    return success_response("Asset report generated successfully", data)


@app.get(BASE_ROUTE + "/threats")
@report_access
def threat_report():
    """Threat intelligence statistics: total, by severity, by type and recent threats.

    Implemented by: Leen Abdallah
    """
    threats = sources.get_threats()
    data = {
        "generated_at": generated_at(),
        "total_threats": len(threats),
        "critical_threats": statistics.count_critical_threats(threats),
        "threats_by_severity": statistics.threats_by_severity(threats),
        "threats_by_type": statistics.threats_by_type(threats),
        "recent_threats": statistics.recent_threats(threats),
    }
    return success_response("Threat report generated successfully", data)


@app.get(BASE_ROUTE + "/vulnerabilities")
@report_access
def vulnerability_report():
    """Vulnerability statistics: total, by severity, by status and critical ones.

    Implemented by: Leen Abdallah
    """
    vulnerabilities = sources.get_vulnerabilities()
    data = {
        "generated_at": generated_at(),
        "total_vulnerabilities": len(vulnerabilities),
        "critical_vulnerabilities": statistics.count_critical_vulnerabilities(vulnerabilities),
        "vulnerabilities_by_severity": statistics.vulnerabilities_by_severity(vulnerabilities),
        "vulnerabilities_by_status": statistics.vulnerabilities_by_status(vulnerabilities),
        "top_critical_vulnerabilities": statistics.top_critical_vulnerabilities(vulnerabilities),
    }
    return success_response("Vulnerability report generated successfully", data)


@app.get(BASE_ROUTE + "/activity")
@report_access
def activity_report():
    """Security activity statistics taken from the audit logs.

    Implemented by: Leen Abdallah
    """
    logs = sources.get_logs()
    data = {
        "generated_at": generated_at(),
        "total_activities": len(logs),
        "login_attempts": statistics.count_login_attempts(logs),
        "successful_logins": statistics.count_successful_logins(logs),
        "failed_logins": statistics.count_failed_logins(logs),
        "most_performed_actions": statistics.most_performed_actions(logs),
        "recent_activities": statistics.recent_activities(logs),
    }
    return success_response("Activity report generated successfully", data)


if __name__ == "__main__":
    app.run(port=config.PORTS["reports"])
