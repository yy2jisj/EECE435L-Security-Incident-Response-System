from datetime import datetime, timezone

from flask import Flask

from common import config
from common.auth import roles_required
from common.errors import register_error_handlers, success_response
from report_service import repository

SERVICE = "reports"

app = Flask(__name__)
register_error_handlers(app)


def report_access(view):
    """Only a Security Administrator or an Auditor may generate reports."""
    return roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)(view)


def generated_at():
    """The moment a report was generated, in UTC."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@app.get("/reports/summary")
@report_access
def summary_report():
    """Overview of the current security status.

    Implemented by: Leen Abdallah
    """
    data = {
        "generated_at": generated_at(),
        "users": repository.count_users(),
        "assets": repository.count_assets(),
        "total_incidents": repository.count_incidents(),
        "open_incidents": repository.count_open_incidents(),
        "total_threats": repository.count_threats(),
        "critical_threats": repository.count_critical_threats(),
    }
    return success_response("Security summary report generated successfully", data)


@app.get("/reports/incidents")
@report_access
def incident_report():
    """Incident statistics: total, by severity and by status.

    Implemented by: Leen Abdallah
    """
    data = {
        "generated_at": generated_at(),
        "total_incidents": repository.count_incidents(),
        "open_incidents": repository.count_open_incidents(),
        "incidents_by_severity": repository.incidents_by_severity(),
        "incidents_by_status": repository.incidents_by_status(),
    }
    return success_response("Incident report generated successfully", data)


@app.get("/reports/assets")
@report_access
def asset_report():
    """Asset statistics: total, critical assets and assets by type.

    Implemented by: Leen Abdallah
    """
    data = {
        "generated_at": generated_at(),
        "total_assets": repository.count_assets(),
        "critical_assets": repository.count_critical_assets(),
        "assets_by_type": repository.assets_by_type(),
        "assets_by_criticality": repository.assets_by_criticality(),
    }
    return success_response("Asset report generated successfully", data)


if __name__ == "__main__":
    app.run(port=config.PORTS["reports"])
