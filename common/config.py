#Shared configuration for every service.
import os

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

DB_PATH = os.environ.get(
    "DB_PATH", os.path.join(BASE_DIR, "database", "security_incident.db")
)
SCHEMA_PATH = os.path.join(BASE_DIR, "database", "schema.sql")

SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")
TOKEN_LIFETIME_MINUTES = 60

ROLE_ADMIN = "Security Administrator"
ROLE_ANALYST = "Security Analyst"
ROLE_USER = "Regular User"
ROLE_AUDITOR = "Auditor"
ALL_ROLES = (ROLE_ADMIN, ROLE_ANALYST, ROLE_USER, ROLE_AUDITOR)

PORTS = {
    "users": 5001,
    "assets": 5002,
    "incidents": 5003,
    "threats": 5004,
    "logs": 5005,
    "reports": 5006,
    "vulnerabilities": 5007,
    "notifications": 5008,
    "playbooks": 5009,
}


def service_url(name):
    """Return the base URL of another service.

    :param name: key of :data:`PORTS`, for example ``"users"``.
    :return: URL such as ``http://127.0.0.1:5001`` (override with the
        ``<NAME>_SERVICE_URL`` environment variable).
    """
    default = f"http://127.0.0.1:{PORTS[name]}"
    return os.environ.get(f"{name.upper()}_SERVICE_URL", default)
