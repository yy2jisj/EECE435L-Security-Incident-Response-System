import logging
import re

from common.db import execute

SEVERITIES = ("Information", "Warning", "Error", "Critical")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
MAX_TEXT_LENGTH = 500

logger = logging.getLogger(__name__)


def _clean(text):
    text = CONTROL_CHARACTERS.sub(" ", str(text))
    return text[:MAX_TEXT_LENGTH]


def log_event(user_id, action, description, severity="Information", service="unknown"):
    """Record a security event in the audit log. Never raises an error.

    :param user_id: ID of the user who did it, or ``None`` if unknown.
    :param action: short name, for example ``"Failed login"``.
    :param description: what happened.
    :param severity: Information, Warning, Error or Critical.
    :param service: name of the service writing the log.
    """
    if severity not in SEVERITIES:
        severity = "Information"
    try:
        execute(
            "INSERT INTO logs (user_id, action, description, severity_level, "
            "related_service) VALUES (?, ?, ?, ?, ?)",
            (user_id, _clean(action), _clean(description), severity, _clean(service)),
        )
    except Exception:
        logger.exception("Could not write audit log entry")
