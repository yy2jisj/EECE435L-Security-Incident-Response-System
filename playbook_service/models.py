"""Service 9 inputs; identity, creator and creation time belong to the server."""

from common.errors import ValidationError
from common.validators import choice, clean_text, parse_id

SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Pending", "In Progress", "Completed")
MAX_ID = 9223372036854775807


def playbook_id(value, field="playbook id"):
    """Validate URL IDs without allowing oversized integers into SQLite."""
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = value.lstrip("0") or "0"
        if len(value) > 19:
            raise ValidationError(f"{field} is outside the supported integer range")
    number = parse_id(value, field)
    if number > MAX_ID:
        raise ValidationError(f"{field} is outside the supported integer range")
    return number


def positive_integer(value, field):
    if type(value) is not int or not 1 <= value <= MAX_ID:
        raise ValidationError(f"{field} must be a positive integer within SQLite's range")
    return value


class Playbook:
    def __init__(self, playbook_name, description, incident_category, severity_level):
        self.playbook_name = clean_text(playbook_name, "playbook_name", max_length=255)
        self.description = clean_text(description, "description", max_length=4000)
        self.incident_category = clean_text(incident_category, "incident_category", max_length=100)
        self.severity_level = choice(severity_level, "severity_level", SEVERITIES)


class ResponseAction:
    def __init__(self, action_description, step_number):
        self.action_description = clean_text(action_description, "action_description", max_length=4000)
        self.step_number = positive_integer(step_number, "step_number")
