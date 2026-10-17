from common.audit import SEVERITIES
from common.errors import ValidationError
from common.validators import choice, clean_text, parse_id

# the largest number SQLite can store in an INTEGER column
MAX_ID = 9223372036854775807
SEVERITY_LEVELS = SEVERITIES


def log_id(value):
    """Turn a log ID taken from the URL into a positive integer the database can hold.

    :raises ValidationError: if it is not a positive whole number or is too large.
    """
    number = parse_id(value, "log id")
    if number > MAX_ID:
        raise ValidationError("log id is too large")
    return number


def validate_user_id(value):
    """Check that a user id sent in a request body is a positive whole number."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError("user_id must be a positive whole number")
    if value < 1 or value > MAX_ID:
        raise ValidationError("user_id must be a positive whole number")
    return value


class AuditLog:
    """A validated audit log record, ready to be saved.

    Every field is checked here, so a bad value is rejected before the database
    is touched. The log id and timestamp are created by the database.
    """

    def __init__(self, user_id, action, description, severity_level, related_service):
        self.user_id = validate_user_id(user_id)
        self.action = clean_text(action, "action", 100)
        self.description = clean_text(description, "description", 500)
        self.severity_level = choice(severity_level, "severity_level", SEVERITY_LEVELS)
        self.related_service = clean_text(related_service, "related_service", 50)
