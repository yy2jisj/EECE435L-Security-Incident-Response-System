"""Notification input rules, using the project's stored spellings."""

from common.errors import ValidationError
from common.validators import choice, clean_text, parse_id

NOTIFICATION_TYPES = (
    "Incident Assignment", "Security Alert", "System Notification",
    "Threat Alert", "Vulnerability Alert",
)
SEVERITIES = ("Low", "Medium", "High", "Critical")
STATUSES = ("Unread", "Read")
MAX_ID = 9223372036854775807


def notification_id(value, field="notification id"):
    """Validate a URL/query ID before binding it to a SQLite integer."""
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = value.lstrip("0") or "0"
        if len(value) > 19:
            raise ValidationError(f"{field} is outside the supported integer range")
    number = parse_id(value, field)
    if number > MAX_ID:
        raise ValidationError(f"{field} is outside the supported integer range")
    return number


class Notification:
    """Validate a new notification; the database generates ID and dates.

    :param user_id: existing Service 1 recipient's integer ID.
    :param title: short notification title (at most 255 characters).
    :param message: notification text (at most 4000 characters).
    :param notification_type: one of NOTIFICATION_TYPES.
    :param severity_level: Low, Medium, High or Critical.
    """

    def __init__(self, user_id, title, message, notification_type, severity_level):
        if type(user_id) is not int or not 1 <= user_id <= MAX_ID:
            raise ValidationError("user_id must be a positive integer within SQLite's range")
        self.user_id = user_id
        self.title = clean_text(title, "title", max_length=255)
        self.message = clean_text(message, "message", max_length=4000)
        self.notification_type = choice(notification_type, "notification_type", NOTIFICATION_TYPES)
        self.severity_level = choice(severity_level, "severity_level", SEVERITIES)
