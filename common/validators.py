import ipaddress
import re
from datetime import date

from flask import request

from common.errors import ValidationError

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+\-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
)
USERNAME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9_.\-]{2,29}$")
CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


def get_json_body():
    """Return the JSON object sent with the request.

    :raises ValidationError: if the body is missing, not JSON, not an object,
        or empty.
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ValidationError("Request body must be a JSON object")
    if len(data) == 0:
        raise ValidationError("Request body cannot be empty")
    return data


def check_fields(data, required=(), allowed=()):
    """Check that required fields are present and no unknown field is sent.

    :param data: the JSON body as a dictionary.
    :param required: field names that must be present.
    :param allowed: optional field names that may also be present.
    :raises ValidationError: listing the missing or unknown fields.
    """
    missing = []
    for name in required:
        if name not in data or data[name] is None or data[name] == "":
            missing.append(name)
    if missing:
        raise ValidationError("Missing required fields: " + ", ".join(missing))

    known_fields = list(required) + list(allowed)
    unknown = []
    for name in data:
        if name not in known_fields:
            unknown.append(name)
    if unknown:
        raise ValidationError("Unknown fields: " + ", ".join(unknown))


def clean_text(value, field, max_length=255, required=True):
    """Validate a text field and return it trimmed.

    :param value: the raw value from the request.
    :param field: field name, used in error messages.
    :param max_length: longest accepted length after trimming.
    :param required: if False, an empty value returns ``None``.
    :raises ValidationError: if it is not text, is empty, too long, or
        contains control characters.
    """
    if value is not None and not isinstance(value, str):
        raise ValidationError(f"{field} must be text")

    if value is None or value.strip() == "":
        if required:
            raise ValidationError(f"{field} is required")
        return None

    value = value.strip()
    if len(value) > max_length:
        raise ValidationError(f"{field} must be at most {max_length} characters")
    if CONTROL_CHARACTERS.search(value):
        raise ValidationError(f"{field} contains invalid characters")
    return value


def choice(value, field, options):
    """Match a value against a list of allowed values, ignoring case.

    :param value: the raw value from the request.
    :param field: field name, used in error messages.
    :param options: the allowed values, written exactly as stored.
    :return: the stored spelling, for example "high" becomes "High".
    :raises ValidationError: if the value is not in the list.
    """
    if isinstance(value, str):
        for option in options:
            if value.strip().lower() == option.lower():
                return option
    raise ValidationError(f"{field} must be one of: " + ", ".join(options))


def validate_email(value):
    """Validate an email address and return it in lower case.

    :param value: the raw value from the request.
    """
    value = clean_text(value, "email", max_length=254)
    if not EMAIL_PATTERN.match(value):
        raise ValidationError("email format is invalid")
    return value.lower()


def validate_username(value):
    """Validate a username (3 to 30 characters, starts with a letter).

    :param value: the raw value from the request.
    """
    value = clean_text(value, "username", max_length=30)
    if not USERNAME_PATTERN.match(value):
        raise ValidationError(
            "username must be 3 to 30 characters, start with a letter and use "
            "only letters, digits, dot, underscore or hyphen"
        )
    return value


def validate_password(value):
    """Check the password rules: 8+ characters, upper, lower and a digit.

    :param value: the raw value from the request.
    """
    if not isinstance(value, str):
        raise ValidationError("password must be text")
    if len(value) < 8:
        raise ValidationError("password must be at least 8 characters")
    if len(value) > 128:
        raise ValidationError("password must be at most 128 characters")
    if not re.search(r"[A-Z]", value):
        raise ValidationError("password must contain an uppercase letter")
    if not re.search(r"[a-z]", value):
        raise ValidationError("password must contain a lowercase letter")
    if not re.search(r"[0-9]", value):
        raise ValidationError("password must contain a digit")
    return value


def validate_ip(value):
    """Validate an IPv4 or IPv6 address and return it in standard form.

    :param value: the raw value from the request.
    """
    value = clean_text(value, "ip_address", max_length=45)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise ValidationError("ip_address is not a valid IP address")
    return str(ip)


def validate_iso_date(value, field):
    """Validate a date written as YYYY-MM-DD.

    :param value: the raw value from the request.
    :param field: field name, used in error messages.
    """
    value = clean_text(value, field, max_length=10)
    try:
        parsed_date = date.fromisoformat(value)
    except ValueError:
        raise ValidationError(f"{field} must be a valid date in YYYY-MM-DD format")
    return parsed_date.isoformat()


def parse_id(value, name="id"):
    """Turn an ID taken from the URL into a positive integer.

    :param value: the text from the URL.
    :param name: name used in the error message.
    :raises ValidationError: if it is not a positive whole number.
    """
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValidationError(f"{name} must be a positive whole number")
    number = int(value)
    if number < 1:
        raise ValidationError(f"{name} must be a positive whole number")
    return number


def read_filters(allowed, require_one=True):
    """Read search filters from the URL query string.

    :param allowed: the query parameter names this search accepts.
    :param require_one: if True, at least one filter must be given.
    :return: dictionary of the filters that were given (empty ones dropped).
    :raises ValidationError: on an unknown parameter, or no filter at all.
    """
    unknown = []
    for name in request.args:
        if name not in allowed:
            unknown.append(name)
    if unknown:
        raise ValidationError(
            "Unknown search parameters: " + ", ".join(unknown)
            + ". Allowed: " + ", ".join(allowed)
        )

    filters = {}
    for name, value in request.args.items():
        value = value.strip()
        if value != "":
            filters[name] = value

    if require_one and len(filters) == 0:
        raise ValidationError("Provide at least one search parameter: " + ", ".join(allowed))
    return filters
