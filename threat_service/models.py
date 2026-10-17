import re

from common.errors import ValidationError
from common.validators import choice, clean_text, validate_ip

THREAT_TYPES = ("IP Address", "Domain", "File Hash", "Malware Signature", "Other")
SEVERITY_LEVELS = ("Low", "Medium", "High", "Critical")

# one label: letters, digits and hyphens, not starting or ending with a hyphen
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
# MD5 (32), SHA-1 (40) and SHA-256 (64) written in hexadecimal
HASH_PATTERN = re.compile(r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})$")


def validate_domain(value):
    """Validate a domain name such as ``evil.example.com`` and return it in lower case."""
    value = clean_text(value, "threat_value", max_length=253).lower()
    if not DOMAIN_PATTERN.match(value):
        raise ValidationError("threat_value is not a valid domain name")
    return value


def validate_hash(value):
    """Validate an MD5, SHA-1 or SHA-256 hex hash and return it in lower case."""
    value = clean_text(value, "threat_value", max_length=64).lower()
    if not HASH_PATTERN.match(value):
        raise ValidationError(
            "threat_value is not a valid file hash "
            "(expected 32, 40 or 64 hexadecimal characters)"
        )
    return value


def validate_threat_value(threat_type, value):
    """Check the value against the format that matches the threat type.

    IP, domain and hash threats have a strict format. Malware signatures and
    other indicators are free text.

    :param threat_type: one of THREAT_TYPES (already validated).
    :param value: the raw value from the request.
    :return: the value in its standard form.
    :raises ValidationError: if the format does not match the type.
    """
    if threat_type == "IP Address":
        if not isinstance(value, str):
            raise ValidationError("threat_value must be text")
        try:
            return validate_ip(value)
        except ValidationError:
            raise ValidationError("threat_value is not a valid IP address")
    if threat_type == "Domain":
        return validate_domain(value)
    if threat_type == "File Hash":
        return validate_hash(value)
    return clean_text(value, "threat_value", max_length=255)


class Threat:
    """A new threat indicator. The constructor validates every field.

    :param threat_type: one of THREAT_TYPES.
    :param threat_value: the indicator, checked against the threat type.
    :param description: what the threat is.
    :param severity_level: Low, Medium, High or Critical.
    :param source: where the intelligence came from.
    :raises ValidationError: if any field is invalid.
    """

    def __init__(self, threat_type, threat_value, description, severity_level, source):
        self.threat_type = choice(threat_type, "threat_type", THREAT_TYPES)
        self.threat_value = validate_threat_value(self.threat_type, threat_value)
        self.description = clean_text(description, "description", max_length=500)
        self.severity_level = choice(severity_level, "severity_level", SEVERITY_LEVELS)
        self.source = clean_text(source, "source", max_length=100)
