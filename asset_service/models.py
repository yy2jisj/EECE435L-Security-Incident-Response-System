from common.errors import ValidationError
from common.validators import choice, clean_text, parse_id, validate_ip

ASSET_TYPES = ("Server", "Workstation", "Database", "Application",
               "Network Device", "Cloud Resource")
CRITICALITY_LEVELS = ("Low", "Medium", "High", "Critical")
ASSET_STATUSES = ("Active", "Inactive", "Under Maintenance")


def check_owner_id(value):
    """Make sure the owner id is a positive whole number and return it."""
    # bool is a kind of int in Python, so True would slip through without this
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValidationError("owner_id must be a positive whole number")
    return parse_id(str(value), "owner_id")


class Asset:
    """A new asset. The constructor validates every field.

    :param asset_name: name of the asset.
    :param asset_type: one of ASSET_TYPES.
    :param ip_address: IPv4 or IPv6 address.
    :param department: department that uses the asset.
    :param owner_id: user_id of the owner.
    :param criticality_level: Low, Medium, High or Critical.
    :param operating_system: optional.
    :param location: optional.
    :param status: Active by default.
    :raises ValidationError: if any field is invalid.
    """

    def __init__(self, asset_name, asset_type, ip_address, department, owner_id,
                 criticality_level, operating_system=None, location=None,
                 status="Active"):
        self.asset_name = clean_text(asset_name, "asset_name", max_length=100)
        self.asset_type = choice(asset_type, "asset_type", ASSET_TYPES)
        self.ip_address = validate_ip(ip_address)
        self.operating_system = clean_text(operating_system, "operating_system",
                                           max_length=100, required=False)
        self.department = clean_text(department, "department", max_length=100)
        self.owner_id = check_owner_id(owner_id)
        self.location = clean_text(location, "location", max_length=100,
                                   required=False)
        self.criticality_level = choice(criticality_level, "criticality_level",
                                        CRITICALITY_LEVELS)
        self.status = choice(status, "status", ASSET_STATUSES)
