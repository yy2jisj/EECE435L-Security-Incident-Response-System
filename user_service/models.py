from werkzeug.security import generate_password_hash

from common import config
from common.validators import (
    choice, clean_text, validate_email, validate_password, validate_username,
)


class User:
    """A new user account. The constructor validates every field.

    :param full_name: the person's full name.
    :param username: unique login name, starts with a letter.
    :param email: email address.
    :param password: plain password (only used to create the hash).
    :param department: the person's department.
    :param role: one of the four roles, Regular User by default.
    :raises ValidationError: if any field is invalid.
    """

    def __init__(self, full_name, username, email, password, department,
                 role=config.ROLE_USER):
        self.full_name = clean_text(full_name, "full_name", max_length=100)
        self.username = validate_username(username)
        self.email = validate_email(email)
        self.password_hash = generate_password_hash(validate_password(password))
        self.department = clean_text(department, "department", max_length=100)
        self.role = choice(role, "role", config.ALL_ROLES)
