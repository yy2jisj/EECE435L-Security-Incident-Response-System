import sqlite3

from flask import Flask, g
from werkzeug.security import check_password_hash

from common import config
from common.audit import log_event
from common.auth import authenticate, create_token, deny, roles_required
from common.errors import ApiError, ValidationError, register_error_handlers, success_response
from common.validators import (
    check_fields, clean_text, get_json_body, parse_id, validate_email,
)
from user_service import repository
from user_service.models import User

SERVICE = "users"

app = Flask(__name__)
register_error_handlers(app)


def check_can_assign_role(role):
    """Decide who may create an account with this role.

    Regular User accounts are open to everyone. Every other role needs a
    Security Administrator token.

    :param role: the role of the account being created.
    :return: the id of the administrator who is creating it, or None.
    """
    if role == config.ROLE_USER:
        return None

    caller = authenticate(SERVICE)
    if caller["role"] != config.ROLE_ADMIN:
        deny(caller, "Only a Security Administrator can create this role", SERVICE)
    return caller["user_id"]


@app.post("/users/register")
def register():
    """Create a new user account

    Implemented by: Adam Yahya
    """
    data = get_json_body()
    check_fields(
        data,
        required=["full_name", "username", "email", "password", "department"],
        allowed=["role"],
    )
    user = User(
        data["full_name"], data["username"], data["email"],
        data["password"], data["department"], data.get("role", config.ROLE_USER),
    )

    if repository.username_exists(user.username):
        raise ApiError("Username already exists", 409)
    if repository.email_exists(user.email):
        raise ApiError("Email is already registered", 409)

    admin_id = check_can_assign_role(user.role)

    try:
        new_id = repository.insert_user(user)
    except sqlite3.IntegrityError:
        raise ApiError("Username or email already exists", 409)

    log_event(admin_id or new_id, "User created",
              f"Account '{user.username}' created with role {user.role}",
              "Information", SERVICE)
    return success_response("User registered successfully",
                            repository.get_by_id(new_id), 201)


@app.post("/users/login")
def login():
    """Log in with a username or email and a password, and return a token.

    Implemented by: Adam Yahya
    """
    data = get_json_body()
    check_fields(data, required=["password"], allowed=["username", "email"])

    identifier = data.get("username") or data.get("email")
    if identifier is None:
        raise ValidationError("Provide a username or an email")
    identifier = clean_text(identifier, "username or email", max_length=254)

    password = data["password"]
    if not isinstance(password, str):
        raise ValidationError("password must be text")

    user = repository.find_for_login(identifier)

    if user is None or not check_password_hash(user["password_hash"], password):
        user_id = user["user_id"] if user else None
        log_event(user_id, "Failed login", f"Failed login attempt for '{identifier}'",
                  "Warning", SERVICE)
        raise ApiError("Invalid username or password", 401)

    if user["account_status"] != "Active":
        log_event(user["user_id"], "Failed login",
                  f"Login refused, account is {user['account_status']}",
                  "Warning", SERVICE)
        raise ApiError(f"Account is {user['account_status'].lower()}", 403)

    repository.update_last_login(user["user_id"])
    log_event(user["user_id"], "Successful login", f"'{user['username']}' logged in",
              "Information", SERVICE)
    return success_response("Login successful", {
        "token": create_token(user),
        "token_type": "Bearer",
        "user": repository.get_by_id(user["user_id"]),
    })


@app.get("/users")
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)
def get_all_users():
    """Return every registered user (Security Administrator and Auditor only).

    Implemented by: Adam Yahya
    """
    return success_response("Users retrieved successfully", repository.get_all())


@app.get("/users/<username>")
def get_user(username):
    """Return one user by username.

    Administrators and auditors may view anyone. A Regular User may only view
    their own record. Analysts have no user management access.

    Implemented by: Adam Yahya
    """
    caller = authenticate(SERVICE)
    if caller["role"] == config.ROLE_ANALYST:
        deny(caller, "User does not have permission to perform this operation", SERVICE)

    user = repository.get_by_username(username)
    if caller["role"] == config.ROLE_USER and (
        user is None or user["user_id"] != caller["user_id"]
    ):
        # Same answer whether the user exists or not, so names cannot be probed.
        deny(caller, "You can only view your own user information", SERVICE)
    if user is None:
        raise ApiError("User not found", 404)
    return success_response("User retrieved successfully", user)


@app.put("/users/<user_id>")
def update_user(user_id):
    """Update full_name, email and/or department of a user.

    A Security Administrator may update anyone. A Regular User may only update
    their own record.

    Implemented by: Adam Yahya
    """
    caller = authenticate(SERVICE)
    if caller["role"] not in (config.ROLE_ADMIN, config.ROLE_USER):
        deny(caller, "User does not have permission to perform this operation", SERVICE)

    user_id = parse_id(user_id, "user id")
    if caller["role"] == config.ROLE_USER and user_id != caller["user_id"]:
        deny(caller, "You can only update your own user information", SERVICE)

    data = get_json_body()
    check_fields(data, allowed=["full_name", "email", "department"])

    if repository.get_by_id(user_id) is None:
        raise ApiError("User not found", 404)

    fields = {}
    if "full_name" in data:
        fields["full_name"] = clean_text(data["full_name"], "full_name", max_length=100)
    if "email" in data:
        fields["email"] = validate_email(data["email"])
    if "department" in data:
        fields["department"] = clean_text(data["department"], "department", max_length=100)

    if "email" in fields and repository.email_taken_by_other(fields["email"], user_id):
        raise ApiError("Email is already registered", 409)

    try:
        repository.update_user(user_id, fields)
    except sqlite3.IntegrityError:
        raise ApiError("Email is already registered", 409)

    log_event(caller["user_id"], "User updated",
              f"User {user_id} updated fields: {', '.join(fields)}",
              "Information", SERVICE)
    return success_response("User updated successfully", repository.get_by_id(user_id))


@app.delete("/users/<user_id>")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def delete_user(user_id):
    """Delete a user account (Security Administrator only).

    Implemented by: Adam Yahya
    """
    caller = g.current_user
    user_id = parse_id(user_id, "user id")

    user = repository.get_by_id(user_id)
    if user is None:
        raise ApiError("User not found", 404)
    if user_id == caller["user_id"]:
        raise ApiError("You cannot delete your own account", 400)

    try:
        repository.delete_user(user_id)
    except sqlite3.IntegrityError:
        raise ApiError(
            "User is still referenced by assets, incidents or other records "
            "and cannot be deleted", 409)

    log_event(caller["user_id"], "User deleted",
              f"Account '{user['username']}' (id {user_id}) deleted",
              "Warning", SERVICE)
    return success_response("User deleted successfully")


if __name__ == "__main__":
    app.run(port=config.PORTS["users"])
