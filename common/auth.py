from datetime import datetime, timedelta, timezone
from functools import wraps

import jwt
from flask import g, request

from common import config
from common.audit import log_event
from common.db import fetch_one
from common.errors import ApiError


def create_token(user):
    """Create a signed token for a user who just logged in.

    :param user: dictionary with ``user_id`` and ``role``.
    :return: the encoded JWT as text.
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["user_id"]),   # JWT subject must be text
        "role": user["role"],          # informational only, never trusted
        "iat": now,
        "exp": now + timedelta(minutes=config.TOKEN_LIFETIME_MINUTES),
    }
    return jwt.encode(payload, config.SECRET_KEY, algorithm="HS256")


def _reject(message, status_code, service, user_id=None):
    """Log a refused request as an unauthorized access attempt, then raise."""
    log_event(
        user_id,
        "Unauthorized access attempt",
        f"{request.method} {request.path}: {message}",
        "Warning",
        service,
    )
    raise ApiError(message, status_code)


def _get_token(service):
    """Return the token from the ``Authorization: Bearer <token>`` header."""
    header = request.headers.get("Authorization", "")
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        _reject("Authentication required: send 'Authorization: Bearer <token>'",
                401, service)
    return parts[1]


def _get_user_id(token, service):
    """Check the token signature and expiry, and return the user ID inside it."""
    try:
        payload = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"])
        return int(payload["sub"])
    except jwt.ExpiredSignatureError:
        _reject("Token has expired, please log in again", 401, service)
    except (jwt.InvalidTokenError, KeyError, ValueError):
        _reject("Invalid authentication token", 401, service)


def authenticate(service):
    """Identify caller from token and load current record.

    :param service: name of the calling service (used in audit logs).
    :return: the user as a dictionary (never includes the password hash).
    :raises ApiError: 401 if the token is missing, invalid or expired, 403 if
        the account is not Active.
    """
    token = _get_token(service)
    user_id = _get_user_id(token, service)

    user = fetch_one(
        "SELECT user_id, username, full_name, email, department, role, account_status "
        "FROM users WHERE user_id = ?",
        (user_id,),
    )
    if user is None:
        _reject("Account no longer exists", 401, service)
    if user["account_status"] != "Active":
        _reject(f"Account is {user['account_status'].lower()}", 403, service, user_id)

    g.current_user = user
    return user


def current_user():
    """Return the user identified by :func:`authenticate` for this request."""
    return g.current_user


def deny(user, message, service):
    """Refuse a request for a reason the role list cannot express.

    Example: a Regular User asking for another person's record.

    :param user: the authenticated user (dictionary).
    :param message: why access is refused.
    :param service: name of the calling service (used in audit logs).
    :raises ApiError: always, with HTTP 403.
    """
    _reject(message, 403, service, user["user_id"])


def roles_required(*roles, service):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            user = authenticate(service)
            if user["role"] not in roles:
                deny(user, "User does not have permission to perform this operation",
                     service)
            return view(*args, **kwargs)

        return wrapper

    return decorator
