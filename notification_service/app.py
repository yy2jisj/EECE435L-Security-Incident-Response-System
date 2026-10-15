from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import deny, roles_required
from common.errors import ApiError, register_error_handlers, success_response
from common.validators import check_fields, get_json_body
from notification_service import repository
from notification_service.models import Notification, notification_id
from user_service import repository as users

SERVICE = "notifications"
OWNER_ROLES = (config.ROLE_USER, config.ROLE_ANALYST)

app = Flask(__name__)
register_error_handlers(app)


def check_owner(user_id):
    """Restrict employees and analysts to notifications assigned to them."""
    caller = g.current_user
    if caller["role"] in OWNER_ROLES and user_id != caller["user_id"]:
        deny(caller, "You can only access your own notifications", SERVICE)


def find_notification(value):
    """Find an accessible notification without disclosing other recipients."""
    item = repository.get_by_id(notification_id(value))
    caller = g.current_user
    if caller["role"] in OWNER_ROLES:
        if item is None or item["user_id"] != caller["user_id"]:
            deny(caller, "You can only access your own notifications", SERVICE)
    if item is None:
        raise ApiError("Notification not found", 404)
    return item


@app.post("/notifications")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def create_notification():
    """Create an unread notification for an existing Service 1 user.

    Implemented by: Youssef Al Hajj Youness
    """
    data = get_json_body()
    check_fields(data, required=["user_id", "title", "message", "notification_type", "severity_level"])
    new_id = repository.insert_notification(Notification(**data))
    log_event(g.current_user["user_id"], "Notification created",
              f"Notification {new_id} created for user {data['user_id']}", "Information", SERVICE)
    return success_response("Notification created successfully", repository.get_by_id(new_id), 201)


@app.get("/notifications/user/<user_id>")
@roles_required(*config.ALL_ROLES, service=SERVICE)
def get_user_notifications(user_id):
    """Return a recipient's notifications, including an empty history.

    Implemented by: Youssef Al Hajj Youness
    """
    user_id = notification_id(user_id, "user id")
    check_owner(user_id)
    if users.get_by_id(user_id) is None:
        raise ApiError("User not found", 404)
    return success_response("Notifications retrieved successfully", repository.get_for_user(user_id))


@app.get("/notifications/<item_id>")
@roles_required(*config.ALL_ROLES, service=SERVICE)
def get_notification(item_id):
    """Return one permitted notification.

    Implemented by: Youssef Al Hajj Youness
    """
    return success_response("Notification retrieved successfully", find_notification(item_id))


if __name__ == "__main__":
    app.run(port=config.PORTS[SERVICE])
