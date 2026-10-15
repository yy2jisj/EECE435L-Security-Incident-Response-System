from flask import jsonify
from werkzeug.exceptions import HTTPException


class ApiError(Exception):
    """An error that should be reported to the client.

    :param message: text shown to the client.
    :param status_code: HTTP status code (400, 401, 403, 404, 409, 503 ...).
    """

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ValidationError(ApiError):
    """Input data is missing or invalid (HTTP 400)."""

    def __init__(self, message):
        super().__init__(message, 400)


def error_response(message, status_code):
    """Build the JSON error response used everywhere.

    :param message: text shown to the client.
    :param status_code: HTTP status code.
    """
    return jsonify({"status": "error", "message": message}), status_code


def success_response(message, data=None, status_code=200):
    """Build the JSON success response used everywhere.

    :param message: text shown to the client.
    :param data: the result (a dictionary or a list).
    :param status_code: HTTP status code.
    """
    return jsonify({"status": "success", "message": message, "data": data}), status_code


def register_error_handlers(app):
    """Attach the JSON error handlers to a Flask app.

    :param app: the Flask application of a service.
    """

    @app.errorhandler(ApiError)
    def handle_api_error(error):
        return error_response(error.message, error.status_code)

    @app.errorhandler(HTTPException)
    def handle_http_error(error):
        messages = {
            404: "Resource not found",
            405: "Method not allowed for this endpoint",
        }
        message = messages.get(error.code, error.description)
        return error_response(message, error.code)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):
        app.logger.exception("Unexpected error: %s", error)
        return error_response("Internal server error", 500)
