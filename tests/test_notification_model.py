import unittest

from common.errors import ValidationError
from notification_service.models import Notification, notification_id


class NotificationModelTests(unittest.TestCase):
    def test_valid_notification(self):
        item = Notification(1, " Alert ", "Suspicious activity.", "security alert", "high")
        self.assertEqual(item.title, "Alert")
        self.assertEqual(item.notification_type, "Security Alert")
        self.assertEqual(item.severity_level, "High")

    def test_invalid_fields(self):
        with self.assertRaises(ValidationError):
            Notification(True, "Alert", "Message", "Security Alert", "High")
        with self.assertRaises(ValidationError):
            Notification(1, " ", "Message", "Security Alert", "High")
        with self.assertRaises(ValidationError):
            Notification(1, "Alert", "Message", "Other", "High")

    def test_invalid_ids(self):
        for value in ("0", "-1", "abc", "9223372036854775808"):
            with self.assertRaises(ValidationError):
                notification_id(value)


if __name__ == "__main__":
    unittest.main()
