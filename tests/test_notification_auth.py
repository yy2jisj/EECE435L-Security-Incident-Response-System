from datetime import datetime, timedelta, timezone

import jwt

from common import config
from notification_service import repository
from tests.test_notification_api import NotificationApiCase


class NotificationAuthenticationTests(NotificationApiCase):
    def test_missing_invalid_expired_and_wrong_signature_all_endpoints(self):
        row = self.create()
        now = datetime.now(timezone.utc)
        expired = jwt.encode({"sub": "1", "exp": now - timedelta(seconds=1)}, config.SECRET_KEY, algorithm="HS256")
        wrong = jwt.encode({"sub": "1", "exp": now + timedelta(minutes=1)}, "unrelated-test-signing-key-435L!", algorithm="HS256")
        calls = [("POST", "/notifications"), ("GET", "/notifications/user/1"),
                 ("GET", f"/notifications/{row['notification_id']}"),
                 ("PUT", f"/notifications/{row['notification_id']}/read"),
                 ("GET", "/notifications/search?status=Unread"),
                 ("DELETE", f"/notifications/{row['notification_id']}")]
        for token in (None, "invalid", expired, wrong):
            for method, path in calls:
                headers = {} if token is None else {"Authorization": "Bearer " + token}
                with self.subTest(token_kind="missing" if token is None else "invalid/expired", method=method):
                    self.assert_error(self.client.open(path, method=method, headers=headers), 401)
        self.assertEqual(repository.get_by_id(row["notification_id"])["status"], "Unread")

    def test_analyst_own_notification_and_empty_history(self):
        user_id = self.people["analyst"]["user_id"]
        response = self.client.get(f"/notifications/user/{user_id}", headers=self.analyst)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"], [])
        row = self.create(user_id=user_id, notification_type="Incident Assignment")
        path = f"/notifications/{row['notification_id']}"
        self.assertEqual(self.client.get(path, headers=self.analyst).status_code, 200)
        self.assertEqual(self.client.put(path + "/read", headers=self.analyst).status_code, 200)
        self.assertIsNotNone(repository.get_by_id(row["notification_id"])["read_date"])

    def test_legacy_read_acknowledgement_sets_missing_time_once(self):
        from common.db import execute
        row = self.create()
        execute("UPDATE notifications SET is_read=1 WHERE notification_id=?", (row["notification_id"],))
        response = self.client.put(f"/notifications/{row['notification_id']}/read", headers=self.admin)
        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(response.get_json()["data"]["read_date"])
        self.assertEqual(response.get_json()["data"]["created_at"], row["created_at"])
