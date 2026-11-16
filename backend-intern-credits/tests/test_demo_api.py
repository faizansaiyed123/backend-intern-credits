import sys
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from demo_main import (  # noqa: E402
    DEMO_CREDIT_ADMIN_KEY,
    DEMO_EMAIL,
    DEMO_PASSWORD,
    DEMO_SCHEMA_ADMIN_KEY,
    app,
    reset_demo_state,
)


class MintlineDemoApiTests(unittest.TestCase):
    def setUp(self):
        reset_demo_state()
        self.client = TestClient(app)
        response = self.client.post(
            "/api/auth/login",
            json={"email": DEMO_EMAIL, "password": DEMO_PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        self.token = response.json()["access_token"]
        self.auth = {"Authorization": "Bearer " + self.token}

    def test_seeded_login_and_account_read(self):
        current = self.client.get("/api/auth/me", headers=self.auth)
        self.assertEqual(current.status_code, 200)
        self.assertEqual(current.json()["user_id"], 1)

        balance = self.client.get("/api/credits/1", headers=self.auth)
        self.assertEqual(balance.status_code, 200)
        self.assertEqual(balance.json()["credits"], 1280)

    def test_registration_creates_zero_balance_and_duplicate_is_rejected(self):
        payload = {
            "name": "New Demo User",
            "email": "new.user@example.com",
            "password": "A-Long-Demo-Password-2026",
        }
        created = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(created.status_code, 201)
        user_id = created.json()["user"]["user_id"]
        headers = {"Authorization": "Bearer " + created.json()["access_token"]}
        balance = self.client.get("/api/credits/" + str(user_id), headers=headers)
        self.assertEqual(balance.status_code, 200)
        self.assertEqual(balance.json()["credits"], 0)
        duplicate = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(duplicate.status_code, 409)

    def test_account_scope_and_operator_access(self):
        hidden = self.client.get("/api/credits/2", headers=self.auth)
        self.assertEqual(hidden.status_code, 404)

        operator_headers = {
            **self.auth,
            "X-API-Key": DEMO_CREDIT_ADMIN_KEY,
        }
        visible = self.client.get("/api/credits/2", headers=operator_headers)
        self.assertEqual(visible.status_code, 200)
        self.assertEqual(visible.json()["credits"], 760)

    def test_credit_mutations_enforce_operator_key_and_balance_rules(self):
        no_key = self.client.post(
            "/api/credits/1/add",
            json={"amount": 20},
            headers=self.auth,
        )
        self.assertEqual(no_key.status_code, 403)

        operator_headers = {
            **self.auth,
            "X-API-Key": DEMO_CREDIT_ADMIN_KEY,
        }
        added = self.client.post(
            "/api/credits/1/add",
            json={"amount": 50},
            headers=operator_headers,
        )
        self.assertEqual(added.status_code, 200)
        self.assertEqual(added.json()["credits"], 1330)

        deducted = self.client.post(
            "/api/credits/1/deduct",
            json={"amount": 30},
            headers=operator_headers,
        )
        self.assertEqual(deducted.status_code, 200)
        self.assertEqual(deducted.json()["credits"], 1300)

        reset = self.client.patch("/api/credits/1/reset", headers=operator_headers)
        self.assertEqual(reset.status_code, 200)
        self.assertEqual(reset.json()["credits"], 0)

        excessive = self.client.post(
            "/api/credits/1/deduct",
            json={"amount": 1},
            headers=operator_headers,
        )
        self.assertEqual(excessive.status_code, 400)

    def test_schema_migrations_are_recorded_but_sql_is_not_executed(self):
        headers = {"X-API-Key": DEMO_SCHEMA_ADMIN_KEY}
        sql = "CREATE INDEX IF NOT EXISTS idx_demo_credits_updated ON credits(last_updated DESC)"
        applied = self.client.post(
            "/api/schema/apply",
            headers=headers,
            json={"migration_name": "demo_index", "sql": sql},
        )
        self.assertEqual(applied.status_code, 200)
        self.assertEqual(applied.json()["status"], "applied")

        duplicate = self.client.post(
            "/api/schema/apply",
            headers=headers,
            json={"migration_name": "demo_index", "sql": sql},
        )
        self.assertEqual(duplicate.json()["status"], "skipped")

        rejected = self.client.post(
            "/api/schema/apply",
            headers=headers,
            json={"migration_name": "unsafe", "sql": "DROP TABLE credits"},
        )
        self.assertEqual(rejected.status_code, 400)

        history = self.client.get("/api/schema/migrations", headers=headers)
        self.assertEqual(history.status_code, 200)
        names = [item["migration_name"] for item in history.json()["migrations"]]
        self.assertIn("demo_index", names)
        self.assertNotIn("unsafe", names)

    def test_daily_credit_refresh_is_idempotent_per_utc_date(self):
        headers = {"X-API-Key": DEMO_CREDIT_ADMIN_KEY}
        first = self.client.post(
            "/api/demo/scheduler/run-daily-credit-refresh",
            headers=headers,
        )
        self.assertEqual(first.json()["status"], "applied")

        second = self.client.post(
            "/api/demo/scheduler/run-daily-credit-refresh",
            headers=headers,
        )
        self.assertEqual(second.json()["status"], "skipped")

        balance = self.client.get("/api/credits/1", headers=self.auth)
        self.assertEqual(balance.json()["credits"], 1285)

    def test_logout_revokes_session(self):
        response = self.client.post("/api/auth/logout", headers=self.auth)
        self.assertEqual(response.status_code, 200)
        current = self.client.get("/api/auth/me", headers=self.auth)
        self.assertEqual(current.status_code, 401)


if __name__ == "__main__":
    unittest.main()
