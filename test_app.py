
import unittest
from unittest.mock import patch

import app as scam_app


class ScamShieldTests(unittest.TestCase):
    def setUp(self):
        scam_app.app.config["TESTING"] = True
        self.client = scam_app.app.test_client()

    def test_homepage_loads(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    def test_homepage_contains_scamshield(self):
        response = self.client.get("/")
        self.assertIn(b"ScamShield", response.data)

    def test_invalid_page_returns_404(self):
        response = self.client.get("/this-page-does-not-exist")
        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main()