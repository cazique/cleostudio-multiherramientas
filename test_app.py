import unittest
from app import app


class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True

    def test_home_page(self):
        result = self.app.get("/")
        self.assertEqual(result.status_code, 200)

    def test_tool_routes(self):
        tool_routes = [
            "/md-to-pdf",
            "/compress-pdf",
            "/merge-pdf",
            "/split-pdf",
            "/images-to-pdf",
            "/compress-image",
            "/ip-whois",
            "/blacklist-check",
            "/ssl-check",
            "/port-scanner",
            "/http-headers",
            "/password-generator",
        ]
        for route in tool_routes:
            with self.subTest(route=route):
                result = self.app.get(route)
                self.assertEqual(result.status_code, 200, f"Failed on route: {route}")

    def test_auth_routes(self):
        auth_routes = [
            "/login",
            "/register",
        ]
        for route in auth_routes:
            with self.subTest(route=route):
                result = self.app.get(route)
                self.assertEqual(result.status_code, 200, f"Failed on route: {route}")


if __name__ == "__main__":
    unittest.main()
