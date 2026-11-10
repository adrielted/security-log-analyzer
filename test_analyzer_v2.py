import unittest
from analyzer_v2 import analyze


class TestAnalyzer(unittest.TestCase):

    def test_login_order(self):
        report = analyze("test_order.log")
        self.assertEqual(report["events"], 2)
        self.assertEqual(report["alerts"], [])
    def test_login_noise(self):
        report = analyze("test_noise.log")
        self.assertEqual(report["events"], 1)
        self.assertEqual(report["alerts"], [])
        self.assertEqual(report["ignored"], 1)
    def test_auth_log(self):
        report = analyze("auth.log")
        self.assertEqual(report["events"], 31)
        self.assertEqual(len(report["alerts"]), 6)

if __name__ == "__main__":
    unittest.main()
