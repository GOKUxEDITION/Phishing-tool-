import unittest
from scanner import analyze_url

class ScannerTests(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(analyze_url("")["level"],"Unknown")
    def test_https_normal(self):
        r=analyze_url("https://example.com")
        self.assertEqual(r["level"],"Low")
    def test_raw_ip(self):
        self.assertGreaterEqual(analyze_url("http://192.0.2.1/login")["score"],35)
    def test_shortener(self):
        self.assertIn("shortener", " ".join(analyze_url("https://bit.ly/example")["findings"]).lower())
    def test_punycode(self):
        self.assertIn("punycode", " ".join(analyze_url("https://xn--example-ova.com")["findings"]).lower())
if __name__=="__main__": unittest.main()
