import unittest
from scanner import analyze_url
from mailtools import analyze_email, extract_iocs

class SuiteTests(unittest.TestCase):
    def test_clean_url(self):
        self.assertEqual(analyze_url("https://example.com")["level"],"Low")
    def test_ip_url_flag(self):
        self.assertGreater(analyze_url("http://192.0.2.1/login")["score"],20)
    def test_shortener_flag(self):
        self.assertIn("shortener"," ".join(analyze_url("https://bit.ly/abc")["findings"]).lower())
    def test_punycode_flag(self):
        self.assertIn("punycode"," ".join(analyze_url("https://xn--test.com")["findings"]).lower())
    def test_ioc_extract(self):
        r=extract_iocs("go https://example.org/test and 8.8.8.8 and evil.test")
        self.assertTrue(r["urls"]); self.assertTrue(r["ipv4"])
    def test_email_urls_and_attachment(self):
        r=analyze_email("From: x@example.com\nSubject: hi\n\nVisit http://example.org and see invoice.exe")
        self.assertTrue(r["urls"]); self.assertTrue(r["attachments"])
if __name__=="__main__": unittest.main()
