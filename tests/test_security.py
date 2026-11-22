import unittest
from security import rate_limited, security_headers

class SecurityTests(unittest.TestCase):
    def test_rate_limit(self):
        key='test-key-'+str(id(self))
        for _ in range(2): self.assertFalse(rate_limited(key,limit=2,window=60))
        self.assertTrue(rate_limited(key,limit=2,window=60))
    def test_headers(self):
        class Response:
            headers={}
        r=security_headers(Response())
        self.assertEqual(r.headers['X-Frame-Options'],'DENY')
        self.assertIn('frame-ancestors',r.headers['Content-Security-Policy'])

if __name__=='__main__': unittest.main()
