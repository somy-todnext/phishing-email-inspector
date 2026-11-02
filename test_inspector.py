import unittest
from inspector import inspect


def rules(body, headers=''):
    data = ('From: Support <help@example.com>\n' + headers + '\n' + body).encode()
    return {f['rule'] for f in inspect(data)['findings']}


class InspectorTests(unittest.TestCase):
    def test_ordinary_email(self):
        self.assertEqual(rules('Meeting notes: https://example.com/notes'), set())

    def test_reply_mismatch(self):
        self.assertIn('reply_domain_mismatch', rules('Hello', 'Reply-To: person@example.net\n'))

    def test_matching_reply(self):
        self.assertNotIn('reply_domain_mismatch', rules('Hello', 'Reply-To: other@EXAMPLE.COM\n'))

    def test_misleading_html(self):
        self.assertIn('misleading_link', rules('<a href="https://example.net">https://example.com</a>', 'Content-Type: text/html\n'))

    def test_matching_html(self):
        self.assertNotIn('misleading_link', rules('<a href="https://example.com/login">https://example.com</a>', 'Content-Type: text/html\n'))

    def test_ip_http_and_pressure(self):
        found = rules('Urgent: provide your password immediately http://192.0.2.1')
        self.assertTrue({'urgency_language', 'sensitive_information_language', 'ip_address_link', 'unencrypted_link'} <= found)

    def test_attachment(self):
        self.assertIn('executable_attachment', rules('unused', 'Content-Disposition: attachment; filename="invoice.exe"\n'))

    def test_encoded_body(self):
        self.assertIn('sensitive_information_language', rules('cGFzc3dvcmQ=', 'Content-Transfer-Encoding: base64\n'))

    def test_missing_sender(self):
        self.assertIn('missing_sender', {f['rule'] for f in inspect(b'Subject: Hello\n\nHi')['findings']})

    def test_malformed_url(self):
        self.assertEqual(rules('https://[broken'), set())

    def test_userinfo(self):
        self.assertIn('url_userinfo', rules('https://example.com@evil.example/login'))

    def test_punycode(self):
        self.assertIn('internationalized_domain', rules('https://xn--bcher-kva.example'))


if __name__ == '__main__':
    unittest.main()
