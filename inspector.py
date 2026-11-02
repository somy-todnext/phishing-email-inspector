"""Inspect saved .eml messages offline; heuristic findings are not a verdict."""
import argparse
from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from html.parser import HTMLParser
import ipaddress
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


def host(url):
    try:
        parsed = urlsplit(url.strip())
        if parsed.scheme.lower() not in ('http', 'https'):
            return None
        return (parsed.hostname or '').lower().rstrip('.') or None
    except ValueError:
        return None


class Links(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.text = []
        self.active = None

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            self.active = [dict(attrs).get('href', ''), []]

    def handle_data(self, data):
        self.text.append(data)
        if self.active is not None:
            self.active[1].append(data)

    def handle_endtag(self, tag):
        if tag == 'a' and self.active is not None:
            self.links.append((self.active[0], ''.join(self.active[1]).strip()))
            self.active = None


def inspect(data):
    message = BytesParser(policy=policy.default).parsebytes(data)
    findings = []
    urls = set()
    texts = []
    def flag(rule, detail):
        finding = {'rule': rule, 'detail': detail}
        if finding not in findings:
            findings.append(finding)
    def domains(field):
        addresses = getaddresses([str(v) for v in message.get_all(field, [])])
        return sorted({addr.rsplit('@', 1)[1].lower().rstrip('.') for _, addr in addresses if '@' in addr})
    sender, reply = domains('From'), domains('Reply-To')
    if not sender:
        flag('missing_sender', 'No usable sender domain was found.')
    if len(message.get_all('From', [])) > 1:
        flag('multiple_from_headers', 'Multiple From headers require manual review.')
    if sender and reply and sender != reply:
        flag('reply_domain_mismatch', f'Replies go to {reply}, while the sender domains are {sender}. Legitimate services may do this.')
    for part in message.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename and filename.lower().endswith(('.exe', '.scr', '.bat', '.cmd', '.ps1', '.js', '.vbs', '.msi', '.lnk')):
            flag('executable_attachment', f'Potentially executable attachment: {filename}')
        if part.get_content_disposition() == 'attachment' or filename:
            continue
        if part.get_content_type() not in ('text/plain', 'text/html'):
            continue
        payload = part.get_payload(decode=True) or b''
        try:
            text = payload.decode(part.get_content_charset() or 'utf-8', errors='replace')
        except LookupError:
            text = payload.decode('utf-8', errors='replace')
        if part.get_content_type() == 'text/html':
            parser = Links()
            parser.feed(text)
            texts.extend(parser.text)
            for target, label in parser.links:
                target_host = host(target)
                if target_host:
                    urls.add(target.strip())
                    visible = host(label)
                    if visible and visible != target_host:
                        flag('misleading_link', f'Link displays {visible} but points to {target_host}.')
        else:
            texts.append(text)
        for match in re.findall(r'https?://[^\s<>"\x27]+', text, flags=re.I):
            url = match.rstrip('.,;!?)')
            if host(url):
                urls.add(url)
    content = ' '.join([str(message.get('Subject', ''))] + texts)
    if re.search(r'\b(urgent|immediately|within 24 hours|account suspended|act now)\b', content, re.I):
        flag('urgency_language', 'Urgency or account-pressure wording appears in the subject/body.')
    if re.search(r'\b(password|passcode|verification code|credit card|bank details)\b', content, re.I):
        flag('sensitive_information_language', 'The message mentions credentials or financial information; review the request in context.')
    for url in sorted(urls):
        hostname = host(url)
        parsed = urlsplit(url)
        if parsed.scheme.lower() == 'http':
            flag('unencrypted_link', f'Unencrypted HTTP link to {hostname}.')
        if parsed.username is not None:
            flag('url_userinfo', f'A link uses misleading user-info before its host: {hostname}.')
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            flag('ip_address_link', f'A link uses an IP address instead of a domain: {hostname}.')
        if any(label.startswith('xn--') for label in hostname.split('.')):
            flag('internationalized_domain', f'Punycode domain needs visual review: {hostname}. This alone is not malicious.')
    return {'subject': str(message.get('Subject', '')), 'sender_domains': sender,
            'reply_domains': reply, 'findings': findings, 'finding_count': len(findings),
            'link_hosts': sorted({host(url) for url in urls}),
            'limitations': 'Heuristics only. No findings does not mean safe. Sender headers are unverified; SPF/DKIM/DMARC and reputation are not checked. Links are never visited.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('email', help='Saved .eml file (maximum 10 MiB)')
    args = parser.parse_args(argv)
    try:
        with Path(args.email).open('rb') as source:
            data = source.read(10 * 1024 * 1024 + 1)
        if len(data) > 10 * 1024 * 1024:
            raise ValueError('Email exceeds the 10 MiB limit')
        print(json.dumps(inspect(data), indent=2, ensure_ascii=True))
        return 0
    except (OSError, ValueError) as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
