# Phishing Email Inspector

An offline Python tool for reviewing saved `.eml` email messages. It flags suspicious indicators and explains each finding without opening links, rendering HTML, extracting attachments, or contacting external services. Python 3.10+; standard library only.

## Try it

```bash
python inspector.py examples/suspicious.eml
python inspector.py examples/ordinary.eml
python -m unittest discover -v
```

On Windows, use `py` instead of `python` if needed. To review your own email, export it as `.eml` in your email client and pass its path to the script. Maximum CLI input size: 10 MiB. Files remain on your computer.

## What it checks

| Indicator | Why review it? |
| --- | --- |
| From / Reply-To domain mismatch | Replies may go to a different organization. Legitimate services also do this. |
| Visible URL differs from destination | The link may conceal where it leads. Only explicit HTTP(S) URLs shown as link text are compared. |
| Urgent or credential-related wording | May pressure someone into sharing sensitive information; context matters. |
| HTTP or IP-address links | May lead to an unusual or unencrypted destination. |
| User-info in URLs | Text before `@` may disguise the actual host. |
| Punycode hostnames | Internationalized domains can need closer visual review; many are legitimate. |
| Executable attachment extensions | Could run code if opened. Attachment bytes are not inspected. |

MIME multipart messages, base64/quoted-printable encodings, and plain-text/HTML bodies are supported. JSON output lists findings and link hosts. Full URLs are omitted from the output to reduce exposure of tracking tokens. Exit code **0** means analysis completed, even with findings; **2** means an input error.

The synthetic suspicious example produces six findings: reply-domain mismatch, misleading link, urgency wording, sensitive-information wording, an HTTP link and an IP-address link. The ordinary example produces none. All example domains and addresses are reserved for documentation.

## Limits

**This is a triage aid, not a safe/malicious verdict.** No findings does not mean an email is safe. Legitimate messages can trigger findings. Header domains can be forged. The tool does not verify SPF, DKIM or DMARC, resolve DNS, check reputation, scan attachment contents, inspect nested attached emails, or detect every obfuscated link. Exact hosts are compared without a public-suffix database, so different subdomains can trigger link mismatches. Wording rules are English-only. Malformed HTML and unusual email structures may evade rules. Do not upload real emails or output containing private subjects, filenames or addresses to public repositories.

## Development

Tests cover ordinary messages, mismatched/matching domains and links, encoded bodies, attachments, pressure wording, HTTP/IP links, malformed URLs, missing senders, user-info and punycode. GitHub Actions runs the tests on Python 3.10 and 3.13.

Created with AI assistance as a cybersecurity portfolio project.
