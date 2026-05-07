# Security Policy

## Supported Versions

CyberCat is currently in active development. Security fixes are applied to the latest version only.

| Version | Supported |
|---------|-----------|
| Latest (main branch) | ✅ |
| Older versions | ❌ |

---

## Reporting a Vulnerability

CyberCat is a security tool — responsible disclosure is something we take seriously.

If you discover a security vulnerability in CyberCat, **please do not open a public GitHub issue.** Public disclosure before a fix is available puts users at risk.

### How to Report

**Preferred method:** Use GitHub's built-in private vulnerability reporting:

1. Go to the [Security tab](../../security) of this repository
2. Click **"Report a vulnerability"**
3. Fill in the details — the more specific, the better

**Alternative:** Email the maintainer directly. You can find contact information in the repository profile.

### What to Include

A good vulnerability report includes:

- A clear description of the vulnerability
- Steps to reproduce it
- The potential impact (what an attacker could do)
- Any proof-of-concept code or screenshots if applicable
- Your suggested fix, if you have one (not required)

### What to Expect

- **Acknowledgment** within 48 hours of your report
- **Status update** within 7 days confirming whether the issue is accepted or declined
- **Credit** in the fix commit and changelog if you'd like it (just let us know)
- **Coordinated disclosure** — we'll work with you on timing before any public disclosure

---

## Scope

### In Scope

- Vulnerabilities in the CyberCat application code (`cybercat.jsx`)
- Issues with the PII redaction engine that could cause sensitive data to leak to the Claude API
- Logic flaws in the sanitization or token-map pipeline
- Dependency vulnerabilities with direct security impact

### Out of Scope

- Vulnerabilities in the Anthropic Claude API itself (report those to [Anthropic](https://anthropic.com/security))
- Issues requiring physical access to a user's device
- Social engineering attacks
- Theoretical vulnerabilities without a realistic attack path
- Bugs that only affect outdated or unsupported browsers

---

## Important Usage Notes

CyberCat is designed to help analysts work with security logs more efficiently. Please be aware of the following when deploying it in your environment:

### Data Handling

CyberCat sends log data to the **Anthropic Claude API**, an external third-party service. While the built-in PII redaction engine removes many categories of sensitive identifiers before submission, you are responsible for:

- Ensuring compliance with your organization's data classification and handling policies
- Reviewing what data your logs contain before pasting them into the tool
- Understanding that the PII redaction engine, while comprehensive, is not guaranteed to catch every sensitive value in every log format
- Not using CyberCat with logs that contain data subject to strict regulatory requirements (HIPAA, PCI-DSS, etc.) without first verifying compliance with your legal and security teams

### API Key Security

- Never hardcode your Anthropic API key directly in the source code
- Never commit a `.env` file containing your API key to version control
- Rotate your API key immediately if you believe it has been exposed
- The `.gitignore` file in this repo is configured to exclude `.env` files — do not remove this

### Network Considerations

CyberCat makes outbound HTTPS requests to `api.anthropic.com`. Ensure this is permitted by your network security policy before deploying in a corporate environment.

---

## Security Features

CyberCat includes the following built-in security controls:

| Feature | Description |
|---------|-------------|
| **PII Redaction Engine** | Scrubs sensitive field values across 9 log schemas before API submission |
| **Pattern Sweep** | Regex-based sweep catches inline PII (emails, SIDs, internal IPs, UNC paths, SAM accounts) not covered by field-level rules |
| **Token Map** | Full transparency — users can inspect exactly what was redacted and what token replaced it |
| **Hunt Sanitizer** | Additional value-stripping layer for threat hunt queries — preserves field structure only |
| **No Data Persistence** | CyberCat does not store logs, results, or API keys. All data exists only in the browser session |

---

*This security policy was last updated with the initial public release.*
