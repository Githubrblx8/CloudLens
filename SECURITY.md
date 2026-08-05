# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of CloudLens seriously. If you believe you have found a security vulnerability, please report it to us as described below.

**Please do NOT report security vulnerabilities through public GitHub issues.**

### How to Report

Send an email to **security@cloudlens.io** with the following information:

1. Description of the vulnerability
2. Steps to reproduce the issue
3. Potential impact assessment
4. Any suggested fixes (optional)

You should receive a response within 48 hours acknowledging your report.

### What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 5 business days
- **Resolution Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1 week
  - Medium: 2 weeks
  - Low: Next release cycle

### Disclosure Policy

We follow a coordinated disclosure process:
1. Reporter submits vulnerability
2. Our team validates and assesses impact
3. We develop and test a fix
4. Fix is released
5. Public disclosure after 30 days (or earlier by mutual agreement)

## Security Best Practices for Users

### Credential Management
- Never commit cloud credentials to the repository
- Use environment variables or secret managers
- Rotate credentials regularly

### Network Security
- Deploy CloudLens in a private network when possible
- Use TLS for all communications
- Restrict API access with authentication

### Updates
- Keep CloudLens updated to the latest version
- Monitor our security advisories
- Apply patches promptly

## Known Security Considerations

### Current Limitations
- AI models may produce false positives/negatives
- Cloud provider API rate limits may affect scanning completeness
- Some advanced attacks may not be detected

### Mitigations in Place
- Input sanitization on all API endpoints
- Sandboxed plugin execution (WASM)
- Secret redaction in logs
- Rate limiting on GraphQL queries
- Memory-safe Rust implementation

## Security Audit History

| Date       | Auditor          | Result           |
|------------|------------------|------------------|
| 2024-01-15 | Internal Team    | No critical issues |
| 2024-03-20 | Third-party Firm | 2 low findings (fixed) |

## Contact

For security-related questions:
- Email: security@cloudlens.io
- GPG Key: [Available on our website](https://cloudlens.io/security)

Thank you for helping keep CloudLens secure! 🔒
