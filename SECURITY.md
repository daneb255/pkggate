# Security Policy

## Reporting Security Vulnerabilities

**⚠️ DO NOT file security vulnerabilities as public issues.**

If you discover a security vulnerability in pkggate, please report it responsibly by emailing the maintainer directly. This allows us to address the issue before it becomes public.

### How to Report

1. Email the maintainer at `d@bitzer.dev`
2. Include:
   - Description of the vulnerability
   - Steps to reproduce (if applicable)
   - Potential impact
   - Suggested fix (if you have one)
   - Your contact information for follow-up

3. **Do not:**
   - Post details publicly
   - Create a public GitHub issue
   - File a CVE independently
   - Disclose the vulnerability on social media

### Response Timeline

- We will acknowledge receipt within 48 hours
- We will provide an initial assessment within 5 business days
- We will work toward a fix and coordinated disclosure
- Credit will be given to reporters (unless you prefer anonymity)

## Vulnerability in Malicious Packages

If you've discovered a malicious package that should be flagged:

- Report it directly to [OSV.dev](https://osv.dev/)
- Report it to the [OSSF Malicious Packages](https://github.com/ossf/malicious-packages) project
- This helps the entire ecosystem benefit from the detection

## Security Considerations for Users

### Deployment

- Run pkggate in a trusted network environment
- Use TLS/HTTPS when exposing pkggate over the network
- Restrict access to the audit log (contains dependency information)
- Run as non-root (the provided Docker image does this)
- Keep the policy file restricted (mode 600 or similar)

### Configuration

- Review `config/policy.yaml` regularly to ensure policies match your risk appetite
- Enable `PKGGATE_MIRROR_ENABLED=true` to keep package lookups private
- Consider `PKGGATE_LIVE_FALLBACK_ENABLED=false` for air-gapped environments
- Monitor `audit.log` for blocked packages and policy violations

### Dependencies

- Keep pkggate and its dependencies up to date
- Review security advisories for `aiohttp`, `pydantic`, and other core deps
- Use a dependency scanner (like `safety` or `pip-audit`) in your CI/CD

## Known Security Limitations

1. **Early Prototype:** pkggate is in early-stage development. APIs and formats may change.
2. **No Authentication:** pkggate does not authenticate clients. Deploy behind a firewall or reverse proxy with auth.
3. **No Encryption:** Traffic between pkggate and clients is unencrypted by default. Use a reverse proxy (nginx, HAProxy) with TLS.
4. **Audit Log:** The audit log contains PII about packages your team installs. Protect it appropriately.

## Security Roadmap

- [ ] Support for authenticated clients (API keys)
- [ ] TLS/HTTPS first-class support
- [ ] Audit log encryption at rest
- [ ] Threat model documentation

## Acknowledgments

We are grateful to security researchers and the open-source community for helping keep pkggate and the broader ecosystem secure.

## See Also

- [README.md](README.md) - Project overview
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) - Community standards
- [CONTRIBUTING.md](CONTRIBUTING.md) - Developer guidelines
