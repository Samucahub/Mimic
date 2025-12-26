# Security Policy

## Security Overview

MIMIC is a honeypot framework designed to capture and analyze malicious activity. As such, security is paramount both in the software itself and in how it is deployed.

---

## Deployment Security Guidelines

### Network Isolation

**CRITICAL:** Always deploy MIMIC in an isolated network segment.

- ✅ Use a dedicated VLAN for honeypot deployment
- ✅ Implement strict firewall rules
- ✅ Monitor all traffic to/from the honeypot
- ✅ Prevent lateral movement to production systems
- ❌ **NEVER** deploy on production networks without isolation

### Access Control

- Use strong, unique credentials for the host system
- Implement IP whitelisting for administrative access
- Regularly rotate honeypot credentials
- Monitor admin access logs

### Data Protection

**Captured data may contain sensitive information:**

- Store logs in encrypted volumes
- Implement access controls on log files
- Regularly review and sanitize captured data
- Comply with GDPR and applicable data protection laws
- Implement data retention policies

### Monitoring

- Set up alerting for unusual honeypot activity
- Monitor system resources (CPU, memory, disk)
- Track log file sizes and rotation
- Watch for denial-of-service attempts
- Monitor for potential honeypot detection/evasion

---

## Reporting Security Vulnerabilities

### Responsible Disclosure

If you discover a security vulnerability in MIMIC, please follow responsible disclosure practices:

1. **DO NOT** open a public GitHub issue
2. **DO NOT** discuss the vulnerability publicly until it's fixed
3. **DO** report privately to the maintainers

### How to Report

**Email:** [Create a private security advisory on GitHub]

**Include:**
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)
- Your contact information

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 1 week
- **Fix Timeline:** Depends on severity
  - Critical: 1-7 days
  - High: 1-2 weeks
  - Medium: 2-4 weeks
  - Low: 4-8 weeks
- **Public Disclosure:** After fix is released

### Security Advisory Process

1. **Report received** - Maintainers acknowledge receipt
2. **Verification** - Vulnerability is confirmed and assessed
3. **Fix development** - Patch is created and tested
4. **Private disclosure** - Reporter is notified of fix
5. **Public release** - Security advisory and patch published
6. **Credit** - Reporter is credited (unless they prefer anonymity)

---

## Known Security Considerations

### By Design

MIMIC is **intentionally vulnerable** as a honeypot:

- Accepts invalid credentials (in honeypot mode)
- Emulates vulnerable services
- Exposes network services

**These are FEATURES, not bugs.** However, the honeypot host must be secured.

### Host System Security

**CRITICAL:** The underlying system running MIMIC must be hardened:

- Keep OS and Python up to date
- Minimize installed packages
- Use security scanning tools
- Implement host-based firewall rules
- Enable system auditing and logging

### Port Binding Security

**Low Ports (<1024):**
- SSH (22), FTP (21), HTTP (80), Telnet (23) require elevated privileges
- On Linux: Use `setcap` instead of running as root
- On Windows: Run with Administrator privileges (isolated environment only)

**Recommended approach:**
```bash
# Linux: Grant port binding capability without full root
sudo setcap 'cap_net_bind_service=+ep' /usr/bin/python3.11
```

### Network Security

**Firewall Configuration:**
```bash
# Example: Allow honeypot ports, block everything else
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 23 -j ACCEPT
iptables -A INPUT -j DROP

# Egress filtering (prevent honeypot from making outbound connections)
iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -j DROP
```

---

## Security Best Practices

### Deployment Checklist

- [ ] Deploy in isolated network segment
- [ ] Configure firewall rules
- [ ] Enable system logging and monitoring
- [ ] Set up log rotation and archival
- [ ] Implement intrusion detection (IDS/IPS)
- [ ] Document deployment configuration
- [ ] Establish incident response procedures
- [ ] Configure automated backups (logs only, not honeypot state)
- [ ] Test isolation (verify no production access)
- [ ] Review legal compliance

### Regular Maintenance

- **Weekly:**
  - Review captured credentials and activity
  - Check disk space and log sizes
  - Verify honeypot is functioning correctly

- **Monthly:**
  - Update Python and dependencies
  - Review and rotate credentials
  - Audit firewall rules
  - Test backup/restore procedures

- **Quarterly:**
  - Security audit of host system
  - Review and update deployment documentation
  - Test incident response procedures

### Incident Response

**If the honeypot host is compromised:**

1. **Isolate** - Disconnect from network immediately
2. **Preserve** - Take memory dump and disk image
3. **Analyze** - Forensic analysis of compromise
4. **Report** - Document incident and lessons learned
5. **Rebuild** - Fresh deployment with updated security

---

## Security Resources

### Honeypot Security
- [The Honeynet Project](https://www.honeynet.org/)
- [SANS Honeypot Research](https://www.sans.org/white-papers/)
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots)

### General Security
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

### Legal Compliance
- [GDPR Guidelines](https://gdpr.eu/)
- [CFAA Overview](https://www.justice.gov/criminal-ccips/computer-fraud-and-abuse-act)
- [Computer Misuse Act (UK)](https://www.legislation.gov.uk/ukpga/1990/18/contents)

---

## 📝 Changelog

### Security Updates

**Version 1.0.0 (2025-12-24)**
- Initial release
- SSH, FTP, HTTP, Telnet, MySQL emulation
- JSON logging with credential capture
- OS template simulation
- Visual configurator with security warnings

---

## Acknowledgments

We thank the security research community for responsible disclosure practices and contributions to improving MIMIC's security.

---

## Contact

**Security Team:** [GitHub Security Advisories](https://github.com/Samucahub/mimic/security/advisories)

**Project Maintainer:** [@Samucahub](https://github.com/Samucahub)

---

<div align="center">

**🎭 Security is not just a feature, it's a performance. 🎭**

*Deploy responsibly. Monitor vigilantly. Report ethically.*

</div>

