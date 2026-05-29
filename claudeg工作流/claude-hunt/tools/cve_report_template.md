# CVE Report Template (English — Submit to NVD/MITRE)

## Summary

- **Product**: [Product Name]
- **Vendor**: [Vendor / GitHub Organization]
- **Version**: [Affected Versions]
- **Type**: [Vulnerability Type, e.g., Remote Code Execution]
- **CWE**: [CWE-XX]
- **CVSS**: [Score] ([Vector String])

## Description

[One paragraph describing the vulnerability. Include:
- What component is affected
- What the vulnerability allows an attacker to do
- Whether authentication is required]

## Affected Versions

- [Product] <= [Version]
- Fixed in: [Version] (if available)

## Proof of Concept

```
[Include minimal PoC that demonstrates the vulnerability.
Do NOT include weaponized exploits.]
```

## Impact

[Describe what an attacker can achieve:
- Remote Code Execution
- Data Leak
- Privilege Escalation
- Denial of Service]

## Remediation

[Vendor patch / Workaround / Configuration change]

## Timeline

| Date | Event |
|------|-------|
| YYYY-MM-DD | Vulnerability discovered |
| YYYY-MM-DD | Reported to vendor |
| YYYY-MM-DD | Vendor acknowledged |
| YYYY-MM-DD | Patch released |
| YYYY-MM-DD | Public disclosure |

## Credit

- Discovered by: [Your Name / Handle]

## References

- [GitHub Repository URL]
- [Vendor Advisory URL]
- [Related CVE if any]

---

## Submission Checklist

- [ ] Report sent to vendor (email / security@vendor.com / GitHub Security Advisory)
- [ ] Wait 90 days for vendor response (or 45 days for critical)
- [ ] Submit to MITRE: https://cveform.mitre.org/
- [ ] Submit to NVD: https://nvd.nist.gov/vuln/submit
