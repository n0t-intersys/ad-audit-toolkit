# Legal & Responsible Use Policy

```
⚠  AUTHORIZED USE ONLY
These scripts query Active Directory using privileged read access.
Run only on domains you own or have explicit written authorization to audit.
```

## Authorized Use

You may use these scripts if **all** of the following apply:

- You are the domain owner, or
- You hold a signed Scope of Work (SOW) / Rules of Engagement (ROE) from
  the domain owner authorizing security assessment activities, and
- Your actions are limited to the agreed scope and timing

Authorized contexts include:
- Your personal lab environment (e.g., Windows Server VM, home lab AD)
- Internal IT/security teams assessing their own organization's AD
- Authorized penetration testing engagements with documented written consent
- Red team exercises under a formal engagement agreement

## Prohibited Use

The following uses are **strictly prohibited**:

- Running these scripts against any domain you do not own or lack written authorization to assess
- Using findings to exploit, attack, or disclose vulnerabilities without following responsible disclosure
- Providing findings to unauthorized third parties
- Running in production environments without change management approval

## Legal Framework

Unauthorized use may violate:

| Jurisdiction | Law |
|---|---|
| United States | Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030 |
| United Kingdom | Computer Misuse Act 1990 (CMA) |
| European Union | Directive 2013/40/EU on attacks against information systems |
| Canada | Criminal Code § 342.1 (unauthorized use of computer) |
| Australia | Criminal Code Act 1995, Part 10.7 |

Penalties for unauthorized access may include imprisonment and significant fines.

## Engagement Checklist

Before running in any environment, confirm:

- [ ] Written authorization (SOW, ROE, or change ticket) obtained
- [ ] Scope defined: target domain(s), OUs, timeframe
- [ ] Point of contact identified for the target organization
- [ ] Findings handling agreed (who receives the report, retention period)
- [ ] Emergency contact procedure established (in case of unexpected impact)

## Responsible Disclosure

If these scripts reveal vulnerabilities in your organization:

1. Document findings with evidence (CSV exports, screenshots)
2. Assign risk ratings and prioritize remediation
3. Report through established internal channels (CISO, IT leadership)
4. Track remediation to closure
5. Do not disclose findings publicly without organizational approval

---

*The author(s) of this toolkit accept no liability for misuse. Use responsibly.*
