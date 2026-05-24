# Lab 3 — Identity & Security Incident
**The Compromised Identity**

## Scenario
A P1 critical security incident was raised by the CISO. Three simultaneous
security failures were detected in the Azure environment — all related to
identity and access control.

## Problems Found
| # | Problem | Root Cause |
|---|---------|------------|
| 1 | Service principal had Owner at subscription scope | Web app Service Principle only needs to read one Key Vault secret — Owner = full admin over entire subscription |
| 2 | Key Vault had no RBAC, open network, weak soft delete | Legacy Access Policies + Allow network default + 7-day retention — compliance violation |
| 3 | Conditional Access MFA policy in Report-only mode | Policy existed but was not enforcing — nobody required to complete MFA |

## How I Fixed It
- Removed Owner role, assigned Key Vault Secrets User scoped to Key Vault only
- Enabled RBAC on Key Vault, locked network firewall to Deny by default
- Disabled Security Defaults, switched CA policy from Report-only to On
- Documented soft delete retention as deployment-time finding

## Tools Used
PowerShell · Azure CLI · Entra Admin Center

## Certification Alignment
SC-300 — Identity & Access · AZ-500 — Azure Security

## Evidence
- `Lab3_Incident_Report_INC0134.docx` — full incident report
- `lab3_proof_sp.png` — SP role assignment verified
- `lab3_proof_kv.png` — Key Vault settings hardened
- `lab3_proof_ca.png` — Conditional Access policy On
- `lab3_proof_resources.png` — all resources deployed
