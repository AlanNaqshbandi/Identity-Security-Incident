# Lab 3 — Identity & Security Incident Response

## Overview
A P1 critical security incident was raised by the CISO after SIEM alerts
fired simultaneously on three separate identity and access control failures.
The environment had a running Azure infrastructure with a Key Vault storing
production secrets — database passwords and API keys — all exposed due to
misconfigurations in identity, access, and authentication layers.

This lab simulates a real security incident response scenario requiring
diagnosis and remediation under pressure across three different Azure
security domains.

---

## Environment
| Resource | Details |
|---|---|
| Platform | Microsoft Azure |
| Region | canadacentral |
| Resource Group | lab3-rg |
| Key Vault | lab3-kv (production secrets store) |
| Service Principal | lab3-webapp-sp (web application identity) |
| Secrets at Risk | Database connection string + API keys |
| Cert Alignment | SC-300 — Identity · AZ-500 — Azure Security |

---

## Problems Found
| # | Area | Problem | Severity |
|---|---|---|---|
| 1 | RBAC | Service principal had Owner role at subscription scope | 🔴 Critical |
| 2 | Key Vault | No RBAC, open network firewall, 7-day soft delete | 🔴 Critical |
| 3 | Entra ID | Conditional Access MFA policy in Report-only mode | 🔴 Critical |

---

## Problem 1 — Over-Privileged Service Principal

**What was wrong:**
The webapp service principal had Owner role assigned at subscription scope.
Owner is the highest privilege level in Azure — it can delete any resource,
assign any role to anyone, and access all data across the entire subscription.
A web application only needs to read one specific secret from Key Vault.

**Why it matters:**
If the SP credentials were ever leaked or stolen, an attacker would have
complete control over the entire Azure subscription — every VM, database,
storage account, and security setting.

**Diagnostic command used:**
```bash
az role assignment list --assignee <SP_ID> --all \
  --query "[].{Role:roleDefinitionName, Scope:scope}" -o table
```

**Fix applied:**
- Removed Owner role at subscription scope
- Assigned Key Vault Secrets User role scoped only to the specific Key Vault
- SP now has exactly one permission: read secrets from one vault

---

## Problem 2 — Key Vault Security Misconfigurations

**What was wrong:**
Three separate issues found on the Key Vault:
1. RBAC was disabled — using legacy Access Policies instead
2. Network firewall defaultAction was Allow — open to the entire internet
3. Soft delete retention was 7 days — minimum possible, not production-grade

**Why it matters:**
Legacy Access Policies are harder to audit and do not integrate with
Azure RBAC properly. An open network means anyone on the internet can
attempt to reach the vault. 7-day soft delete means secrets deleted by
mistake or by an attacker could be permanently lost within a week.

**Diagnostic command used:**
```bash
az keyvault show --name <KV_NAME> \
  --query "{RBAC:properties.enableRbacAuthorization,
            Network:properties.networkAcls.defaultAction,
            SoftDelete:properties.softDeleteRetentionInDays}" -o table
```

**Fix applied:**
- Enabled RBAC authorization on the Key Vault
- Locked network firewall to Deny by default with AzureServices bypass
- Documented soft delete as a deployment-time finding — Azure does not
  allow changing retention after creation. Must be set to 90 in Bicep
  before deploying

---

## Problem 3 — Conditional Access MFA Not Enforcing

**What was wrong:**
A Conditional Access policy named Require-MFA-All-Users existed in the
tenant but was in Report-only mode. Report-only means the policy only
logs what would happen — it does not enforce anything. During this window
three suspicious sign-in attempts from unknown locations were detected.

**Why it matters:**
With no MFA enforced, any user whose password is compromised gives an
attacker immediate access with no second factor to stop them. This is
the most common entry point for identity-based attacks.

**Diagnostic step:**
Entra Admin Center → Protection → Conditional Access → Policies →
confirmed State = Report-only

**Fix applied:**
- Disabled Security Defaults (required before custom CA policies can be enabled)
- Changed policy state from Report-only to On
- MFA now enforced for all users including guests and external accounts

---

## Verification Results
| # | Check | Result |
|---|---|---|
| 1 | SP role assignment — Owner removed | ✅ Key Vault Secrets User only |
| 2 | Key Vault RBAC enabled | ✅ True |
| 3 | Key Vault network locked | ✅ Deny |
| 4 | CA policy enforcing MFA | ✅ State: On |
| 5 | Soft delete retention | ⚠️ Documented — cannot change post-creation |

---

## Key Lessons

**Least privilege is not optional.**
A service principal should have only the minimum role needed for its
specific job — scoped to the specific resource it needs. Never use
Owner or Contributor for application identities.

**Report-only is not the same as On.**
A Conditional Access policy in Report-only enforces nothing. Always
verify the State is On in production environments, not just that the
policy exists.

**Key Vault settings must be right at deployment time.**
Soft delete retention cannot be changed after creation. Set it to 90
days in your Bicep or ARM template before deploying.

**Security Defaults vs Conditional Access — choose one.**
Security Defaults provides basic protection for free tenants. Enterprise
environments disable it and use Conditional Access policies for full
control over authentication requirements.

---

## Tools Used
PowerShell · Azure CLI · Bicep · Microsoft Entra Admin Center

## Certification Alignment
- **SC-300** — Implement and manage identity · Conditional Access · Service Principals
- **AZ-500** — Manage Key Vault security · RBAC · Identity protection

## Evidence
- `Lab3_Incident_Report_INC0134.docx` — full incident report with interview story
- `Lab3_Technical_Journal.docx` — every command and output from A to Z
- `lab3_proof_sp.png` — SP role fixed, Owner removed
- `lab3_proof_kv.png` — Key Vault RBAC and firewall hardened
- `lab3_proof_ca.png` — Conditional Access policy On
- `lab3_proof_resources.png` — all deployed resources
