# Remediation Roadmap — HOUNDLABS.EPI

Consolidated, prioritized view across all 11 solved challenges. Each
write-up's own `Remediation & Recommendations` section covers that
finding in isolation; this document exists because several of the same
root causes recur across multiple, independently-scored findings — fixing
one control here closes several write-ups' exposure at once. This is a
supplementary synthesis, not a replacement for the per-challenge
sections, which remain the graded deliverable per
`notes/project-instructions.md`.

## How to read this

Each item lists the control to put in place, which findings it directly
closes, and why it's prioritized where it is. "Closes" means the
specific technique documented stops working if this control is deployed
— it does not mean every finding's *entry point* disappears (several
chains have independent entry points that also need their own fix,
listed separately below).

## Priority 1 — structural controls (fix once, close multiple findings)

### Deploy Microsoft LAPS (or equivalent) domain-wide
Randomizes and rotates every host's local Administrator password
independently. Directly closes:
- [Baton Passer](baton_passer/baton_passer_tech.md) — pass-the-hash
  reuse of a shared local Administrator password across ARGOS → ANUBIS.

Without LAPS, any single host's local-admin compromise (by any means)
remains a standing lateral-movement risk, independent of how that first
host was reached.

### Technically enforce password rotation, don't rely on policy text
Force a password change on next logon and actually lock accounts that
miss the deadline, rather than a written-only policy. Directly closes
the base condition behind:
- [Instructions Unclear](instructions_unclear/instructions_unclear_tech.md) —
  `d.folt` never rotated the onboarding default.
- [Catastrophic Failure](catastrophic_failure/catastrophic_failure_tech.md) —
  same onboarding default, `a.nozer` never rotated it either, cascading
  into LSA-secrets exposure on ARGOS.
- Indirectly, [Baton Passer](baton_passer/baton_passer_tech.md) and
  [Shadowy Technique](shadowy_technique/shadowy_technique_tech.md),
  both of which chain from the same `a.nozer` foothold.

### Eliminate credentials stored outside a secrets manager
Three independent, unrelated storage locations leaked real passwords in
this engagement — a pattern, not a one-off:
- A plaintext memo on a public SMB share → [Instructions Unclear](instructions_unclear/instructions_unclear_tech.md).
- GPP `cpassword` in a SYSVOL `Groups.xml` left over from a deprecated
  feature → [Reversable Encryption](reversable_encryption/reversable_encryption_tech.md).
- Plaintext passwords in two accounts' AD `description` attributes →
  [A Verbose Description](a_verbose_description/a_verbose_description_tech.md).

A single recurring audit (scan SYSVOL for `cpassword`, scan every AD
free-text attribute for password-shaped strings, review any share
readable org-wide for credential content) would have caught all three
independently of which specific storage mechanism was used.

### Domain-wide ACL audit — explicitly including computer-sourced ACEs
Every DACL-abuse finding in this engagement was found only because a
sweep looked for a *specific* dangerous ACE type or principal type that
no prior sweep had checked:
- [Service Changer](service_changer/service_changer_tech.md) —
  `WriteSPN` held by a user.
- [Shadowy Technique](shadowy_technique/shadowy_technique_tech.md) —
  `AddKeyCredentialLink` held by a user.
- [That's Not My Password](thats_not_my_password/thats_not_my_password_tech.md) —
  `ForceChangePassword` held by a user.
- [Rise of the Machines](rise_of_the_machines/rise_of_the_machines_tech.md) —
  `WriteOwner` held by a **computer** account, invisible to every sweep
  that implicitly assumed only users hold dangerous ACEs.

A recurring, exhaustive sweep — every dangerous ACE type
(`GenericAll`/`GenericWrite`/`WriteDacl`/`WriteOwner`/`ForceChangePassword`/
`WriteSPN`/`AddKeyCredentialLink`/`AddMember`/etc.), held by *any*
principal type (user **and** computer **and** group-nested) — is the
single control that would have surfaced all four of these findings at
once, rather than one at a time across months of incremental, deeper
sweeps.

### Review and decommission unused groups holding live permissions
`COFFEE_USERS` had zero members but still held `WriteSPN` over three
accounts, and was independently writable-ownership by a computer
account — the entry point for both
[Service Changer](service_changer/service_changer_tech.md) (via
`g.clooney`'s own SPN, not this group) and the inherited-rights half of
[Rise of the Machines](rise_of_the_machines/rise_of_the_machines_tech.md).
An empty group is not a harmless group; its permissions remain fully
live until explicitly removed.

## Priority 2 — detection (shared across findings)

A single centralized detection program covering these event types would
catch most techniques demonstrated in this engagement as they happen,
not just after the fact:

| Event ID | Signature | Catches |
|---|---|---|
| `4769` + RC4 encryption | Kerberoasting | Dangerous Services, Service Changer, Rise of the Machines |
| `4768` + no pre-auth | AS-REP Roasting | No Preauth Needed |
| `4662` + `WriteOwner`/`WriteDacl` on a group, from a computer principal | ACL takeover | Rise of the Machines |
| `5136` on `servicePrincipalName` | Targeted SPN write | Service Changer |
| `5136` on `msDS-KeyCredentialLink` | Shadow Credentials | Shadowy Technique |
| `4724` with an unexpected Subject | Forced password reset | That's Not My Password |
| `4624`/`4625` volume across many accounts, same password, short window | Password spraying | Instructions Unclear, Catastrophic Failure |
| `4624` Logon Type 3 + NTLM, same account across many hosts | Pass-the-hash | Baton Passer |

## Priority 3 — per-finding fixes with no cross-cutting overlap

These close a single finding's own entry point and don't double up with
anything above:

- **Rotate every credential recovered during this engagement** —
  `g.clooney`, `j.vabre`, `p.origan`, `b.pitt`, `d.toh`, `k.cheh`,
  `r.singh`, `k.cedepte`, `d.scrip`, `a.nozer` — all appear in
  `scripts/spray-all.sh` and should be treated as fully compromised.
- **Enable Kerberos pre-authentication** on `j.vabre` specifically (see
  [No Preauth Needed](no_preauth_needed/no_preauth_needed_tech.md)).
- **Never configure Windows AutoLogon** on a domain-joined host (see
  [Catastrophic Failure](catastrophic_failure/catastrophic_failure_tech.md)).
- **Enforce AES-only Kerberos encryption** (disable RC4) where domain
  functional level permits — removes the fast-crackable `$krb5tgs$23$`
  format used throughout the Kerberoasting findings.

## Scope note

This roadmap covers the 10 challenges solved and written up as of
2026-10-25, plus [A Verbose Description](a_verbose_description/a_verbose_description_tech.md).
[Divine French Fries](../challenges/divine-french-fries.md) remains
unsolved and is not reflected here.
