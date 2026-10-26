# Technique Glossary — HOUNDLABS.EPI

Consolidated index of every named technique/exploit used across the 11
solved challenges, for quick oral-defense reference. Each technical
write-up also carries its own `**Primary Technique(s):**` line near the
top, and a full MITRE ATT&CK mapping table in its Attack Chain section —
this file exists to see them all at once, cross-challenge.

## By challenge

| Challenge | Industry/technique name | AD-specific primitive | MITRE ATT&CK |
|---|---|---|---|
| [Dangerous Services](dangerous_services/dangerous_services_tech.md) | Kerberoasting | SPN-bearing account, TGS-REP crack | T1558.003 |
| [No Preauth Needed](no_preauth_needed/no_preauth_needed_tech.md) | AS-REP Roasting | `DONT_REQUIRE_PREAUTH` | T1558.004 |
| [Service Changer](service_changer/service_changer_tech.md) | Targeted Kerberoasting (via ACL abuse) | `WriteSPN` | T1558.003, T1098 |
| [Instructions Unclear](instructions_unclear/instructions_unclear_tech.md) | Credentials in Files + Password Spraying | — | T1552.001, T1110.003 |
| [Catastrophic Failure](catastrophic_failure/catastrophic_failure_tech.md) | LSA Secrets Dumping → AutoLogon credential exposure | SAM+SECURITY hive export | T1003.002, T1003.004, T1552.002 |
| [Baton Passer](baton_passer/baton_passer_tech.md) | Pass-the-Hash (local admin password reuse) | NTLM hash reuse across hosts | T1003.002, T1550.002, T1078.001 |
| [Shadowy Technique](shadowy_technique/shadowy_technique_tech.md) | Shadow Credentials (PKINIT cert-based takeover) | `AddKeyCredentialLink` / `msDS-KeyCredentialLink` | T1649, T1550.002 |
| [That's Not My Password](thats_not_my_password/thats_not_my_password_tech.md) | ForceChangePassword DACL abuse | `ForceChangePassword` extended right | T1098 |
| [Rise of the Machines](rise_of_the_machines/rise_of_the_machines_tech.md) | Computer-account `WriteOwner` abuse → inherited Kerberoasting | `WriteOwner` + `WriteDacl` + group `WriteSPN` inheritance | T1550.002, T1098, T1558.003 |
| [Reversable Encryption](reversable_encryption/reversable_encryption_tech.md) | GPP `cpassword` decryption | SYSVOL `Groups.xml`, static AES key | T1552.006 |
| [A Verbose Description](a_verbose_description/a_verbose_description_tech.md) | Credentials in (LDAP) attribute | AD `description` field | T1552.001 |

Every finding also chains through **T1078 Valid Accounts** (and usually
**T1021.006 Remote Services: WinRM**) once a credential is recovered —
the common "land" step across all 11, not unique to any single finding.

## AD-specific DACL/ACL primitives

Six distinct Active Directory access-control primitives appear across
the DACL-category findings — likely worth having cold for the oral
defense's "AD access control mechanisms" question:

- **`WriteOwner`** — lets the holder take ownership of an object
  (Rise of the Machines). Self-ownership only, unless the acting
  principal also holds `SeRestorePrivilege`.
- **`WriteDacl`** — lets the owner (or an explicit grantee) rewrite an
  object's DACL from scratch (Rise of the Machines, as the follow-on to
  `WriteOwner`).
- **`WriteSPN`** — lets the holder register an arbitrary SPN on the
  target, making it Kerberoastable on demand (Service Changer; inherited
  via group membership in Rise of the Machines).
- **`ForceChangePassword`** — the `User-Force-Change-Password` extended
  right; resets a target's password with no knowledge of the original
  (That's Not My Password).
- **`AddKeyCredentialLink`** — write access to `msDS-KeyCredentialLink`;
  the Shadow Credentials primitive (Shadowy Technique).
- **Group-membership ACE inheritance** — joining a group grants every
  ACE that group itself holds, without any ACE on the joining principal
  directly (Rise of the Machines — `WriteSPN` inherited via
  `COFFEE_USERS` membership).

## By MITRE ATT&CK tactic (Credential Access)

- **T1558.003 — Kerberoasting**: Dangerous Services, Service Changer,
  Rise of the Machines.
- **T1558.004 — AS-REP Roasting**: No Preauth Needed.
- **T1552.001 — Unsecured Credentials: Credentials In Files**:
  Instructions Unclear, A Verbose Description.
- **T1552.002 — Unsecured Credentials: Credentials in Registry**:
  Catastrophic Failure (AutoLogon).
- **T1552.006 — Unsecured Credentials: Group Policy Preferences**:
  Reversable Encryption.
- **T1003.002 — OS Credential Dumping: SAM**: Catastrophic Failure,
  Baton Passer.
- **T1003.004 — OS Credential Dumping: LSA Secrets**: Catastrophic
  Failure.
- **T1550.002 — Use Alternate Authentication Material: Pass the Hash**:
  Baton Passer, Shadowy Technique, Rise of the Machines.
- **T1649 — Steal or Forge Authentication Certificates**: Shadowy
  Technique (Shadow Credentials).
- **T1098 — Account Manipulation**: Service Changer, That's Not My
  Password, Rise of the Machines.
- **T1110.003 — Password Spraying**: Instructions Unclear.

See also: [Remediation Roadmap](remediation-roadmap.md) (fixes grouped
by which root cause closes multiple findings at once) and each
write-up's own "Attacker operational security" subsection (stealth/OPSEC
profile per technique — which ones are quiet, which are loud, and why).
