# The case of the "encrypted" password that wasn't

*A plain-English summary of the "Reversable Encryption" finding — no jargon
required.*

## What happened, in one sentence

A company account's password was stored "encrypted" in a system-wide
configuration file — except the encryption used a publicly known key, so
scrambled or not, anyone could unscramble it in seconds, and that one
password eventually unlocked administrator access to a company laptop.

## The setup

Companies running Windows networks often push out standardized settings to
every computer automatically — things like "create this local account" or
"map this network drive." Microsoft built a feature for exactly this years
ago, and it included the ability to push out a username and password as part
of those settings (for example, to auto-create a local account on every
machine).

To avoid storing that password in plain, readable text, Microsoft
"encrypted" it. The catch — and this became a famous, widely-publicized
security failure — is that the encryption key was accidentally published in
Microsoft's own developer documentation. Once that happened, the
"encryption" provided effectively zero protection: anyone who finds one of
these settings files can decrypt the password with a single, publicly
available command. Microsoft patched the feature itself years ago so it
can no longer be used to push new passwords this way, but any *existing*
settings file created before the fix still has the old, crackable
scrambled password sitting in it, and nothing automatically removes those
leftover files.

We found exactly one of these leftover files sitting in this network's
central configuration store — containing a password for an account
labeled "Legacy backup account."

## What we actually did

1. Browsed the central configuration store (readable by any valid account
   on the network) and found the leftover settings file.
2. Fed the scrambled password it contained through the standard, public
   decryption tool — took seconds, no cracking or guessing involved, since
   it isn't really "encrypted" in any meaningful sense.

![The "encrypted" password decrypted in under a second with a public, well-known tool](assets/01-gpp-decrypt.png)

3. Got a real, working password for an account called `r.singh`.
4. Checked what that account could actually do. On paper, almost nothing —
   it wasn't part of any special group, had no listed permissions beyond
   basic access, and automated mapping tools reported it as a dead end.
5. Rather than trust that automated report at face value, we manually
   tested the account against every single computer on the network one by
   one — and found it quietly had remote access rights on one specific
   machine that the automated tool had failed to report correctly (that
   machine's trust relationship with the network was broken in a way that
   made the automated scan silently skip it).
6. Logged into that machine remotely and found a flag file waiting on the
   account's desktop, confirming full compromise.

![Checking every machine by hand — found on the one the automated scan had missed](assets/04-winrm-sweep-procyon-hit.png)

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, found on the account's own desktop](assets/08-flag-retrieved.png)

</details>

## Why this is dangerous

- **"Encrypted" doesn't always mean protected.** This is a textbook example
  of encryption providing a false sense of security — the mechanism looks
  secure on the surface, but the key being public makes it no better than
  storing the password in plain text.
- **Old settings files don't expire on their own.** Even though Microsoft
  fixed the underlying feature years ago, this leftover file kept the
  crackable password sitting there indefinitely, with nobody noticing or
  cleaning it up.
- **Automated tools can have blind spots.** The mapping tool we used to
  check the account's permissions reported a clean dead end — but it had
  silently failed to fully scan one machine due to an unrelated network
  issue, and that's exactly where the real access was hiding. Trusting the
  automated report alone would have meant missing this entirely.
- **A "legacy" account with no obvious permissions still had real power.**
  Nothing about this account looked dangerous on paper — the actual risk
  only became visible by testing it directly against every machine.

## What should be fixed

- **Find and remove every leftover Group Policy Preferences settings file**
  containing a `cpassword` value — this is a well-known, easily-scanned-for
  indicator (tools like PowerSploit's `Get-GPPPassword` or `netexec`'s GPP
  module exist specifically for this).
- **Never push credentials through Group Policy Preferences again** — use a
  dedicated secrets-management or Local Administrator Password Solution
  (LAPS) approach instead.
- **Rotate any account whose password may have been exposed this way**,
  immediately and as a standard incident-response step whenever this kind
  of file is found.
- **Don't rely solely on automated access-mapping tools** for permission
  audits — verify critical findings (especially "this account has no
  access anywhere") with direct testing, particularly on any system known
  to have connectivity or trust issues that could cause silent scan
  failures.

## Bottom line

A years-old, publicly known Windows weakness (a password "encrypted" with a
key anyone can look up) left a real, working credential sitting in a
central configuration file — and that credential, which looked completely
powerless on paper, turned out to have real remote access on one machine
that an automated scan had quietly missed. This is a cheap, well-documented
fix: scan for and remove these files, and never trust a "no access found"
result without checking it by hand on anything with known network quirks.
