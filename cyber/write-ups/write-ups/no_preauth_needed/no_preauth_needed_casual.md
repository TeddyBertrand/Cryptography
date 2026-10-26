# The case of the account that skipped the ID check

*A plain-English summary of the "No Preauth Needed" finding — no jargon required.*

## What happened, in one sentence

We found a staff account that could be impersonated well enough to steal its
password **without ever typing a single guess at a login screen**, because a
security setting that's normally on by default had been switched off for
that one account — and the stolen password turned out to open full
administrative access to a company server, again.

## The setup

In our earlier finding (["The case of the 'juicy' service
account"](../dangerous_services/dangerous_services_casual.md)), the network's
identity-checking system ("Kerberos") only handed over crackable data for
accounts that had a particular optional feature switched on (a "service
tag"). This finding is the same underlying weakness, through a different
door.

Normally, before the network hands anyone a "temporary pass" (a ticket) for
an account, it requires proof you actually know that account's password —
a first-round ID check. This finding was possible because that first-round
ID check had been **explicitly disabled** on one account (`j.vabre`). With
it off, anyone can simply ask "give me a temporary pass for `j.vabre`" and
receive one back immediately — no password needed to ask the question.

The catch: that temporary pass is itself scrambled using data derived from
`j.vabre`'s real password. So even though we never had to prove we knew the
password to get the pass, we can still take that scrambled pass away and try
to crack it open offline.

## What we actually did

1. Asked the network for a temporary pass for `j.vabre`, specifically
   because `j.vabre`'s account had its ID-check requirement switched off —
   no credential needed for this step at all.
2. Took the scrambled pass away and ran it through password-cracking
   software against a common password list.
3. It cracked quickly to `Coffee4me!`.
4. Confirmed the password actually worked by logging into the domain
   controller with it.
5. Checked that password against every server and protocol in the
   environment, not just the obvious ones — found it worked broadly, and
   granted full administrative access on the same company server ("SIRIUS")
   as our other findings.
6. Logged in and found a flag file directly on the account's desktop,
   confirming full compromise.

![Cracking the pass that required no password to obtain, recovered in under a minute](assets/02-hashcat-crack.png)

![That password checked across every server — full admin access found, again](assets/04-spray-all-summary.png)

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, retrieved directly from the account's own desktop](assets/06-flag-retrieved.png)

</details>

Along the way, we also spotted an interesting dead end: BloodHound showed
`j.vabre` might belong to a group with some extra permissions
(`COFFEE_USERS`), which in turn could write service tags onto a chain of
other accounts. We couldn't actually prove `j.vabre` was a member of that
group, though, so that particular lead stayed unconfirmed and wasn't needed
to get the flag.

## Why this is dangerous

- **It requires zero credentials to even attempt.** Unlike a normal password
  guess, requesting this pass needs no login information at all for the
  target account — just knowing the account's name.
- **It's invisible to login monitoring.** Because no password was ever
  submitted, there's no "wrong password" event, no lockout, nothing for
  standard alerting to catch.
- **One disabled setting undoes the whole protection.** The ID-check
  requirement exists specifically to prevent this. An account with it
  switched off is exposed by that single toggle, regardless of anything
  else about the account.
- **It compounds with weak passwords, same as before.** The exposure gets
  you a scrambled credential; a weak password is what actually turns that
  into a usable login. Fix either half and this specific chain breaks.

## What should be fixed

- **Re-enable mandatory pre-authentication** on every account unless there's
  a specific, documented reason it's off (some legacy systems need it off,
  but it should never be a default or an accident).
- **Audit the domain for any other accounts with this setting disabled** —
  this is a single directory attribute check, trivial to sweep for.
- **Use long, random passwords on every account**, so that even if a pass is
  obtained this way, cracking it offline is computationally impractical.
- **Monitor for AS-REQ requests with no pre-authentication data** — this is
  a distinctive, loggable pattern that's different from normal logins and is
  a strong early-warning signal on its own.

## Bottom line

A single security toggle, switched off on one account, let us obtain a
crackable credential with no login attempt at all — and a weak password on
that account turned it into full administrative access to a server, the same
outcome as our other findings but reached through a completely different,
even quieter door. This is a cheap, well-known fix: pre-authentication
should be on everywhere, and it almost never has a good reason to be off.
