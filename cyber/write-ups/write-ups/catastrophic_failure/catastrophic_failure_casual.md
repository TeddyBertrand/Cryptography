# The case of the forgotten auto-login password

*A plain-English summary of the "Catastrophic Failure" finding — no jargon
required.*

## What happened, in one sentence

A single company laptop had been quietly configured, at some point, to log
itself in automatically on startup — and the password used for that
convenience feature was still sitting on the machine in a recoverable form,
findable by anyone who managed to get administrator access to that one
computer.

## The setup

This finding is really a chain of small, individually-forgivable slip-ups
that added up to something serious:

1. **Every new employee gets the same starter password.** The company's IT
   onboarding process issues a shared, temporary password to new accounts,
   with instructions to change it within five business days. That password
   itself was sitting in a memo on a company-wide shared drive that anyone
   could read without logging in first.
2. **Not everyone changed it.** We found at least one account that was still
   using that starter password well past the five-day window.
3. **That account turned out to be an administrator on one specific laptop.**
   Not because of any official "this person is an IT admin" designation —
   just a local setting on that one machine that nobody ever reviewed or
   undid.
4. **That laptop had been set up to auto-login.** Windows has a legitimate
   feature for this (skip typing a password at the lock screen on boot) —
   but to make it work, it has to store that password somewhere the
   operating system can read it before anyone has logged in. That storage
   location is technically protected, but **any administrator on that
   machine can read it**, which is exactly what our compromised account was.

## What we actually did

1. Read a public, no-login-required file share and found the leaked starter
   password in an onboarding memo.
2. Tried that password against every known employee account — found two
   that still had it, including `a.nozer`.
3. Checked where that account actually had power, rather than assuming its
   lack of listed permissions meant it was harmless — and found it was a
   genuine administrator on one laptop, `ARGOS`.
4. Used that admin access to pull a protected part of the machine's
   internal storage — not just the usual "list of local passwords" admins
   usually go after, but a deeper, more sensitive vault the operating
   system itself uses.
5. Found the laptop's forgotten auto-login password sitting in that vault,
   in a form that could be read back out directly — and that password was
   the flag.

![Confirming the compromised account was a genuine administrator on the laptop](assets/02-netexec-argos-admin.png)

<details><summary>What the deeper secret vault looked like, flag and all (click to reveal)</summary>

![The full secret dump, including the forgotten auto-login password](assets/03-netexec-sam-lsa-dump.png)

</details>

## Why this is dangerous

- **Small mistakes compound.** No single step here was catastrophic on its
  own — a shared onboarding password, one person not changing it, one local
  admin grant nobody cleaned up, one convenience feature nobody turned off.
  Together, they add up to full exposure of a machine's most sensitive
  internal secrets.
- **"Local administrator" is often treated as low-stakes.** Being an admin
  on just one laptop sounds minor compared to being a domain-wide admin —
  but it's enough to unlock an entire protected vault on that machine,
  including that machine's own network identity credentials.
- **Convenience features leave permanent residue.** Auto-login is meant to
  save a few seconds at boot. It leaves behind a recoverable password for
  as long as the feature stays enabled — effectively forever, until someone
  remembers to turn it off and clean up after it.
- **It's a textbook "administrator not listening" problem** — someone set
  this convenience feature up at some point, it did its job quietly, and
  nobody circled back to ask whether it was still a good idea.

## What should be fixed

- **Stop issuing a shared starter password to new accounts.** Use unique,
  randomly generated ones, or a process that actually blocks the account
  until the password is changed.
- **Don't publish anything containing a password anywhere broadly
  readable**, even internally.
- **Regularly review who has local administrator rights on every machine**
  — not just who's in the official IT admin group — and remove access that
  nobody can justify anymore.
- **Never use Windows auto-login on a company machine.** If a login screen
  is genuinely too inconvenient for a specific use case, there are secure,
  purpose-built alternatives that don't leave a readable password behind.
- **Treat "deeper" credential stores, not just the obvious ones, as
  sensitive** — a protective audit should check everywhere a password could
  realistically be stashed, not just the first, most familiar place.

## Bottom line

No single step in this chain was a dramatic hack — it was a sequence of
ordinary, easy-to-overlook lapses that, together, exposed a forgotten
password sitting on one laptop. This is a very common real-world pattern:
the biggest risks often aren't one big flashy vulnerability, they're a few
small unaddressed ones stacked on top of each other.
