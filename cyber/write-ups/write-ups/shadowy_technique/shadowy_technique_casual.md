# The case of the invisible impersonation permission

*A plain-English summary of the "Shadowy Technique" finding — no jargon
required.*

## What happened, in one sentence

An ordinary employee account turned out to have a hidden permission that
let it **become** a completely different employee — not by stealing their
password, not by resetting it, but by quietly attaching a secret
"spare key" to that person's account that let us log in as them while
their real password kept working the whole time.

## The setup

Windows networks have a modern feature that lets people log in using a
certificate (like a smart card or a phone-based authenticator) instead of
typing a password. To support this, every account has a hidden field where
one or more of these "certificate keys" can be registered.

Here's the dangerous part: **whoever has permission to edit that hidden
field can add their own key to someone else's account**, without that
person's knowledge or consent, and without touching their password at all.
Once that key is added, the attacker can use it to log in as the victim via
the certificate-login mechanism — fully impersonating them — while the
victim's actual password keeps working completely normally, so they have
no reason to suspect anything happened.

We found that an ordinary, low-privilege employee account had exactly this
permission over a completely unrelated coworker's account. We only found
it because we specifically went looking for *every* account with *any*
kind of dangerous editing permission over *any* other account — a broader
sweep than just checking the accounts we already knew had power.

## What we actually did

1. Ran a broad scan across every account in the company directory, looking
   for any account that had been granted an unusual, powerful editing
   permission over another account — not just the ones we already had
   footholds on.
2. Found that one employee account could silently register a login key on
   a completely different coworker's account.
3. Used an automated tool to register a temporary key on the target
   account, then used that key to log in *as* the target — all without
   ever knowing or changing their real password.
4. Recovered the target account's underlying credential material this way,
   then had the tool clean up after itself, restoring the account to
   exactly how it looked before.

![The automated tool silently registering a key, logging in as the target, and recovering their credential material — then undoing its own tracks](assets/01-certipy-shadow-auto.png)

5. Took that recovered credential and tried it against every company
   computer — found it granted full administrator access on one specific
   machine.
6. Logged into that machine and found a flag file, confirming full
   compromise, achieved without ever resetting or even knowing the
   target's real password.

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, found on the impersonated account's own desktop](assets/05-flag-retrieved.png)

</details>

## Why this is dangerous

- **It's a real, legitimate feature turned against its own purpose.**
  Certificate-based login exists to make authentication more secure and
  convenient — the same mechanism that normally protects an account can be
  hijacked to silently clone access to it.
- **The victim never notices.** Unlike resetting someone's password (which
  immediately locks them out and gets noticed), this technique leaves the
  real password completely untouched. The victim keeps logging in
  normally, with no visible sign anything happened.
- **It's invisible unless you're specifically looking for it.** This
  permission doesn't show up as "this account is an administrator" or
  "this account is in a powerful group" — it only appears when you
  specifically check for this one particular type of editing right, which
  most routine security reviews don't think to check.
- **A completely ordinary account held this power.** There was nothing
  about the account that held this permission suggesting it should have
  any special reach at all — which is exactly why a broad, exhaustive
  sweep for this specific condition (rather than trusting a surface-level
  review) was necessary to find it.

## What should be fixed

- **Audit every account for who can edit the certificate-login field on
  other accounts.** This is a specific, scannable condition — tools exist
  purpose-built to check for it across an entire company directory.
- **This permission should only ever be held by dedicated IT/security
  service accounts** managing certificate enrollment — never by an
  ordinary employee account, under any circumstance.
- **Monitor for changes to that hidden field directly** — an unexpected
  key being added (and especially one being quickly removed again
  afterward) is a strong, specific signal this technique is in use.
- **Treat this permission with the same seriousness as a password-reset
  permission** — functionally, it grants the same level of account
  takeover, just without the side effect of locking the real user out.

## Bottom line

A permission that most routine security checks don't even think to look
for let one ordinary employee account silently become any other account it
had this hidden permission over — with zero impact on the real account
holder's own ability to keep logging in normally. This is a newer, quieter
cousin of more commonly known account-takeover techniques, and it only
gets caught by deliberately scanning for it, not by reviewing group
memberships or job titles.
