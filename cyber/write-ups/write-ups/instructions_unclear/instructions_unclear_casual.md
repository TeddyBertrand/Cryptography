# The case of the memo nobody acted on

*A plain-English summary of the "Instructions Unclear" finding — no jargon
required.*

## What happened, in one sentence

A company-wide announcement telling new employees "change your starter
password within five days" was itself sitting in a folder anyone could read
without logging in — and at least one employee never actually changed it,
which was enough to get an administrator-level foothold on their work
laptop.

## The setup

Most companies have some kind of shared drive or folder everyone in the
organization can browse — HR documents, IT notices, that sort of thing. We
found one here too: a "public" folder readable by any employee, no
credentials required.

Sitting in it was a single file: an onboarding memo. It told new hires their
starter account password was a specific value, and that they had five
business days to change it before the account would be locked. Reasonable
policy, on paper.

The problem is twofold:
1. **The memo itself was sitting somewhere anyone could casually read it** —
   including us, before we had any real foothold in the network at all.
2. **At least one employee never actually changed it.** The "five day"
   instruction wasn't technically enforced — nothing actually locked the
   account when the deadline passed, it was just a request.

## What we actually did

1. Browsed the public company share and found the memo.
2. Read it — found the starter password spelled out in plain text.
3. Tried that password against every employee account we could enumerate
   (around 90 of them).
4. Two accounts still accepted it — meaning those two people had simply
   never gotten around to changing their password.
5. Checked where those two accounts actually had any power — not by looking
   at their official job titles or group memberships (neither looked special
   on paper), but by directly testing access against every company laptop
   and server.
6. One of them turned out to have full administrator rights on a specific
   laptop. We logged in and found a flag file waiting — confirming full
   compromise of that machine, achievable from nothing more than "an
   employee didn't change a password they were told to."

![Checking access across every laptop and server for both still-on-default accounts](assets/01-spray-all-dfolt.png)

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The real flag, found on the second account's desktop](assets/06-flag-retrieved.png)

</details>

Along the way we also found a red herring: the *other* still-on-default
account had a decoy file on its desktop joking "your flag is in another
castle" — a genuine, if cheeky, nudge pointing us toward the real account

![The decoy message found on the first (wrong) account's desktop](assets/04-anozer-decoy-flag.png)
instead.

## Why this is dangerous

- **Policy on paper isn't security.** Telling someone to change their
  password "within 5 days" does nothing if there's no technical check behind
  it. A human reading an instruction and ignoring it is exactly as
  predictable as this scenario assumes.
- **A shared starter password is a single point of failure.** It only takes
  one person skipping the change for that password to become a standing key
  that works against the whole organization, not just their own account.
- **"Just an employee account" can still be worth a lot.** Neither
  compromised account had any special title or group membership — but one of
  them was a genuine administrator on a specific laptop, and that fact simply
  wasn't visible anywhere in the company's own directory listings. It only
  showed up by actually testing access directly.
- **The leak itself required zero special access.** We didn't need to hack
  anything to read the memo — it was sitting on a share open to the entire
  company by design.

## What should be fixed

- **Enforce password changes technically, not just by instruction.** If a
  policy says "change this within 5 days," the system should actually block
  the account (or force a change on next login) rather than relying on the
  employee to act.
- **Never put a real, currently-valid password in a shared document**,
  plaintext or otherwise — use a one-time, auto-expiring link or a
  password-manager-based onboarding flow instead.
- **Restrict "public" shares to genuinely non-sensitive material.** If a
  document references credentials at all, it shouldn't live somewhere
  readable by the whole company by default.
- **Periodically audit for accounts still on default/initial passwords** —
  this is a simple, automatable check that would have caught this
  immediately without needing an external tester to find it.

## Bottom line

A password policy that exists only as a memo, combined with a memo that
leaked the password it was warning people to change, let us walk straight
into administrator access on a company laptop with no technical exploit at
all — just following a trail of things that were supposed to happen but
didn't. This is one of the cheapest classes of weakness to fix, and one of
the most common in the real world.
