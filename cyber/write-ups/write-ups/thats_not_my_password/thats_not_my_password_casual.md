# The case of the permission nobody should have

*A plain-English summary of the "That's Not My Password" finding — no
jargon required.*

## What happened, in one sentence

One employee account had a quiet, narrow permission that let it reset a
completely different employee's password outright — no guessing, no
cracking, not even needing to know what the old password was — and we used
it to simply hand ourselves a brand-new password for someone else's
account.

## The setup

Most of our earlier findings involved stealing or cracking a password in
some way. This one is different, and in some ways simpler and more
alarming: we didn't need to crack anything at all.

We'd already found a working employee login through an earlier, unrelated
slip-up (a password accidentally left in a plain-text notes field on that
employee's company directory entry — the kind of field meant for a short
job description, not a password). Using that account, we checked what
permissions it actually had over *other* people's accounts in the company
directory.

It turned out this account had been granted a very specific, very powerful
right over one other, completely unrelated employee: **the ability to
reset that person's password directly**, without needing to know or
provide their current one. This is a legitimate feature that exists for
IT help-desk tools (so a support technician can reset a forgotten
password) — but it had been granted to an ordinary employee account that
had no business holding it.

## What we actually did

1. Checked what special permissions our already-compromised account had
   over other accounts in the company directory — not just what group it
   belonged to, but specifically what it was individually allowed to *do*
   to other accounts.
2. Found it could force-reset the password of a completely unrelated
   employee account.
3. Used that permission to set a brand-new password of our choosing on
   that account — no knowledge of their original password required at
   any point.

![The password reset succeeding instantly, with zero knowledge of the original password](assets/01-changepasswd-reset.png)

4. Logged in as that account with the new password.
5. Checked where that account actually had meaningful access — not by
   trusting its listed job title or group memberships, but by testing it
   directly against every company computer.

![Checking the newly-hijacked account against every machine on the network](assets/03-spray-all-summary.png)

6. Found it had full administrator rights on one specific machine, logged
   in, and found a flag file confirming complete compromise.

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, found on the hijacked account's own desktop](assets/05-flag-retrieved.png)

</details>

## Why this is dangerous

- **You don't need to crack anything.** This bypasses password strength
  entirely — it doesn't matter how strong the target's original password
  was, because we never needed it. One permission grant is all it takes.
- **It's a legitimate IT feature, misapplied.** Password-reset rights are
  a normal, necessary part of running a help desk. The danger here isn't
  the feature itself — it's that it was granted to an account with no
  actual help-desk role.
- **The victim finds out immediately, but too late.** Unlike some quieter
  techniques, resetting someone's password does lock them out — but by
  the time they notice and report it, the attacker has already used the
  new password to get in.
- **It chains off an earlier, seemingly minor leak.** The account that
  held this dangerous permission only became useful to us because of a
  separate, smaller mistake (a password sitting in a plain-text notes
  field). Neither mistake alone looks catastrophic — together, they add
  up to full account takeover of someone else entirely.

## What should be fixed

- **Audit every account for exactly which other accounts it can reset the
  password of**, and remove any grant that doesn't map to an actual,
  documented help-desk or support responsibility.
- **Never store a password in a plain notes/description field** — that
  field is visible to a far wider audience than the password fields
  themselves, and it isn't treated with the same security controls.
- **Monitor for password resets performed by an account other than the
  account holder or a recognized administrative tool** — a strong,
  specific signal this kind of permission is being misused.
- **Apply least-privilege review to delegated permissions, not just group
  membership** — this kind of narrow, individually-granted right is
  exactly the sort of thing a routine "who's in the admin group" review
  would never catch.

## Bottom line

A single, narrowly-scoped permission — the ability to reset one specific
other person's password — was all it took to fully take over an unrelated
account, with zero password-cracking involved. This is one of the
clearest illustrations of why access reviews need to check not just who's
powerful, but exactly what every account is individually permitted to do
to every other account.
