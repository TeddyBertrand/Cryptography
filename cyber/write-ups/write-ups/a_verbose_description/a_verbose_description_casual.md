# The case of the password in the job-title field

*A plain-English summary of the "A Verbose Description" finding — no
jargon required.*

## What happened, in one sentence

Two employee accounts had their actual passwords typed directly into a
field meant for a short note about the account — a field any logged-in
employee can read — and one of those leaked passwords turned out to open
full administrator access to a company server.

## The setup

Every account in a company directory has a few free-text fields attached
to it — things like a short description or notes field, usually used for
something harmless like "Backup account for X" or "IT helpdesk testing."
These fields are, by design, readable by any employee who's logged in —
they're meant to be low-stakes, informational, nothing sensitive.

We found two accounts where someone — almost certainly whoever set the
account up — had typed the account's actual password directly into that
notes field instead. Not a hint, not a reminder, the literal working
password, sitting in plain text, visible to anyone who looked.

## What we actually did

1. Pulled a list of every account in the company directory, including
   their notes/description fields.
2. Found two accounts whose "notes" field was, word for word, a real
   password.
3. Tried both passwords against their respective accounts — both worked
   immediately.
4. Checked what each account could actually access — not by trusting
   their job title or group membership, but by testing them directly
   against every company computer and service.

![Checking one account against every machine on the network — full admin access turned up on one specific server](assets/02-spray-all-dscrip.png)

5. One of the two accounts turned out to have full administrator access
   on a specific server. (The other account checked out as a dead end —
   valid login, but no real access anywhere.)

![The other leaked account, checked the same way: a real login, but no meaningful access anywhere](assets/03-spray-all-kcedepte-deadend.png)

6. Logged into that server and found a flag file directly on the
   account's desktop, confirming full compromise.

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, found directly on the account's own desktop](assets/06-flag-retrieved.png)

</details>

## Why this is dangerous

- **A "notes" field is not a secure place for anything.** It exists
  specifically to be casually readable — treating it as a safe place to
  park a password defeats the purpose of having a password at all.
- **No privilege is needed to find it.** Any single authenticated
  employee account can read every other account's description field —
  this isn't a special admin-only view.
- **It bypasses the usual checks entirely.** Password strength doesn't
  matter here — it doesn't matter how complex the password is if it's
  just sitting in plain text somewhere people can read it directly.
- **One of two leaked accounts was a dead end, one wasn't — and you
  can't tell which from the directory alone.** Both accounts looked
  identical on paper (no special group membership, no listed
  permissions). Only directly testing access against every system
  revealed which one actually mattered.

## What should be fixed

- **Never store a password — or anything resembling one — in a notes,
  description, or comment field on an account.** These fields should be
  treated as public within the organization.
- **Routinely scan the directory for this exact pattern.** It's a
  well-known, easily automated check — any password-strength-looking
  string sitting in a notes field is worth flagging immediately.
- **Rotate both leaked passwords** and review whether either account is
  still actually needed.
- **Audit real access for every account directly, not just on paper.**
  As with several other findings, directory listings alone didn't show
  which account actually had meaningful access — only live testing did.

## Bottom line

A password typed into the wrong field — one explicitly meant to be
casually readable by anyone — was enough to eventually hand over full
administrator access to a company server. This is one of the simplest,
most avoidable mistakes in this entire set of findings, and also one of
the easiest to find once you know to look for it.
