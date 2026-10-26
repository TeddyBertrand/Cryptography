# The case of the laptop that could edit company groups

*A plain-English summary of the "Rise of the Machines" finding — no jargon
required.*

## What happened, in one sentence

A laptop's own built-in network identity — not any human employee's login,
but the identity the computer itself uses to talk to the network — turned
out to have the power to edit a company security group, and we rode that
all the way to a fourth compromised employee account through a chain of
five separate steps.

## The setup

Every computer joined to a company network has its own hidden account,
separate from any human user — think of it as the computer's own employee
badge, which it uses to prove its identity to the network automatically,
without a person typing anything. Normally nobody thinks about what *that*
account can do, because it's not meant to be a security-relevant identity
at all — it's plumbing.

In an earlier finding, we'd already gotten administrator access to one
laptop and, while poking around its internal secret storage, accidentally
picked up that laptop's own hidden network account credential along with
everything else. At the time we didn't think much of it — but it turned
out that laptop's own identity had been granted a special permission over
a company security group: the ability to **take ownership** of that group.

Taking ownership of something in this type of system is a bit like being
handed the deed to a building — even if you don't have a key to any
specific door yet, owning the building lets you give yourself one. We used
the laptop's own identity to make itself the "owner" of the group, which
then let it freely rewrite who was allowed to do what with that group —
including adding a human employee account as a member.

That group, it turned out, already had a legitimate-but-forgotten
permission of its own: the ability to assign a technical "service tag" to
three other employee accounts (the same kind of tag used in an earlier
finding to steal a password via Kerberos ticket-cracking). Once our
employee account joined the group, it inherited that permission — and we
used it on the one target account from that trio nobody had touched yet.

## What we actually did

1. Reused a laptop's own hidden network credential (captured incidentally
   during an earlier investigation) to connect as the laptop itself,
   rather than as any human user.
2. Found that laptop's identity could take ownership of a particular
   company security group.
3. Took ownership of that group using the laptop's identity — our first
   attempt tried handing ownership straight to a human account, which was
   correctly refused by the system (a real, built-in security rule: you
   can only hand yourself ownership directly, not pass it to someone
   else, without an even higher special privilege) — so we took it for
   the laptop itself first.

![The system correctly refusing a direct hand-off of ownership to someone else](assets/06-owneredit-rejected.png)

4. As the new owner, rewrote the group's permissions to let a human
   employee account add members to it.
5. Added that employee account into the group — which meant it now
   automatically inherited every permission the group itself already had.

![Checking the group's membership — along the way we also found two accounts in there nobody could explain](assets/09-group-membership.png)

6. One of those inherited permissions let us assign a Kerberos service tag
   to a previously-untouched employee account, then steal and crack that
   account's password the same way as an earlier finding.
7. Checked where that newly-cracked account had real access — found full
   administrator rights on a company server.
8. Logged in and found a flag file, confirming complete compromise,
   reached entirely through a chain that started from a computer's own
   identity rather than any person's.

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag, found on the hijacked account's own desktop](assets/14-flag-retrieved.png)

</details>

## Why this is dangerous

- **Computer accounts are security principals too.** It's easy to think
  of permissions and access only in terms of human employee accounts —
  but a device's own network identity can hold real, dangerous
  permissions that nobody thinks to review, precisely because nobody
  expects a laptop to "do" anything on its own.
- **"Ownership" is a backdoor around normal permissions.** Owning an
  object in this kind of system lets you rewrite its rules from scratch,
  even without an explicit permission grant for the specific thing you
  want to do — it's a broader, easier-to-overlook form of control than a
  direct permission.
- **Forgotten groups don't lose their power just because they're
  forgotten.** The group at the center of this chain had zero actual
  members and looked abandoned — but its underlying permissions over
  other accounts were still fully intact and exploitable the moment
  anyone (or anything) could get into it.
- **One compromised laptop cascaded into a fourth stolen account.** The
  entire chain started from a credential incidentally captured during an
  unrelated earlier investigation — a strong illustration of how
  thoroughly a single foothold needs to be investigated before it's
  considered "used up."

## What should be fixed

- **Review what permissions computer accounts hold, not just user
  accounts.** Security audits routinely check which employees can do
  what — they should check the same for every device's own network
  identity.
- **Remove or review any "ownership" or group-editing rights granted to a
  computer account** unless there's a specific, documented automation
  reason for it.
- **Clean up groups that no longer have an active purpose.** An empty
  group with real permissions still attached is a live risk, not a
  harmless leftover — either remove its permissions or delete it
  entirely.
- **Monitor for ownership changes and group-membership changes on
  sensitive objects** — both are unusual, infrequent events in a healthy
  environment and are strong signals of this exact kind of abuse when
  they do happen.

## Bottom line

A permission attached to a laptop's own identity — not any person's login
— let us take ownership of a company group, rewrite its rules, add
ourselves to it, and inherit a forgotten-but-still-active permission that
led to a fourth compromised account. This finding is a clear example of
why security reviews need to think about every kind of account that can
hold permissions in a system, not just the human ones.
