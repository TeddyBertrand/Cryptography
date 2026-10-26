# The case of the "juicy" service account

*A plain-English summary of the "Dangerous Services" finding — no jargon required.*

## What happened, in one sentence

We found a staff account inside the company's network whose password could be
cracked just by *asking the network a normal, everyday question* — no hacking
tools pointed at a login screen, no alarms triggered, no lockouts — and that
cracked password gave us full remote control of one of the company's servers.

## The setup

Think of the company's internal network like a secure office building that uses
keycards. To get into any room, your keycard first has to be validated by the
front desk. That's roughly what "Kerberos" (the authentication system Windows
networks use) does: it hands out time-limited tickets that prove who you are
and what you're allowed to open.

Here's the catch we found: **you don't need permission to ask what a specific
door's lock looks like.** Any employee — even a brand-new, low-privilege one —
is allowed to request a copy of the "lock mechanism" for any service account in
the building, including ones they have no business accessing. That copy is
technically scrambled (encrypted), but it's scrambled using a key derived
directly from that account's own password.

If that account's password is weak, we can take the scrambled copy home,
run it through password-cracking software, and work out the real password —
all without ever touching the "front desk" again, which means there's nothing
suspicious for anyone watching the front desk logs to notice.

## What we actually did

1. Asked the network, as an ordinary logged-in user, "which service accounts
   exist that I can request a ticket for?" — this is a completely normal,
   permitted request.
2. Picked out an account called `g.clooney` that had this kind of service
   ticket available.
3. Requested that ticket and took it away to crack offline.
4. The password cracked in minutes using a common password list — it turned
   out to be a simple, guessable word-based password (`CoffeeMug!1`).
5. That password worked to log directly into one of the company's servers
   (nicknamed "SIRIUS") with full administrative rights.
6. On that server's desktop, we found a flag file proving full compromise —
   in a real incident, this would represent complete control of that machine
   and everything reachable from it.

No alarms. No failed-login lockouts. No "someone tried your password wrong 5
times" email. The entire password-stealing step happens offline, after the
network handed over the scrambled ticket completely legitimately.

![Cracking the stolen ticket recovered the account's real password in minutes](assets/02-hashcat-crack.png)

![That password opened full administrative access to the server](assets/03-netexec-winrm-admin.png)

<details><summary>What "full compromise" looked like on screen (click to reveal)</summary>

![The flag file sitting on the compromised server's desktop](assets/06-flag-retrieved.png)

</details>

## Why this is dangerous

- **It needs almost no starting privilege.** Any valid employee login — even
  the lowest-level one — can pull this off. We started with a basic account
  that had no special access at all.
- **It's quiet.** Because the attacker never tries to log in with the wrong
  password against the real system, there's nothing for standard security
  monitoring to flag.
- **It's a numbers game that favors the attacker.** Only *one* service account
  out of many needs a weak password for this to work. We also found a second,
  related weakness (an account with login verification switched off entirely)
  that was cracked the same way.
- **The blast radius is bigger than it looks.** The compromised account had no
  obviously dangerous permissions listed in the directory — yet it turned out
  to have full admin access to a real server, which nothing in a routine
  permissions review would have predicted without actively testing it.

## What should be fixed

- **Give service accounts long, random, non-dictionary passwords** (ideally
  25+ characters, generated and stored in a password vault, never typed or
  remembered by a human). A long random password makes offline cracking
  computationally pointless.
- **Rotate service account passwords regularly** and immediately after any
  suspected exposure.
- **Reduce the number of accounts that need this kind of ticket at all** —
  every account with this property is a potential weak point; fewer of them
  means less exposure.
- **Monitor for the request pattern itself**, not just failed logins — a
  single account requesting tickets for an unusual number of services in a
  short window is a strong early warning sign, even though no login was
  attempted.
- **Re-enable mandatory identity verification** on every account — we also
  found at least one account where this had been switched off, which is an
  even easier version of the same attack.

## Bottom line

A single weak password on an account nobody was watching closely turned into
full administrative access to a company server — achieved almost entirely
through legitimate, unlogged requests to the network itself. This is a very
common and well-understood weakness in Windows networks, and it is also one
of the cheapest to fix: strong, random, rotated passwords on service accounts
close this door almost completely.
