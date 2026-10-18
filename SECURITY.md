# Security and privacy

Resea Canvass holds people's names, addresses and what they told your volunteers, so it's worth taking a little care when you set it up. This page explains how the app protects that data and what's left for you to do. Our automated tests are useful evidence, but they aren't an independent security audit.

## What the app stores about people

Please be clear with your team, and with the people you canvass, about what's kept:

- **Residents.** Whatever you import (name, address, flat, elector number), plus each visit's outcome, survey answers and notes. Saved answers are linked to the resident and address. They are **not anonymous**.
- **Volunteers.** Their email address and the name they type in, attached to every visit they record.
- **Organisers.** Their email address, and who changed which survey question.
- **Sign-in data.** Email addresses waiting for a code, and sign-in sessions. Rate limits are stored under a keyed hash, so no IP addresses are kept in the database.

The app doesn't write web access logs, so volunteers' IP addresses and routes aren't recorded by default. Your reverse proxy may log them, so check its settings.

The app doesn't delete old data on its own. Decide how long you need it, then remove it on a schedule (see "Housekeeping" below).

## Signing in

Email codes prove that someone can read that inbox. That's convenient, but it isn't two-factor authentication, and anyone who gets into an organiser's email can sign in as them. If you're collecting sensitive answers, put the organiser side behind something with passkeys or 2FA, such as an identity-aware proxy. NIST explains why email alone isn't enough: [NIST guidance](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/).

How codes work:

- Codes are random, last ten minutes and work once. Asking for a new code cancels the old one.
- Five wrong guesses use up a code.
- Only a keyed hash of each code is stored. Keep `EMAIL_CODE_SECRET` out of the database and out of git.
- Organiser and volunteer codes live in separate tables, and the volunteer app can't read organiser codes.
- The response is the same whether or not an email belongs to an organiser, and emails are sent after the page responds, so nobody can work out who your organisers are.
- Codes never appear in web responses or logs. If sending fails, the log just says so, without codes or addresses.
- Anyone can ask for a volunteer code, but it's useless without a valid route code.

Limits are shared across all copies of the app: three emails per address every 15 minutes (at least a minute apart), 20 per IP address every 15 minutes, 200 per app per hour, and 60 sign-in attempts per IP address every 15 minutes. Volunteers behind the same office or mobile network share an IP limit, so adjust it if that causes trouble.

Route codes contain the route name, which means a sign-in attempt only ever checks that route's codes. That keeps each guess cheap for the server while staying slow and hopeless for an attacker. Codes are stored as bcrypt hashes. Only the organiser app holds the key that can show them again.

## Putting it online safely

- **Use HTTPS everywhere** except on your own computer. Sign-in cookies only work over HTTPS (or `localhost`).
- **Give the organiser and volunteer sides separate addresses**, and set `ALLOWED_HOSTS` to exactly those names.
- **Tell the app who your proxy is.** Set `FORWARDED_ALLOW_IPS` to your reverse proxy's address so rate limits see real visitors rather than the proxy. Never use `*` on a server the internet can reach.
- **Make sure your proxy passes the original scheme** (`https`), or the app will reject form submissions as cross-site.
- **Keep the database private.** If it's on another machine, use `*_SSLMODE=verify-full` with a trusted certificate.
- **Consider restricting the organiser side** to known people, for example behind a VPN or login gateway.

What the app already does for you:

- Cookies are `Secure`, `HttpOnly` and `SameSite=Lax`. Sessions last twelve hours. Signing out ends the session. Removing an organiser from `users` ends their access straight away.
- Every change must come from the app's own pages (matching `Origin` or `Referer`). Pages can't be embedded in other sites, scripts are locked down by a Content Security Policy, and private pages aren't cached.
- Volunteers can only see and record visits on the route their code is for, checked on every request.
- Only global organisers can change the survey. Regional and area organisers only see their own routes and exports.
- Each part of the app logs in to the database with only what it needs. The volunteer app can add answers but can't read them back. Exports are read-only. The volunteer app never gets the export login or the route-code key.

## Housekeeping

- Back up both databases, keep them on encrypted storage, and rotate passwords now and then.
- Run a scheduled job, using a database admin login (not the app's), to remove expired sessions, sign-in codes older than a day, and `email_auth_limits` rows whose `resets_at` is more than a day old.
- Remove survey answers and resident lists once you no longer need them.
- Keep `.env`, exported CSVs, database dumps, email passwords, route codes and real resident data out of git and out of public issues.
- Don't log request bodies or cookies at your proxy.
- Check dependencies regularly with `pip-audit` and keep them up to date.

## Reporting a problem

If you find a security issue, please email [resea@tuta.io](mailto:resea@tuta.io) privately rather than opening a public issue. Let us know the version, the steps to reproduce it using made-up data, and what you think the impact is. Please don't include real resident data, passwords, route codes or sign-in codes.

If the problem affects a particular installation, please tell whoever runs it too.
