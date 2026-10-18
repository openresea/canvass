# Security model

This app handles resident information and survey responses. Automated checks are useful evidence, not an independent security audit or a guarantee that a deployment is secure.

## Email authentication

Email sign-in proves access to a mailbox. It is vulnerable to mailbox compromise and phishing, and is not MFA. For deployments holding sensitive responses, protect administrator access with an additional passkey/MFA-capable access gateway until app-native stronger authentication is available. Email alone does not satisfy NIST's out-of-band authenticator requirements: [NIST guidance](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/).

Codes use cryptographic randomness, expire after ten minutes, and are consumed atomically. Five wrong attempts consume a challenge. Only an HMAC digest bound to the challenge, email and login purpose is stored; keep `EMAIL_CODE_SECRET` outside the database and source control. Resending invalidates earlier codes. Admin and canvasser challenges use separate tables, and the canvasser database role cannot read admin codes.

PostgreSQL-backed limits apply across app instances: three emails per address per 15 minutes, at least 60 seconds between requests, 20 per IP per 15 minutes, 200 per service per hour, and 60 verification attempts per IP per 15 minutes. Limits include ineligible requests. Shared NATs can hit these limits; adjust deliberately after considering abuse. Configure edge throttling for overall traffic and login/route-code attempts. The app does not trust arbitrary forwarded IP headers.

SMTP requires TLS with certificate validation. Delivery runs after the HTTP response so SMTP timing does not reveal approved admin accounts. Delivery failures produce a generic server log without codes, credentials, or addresses. There is no durable mail queue or automatic delivery retry; the user can request another code after the cooldown. Codes never appear in API responses or app logs. The response for unknown admin accounts is identical to that for eligible accounts. Anyone may request a canvasser email code, but it grants no route access without a valid route code.

Code handling follows the single-use, expiry, throttling and neutral-response principles in the [OWASP verification guidance](https://cheatsheetseries.owasp.org/cheatsheets/Email_Validation_and_Verification_Cheat_Sheet.html).

## Access and deployment

- Serve HTTPS only outside localhost. Cookies are Secure, HttpOnly and SameSite=Lax. Use separate admin/canvasser hostnames. Sessions expire after twelve hours; admin approval is checked on every request. Deleting a user revokes their admin access. Logging out deletes the current session.
- Set exact `ALLOWED_HOSTS`. Keep database ports private. Put the admin service behind a restricted access gateway, especially when collecting sensitive answers.
- Configure Uvicorn's `--forwarded-allow-ips` to trust only your actual reverse proxy. TLS-terminating proxies must pass the correct scheme for same-origin write checks. Never trust `*` on an externally reachable server.
- Writes require an exact same-origin Origin or Referer. Browser CSP allows only app scripts with a nonce or same-origin assets, disallows external frames, and forbids embedding this app. Private responses are not cached.
- Survey changes require GLOBAL_ADMIN. Region/area roles and exports remain scoped. Canvasser sessions are route-bound and checked against the original route code's active/expiry state on every request.
- The answers writer is INSERT-only. The export role is SELECT-only. The public service receives no export credentials or code-decryption key. Database role checks do not replace app-level route checks.
- Configure backups, encrypted storage, secret rotation and a retention policy. The responses and operational receipt logs contain personal information; receipts are not anonymous. Use authorised owner-level maintenance for retention. The app does not implement a retention scheduler or field-level response encryption.
- Operational receipts and response data live in separate databases. Retries use a payload hash and a unique submission ID, and recover a failed status update. There is no distributed transaction; monitor failed receipt events and reconcile interrupted writes. An old survey version must be reviewed before a new submission.
- The local PostgreSQL container uses a private network. For databases across a network boundary use certificate-verified TLS (`*_SSLMODE=verify-full`) and an appropriate CA.

## Maintenance

Run dependency audits and patch regularly. Keep `.env`, exported CSVs, database dumps, mail credentials, route codes and real resident data out of commits. Do not log request bodies or cookies at the proxy. Do not put resident data or active credentials in public issues.

As a privileged scheduled maintenance job, remove expired admin/canvasser sessions, email challenges older than one day, and `email_auth_limits` whose `resets_at` is older than one day. This avoids indefinite retention of authentication metadata. Do not grant the public runtime broader privileges to perform maintenance.

## Reporting

Report vulnerabilities privately to [resea@tuta.io](mailto:resea@tuta.io). Include the affected version, reproduction steps using fictional data, and the expected impact. Never include live resident data, credentials, route codes, or sign-in codes. For an incident affecting a particular installation, also contact its deployment owner.
