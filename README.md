# Resea Canvass

A self-hosted canvassing app for nonprofits, community groups, and campaigns. Import addresses, give volunteers access to a route, and record visits and survey answers on a phone or computer. Free for permitted nonprofit and other noncommercial use under the [PolyForm Noncommercial licence](LICENSE). Commercial use outside those permissions requires a separate agreement; see [commercial licensing](COMMERCIAL.md). You pay for your own hosting and email service.

See the [screenshots](docs/screenshots.md).

Source: [openresea/canvass](https://github.com/openresea/canvass). Commercial enquiries: [resea@tuta.io](mailto:resea@tuta.io).

## Features

- Sign in using an email address from any provider and a six-digit, single-use code.
- Canvassers need a valid route code as well as email verification. Revoking or expiring the route code also blocks sessions created with it.
- Approved admins import routes, issue/revoke route codes, and export scoped results.
- Global admins add, edit, reorder, remove, and restore questions. Types: written answer, choose one, and yes/no/not sure. Questions can be optional or required.
- The survey is shared across this deployment. Region/area admins cannot change it. Use separate deployments for independent organisations.
- Responses preserve question wording and choices. Stale forms are rejected for review; request IDs prevent duplicate responses on retries.
- Record a conversation, no answer, declined participation, or inaccessible address.

## Start locally

Requires Docker Compose and Python 3.9+ for the configuration helper. The app container uses Python 3.12.

1. Set up an SMTP account with a mail provider and verify its sender address. The app supports encrypted SMTP using STARTTLS (usually port 587) or implicit TLS (`SMTP_SECURITY=ssl`, usually port 465). It does not support unencrypted SMTP or log-in codes printed to a console.
2. Run `python3 scripts/configure.py`. Enter your admin email, sender address, and SMTP hostname. This creates `.env` with fresh random secrets and owner-only permissions; it never overwrites an existing file.
3. Edit `.env` to set `SMTP_USERNAME` and `SMTP_PASSWORD`. Quote values containing `$` or `#` with single quotes according to Compose dotenv syntax. Change SMTP port/security if needed.
4. Run `docker compose up --build`.
5. Open **http://localhost:8001** for admin and **http://localhost:8000/join** for canvassing. Use `localhost`, not a LAN IP. Session cookies are always Secure; browsers that do not permit Secure cookies on localhost require a local HTTPS reverse proxy.

For an existing installation using the old Compose project name, set `COMPOSE_PROJECT_NAME=open-canvass` in `.env` to keep using its database volume.

The database is internal to the Compose network, and web ports bind only to loopback. Production requires HTTPS, explicit hostnames and an appropriately configured reverse proxy; see [SECURITY.md](SECURITY.md).

Only the email in `ADMIN_EMAIL` receives initial admin access. This is used when the database volume is first created. Changing `.env` later does not change database users or passwords. Never delete a volume to change a setting on an installation containing real data.

### First route

1. Sign in to admin with your email code. Open **Manage survey questions** and add the questions you need.
2. Import [the fictional sample route](docs/sample-route.csv) using area `LOCAL_CENTRAL`. The initial installation creates this generic area; you can rename it in the database.
3. Share the generated route code with your team. They sign in using their own email addresses, enter the code, and choose an address to start.
4. Review and export the results from admin. Removed questions remain available to restore; past answers stay in exports.

Plain CSV headers: `street,house,postcode`. For prepared resident lists: `elector_id,street_name,building,flat_number,postcode,resident_name`. Import only data you are authorised to use. The repository includes fictional samples only.

## Run without Docker

Use Python 3.12+ and PostgreSQL 17. Install `requirements.txt` in a virtual environment. Create **new, empty** operations and answers databases; do not point this app at a previous deployment.

Apply these files as the database owner with `psql -v ON_ERROR_STOP=1 -d DATABASE -f FILE`:

| Operations database, in order | Answers database, in order |
| --- | --- |
| `app/sql/ops_schema.sql` | `app/sql/answers_schema.sql` |
| `app/sql/ops_scope.sql` | `app/sql/roles_and_grants_answers.sql` |
| `app/sql/survey_schema.sql` | |
| `app/sql/email_auth_schema.sql` | |
| `app/sql/roles_and_grants_ops.sql` | |

Assign separate passwords to `ops_admin`, `ops_canvasser`, `answers_admin`, and `answers_writer`; do not run the app as a database owner. Add a region, area, and the first approved admin to `boroughs`, `areas`, and `users`. The SQL in `scripts/docker-init.sh` shows the generic initial records.

Both services need `EMAIL_CODE_SECRET` (32+ random characters), `SMTP_HOST`, `SMTP_FROM`, `SMTP_PORT`, `SMTP_SECURITY`, `SMTP_USERNAME`, `SMTP_PASSWORD`, and `ALLOWED_HOSTS`. Both need `OPS_DB_HOST`, `OPS_DB_PORT`, `OPS_DB_NAME`, `OPS_DB_USER`, `OPS_DB_PASS` for their own role.

The admin service also needs `ROUTE_CODE_FERNET_KEY` and the `ANSWERS_DB_ADMIN_*` connection variables. The canvasser needs `ANSWERS_DB_WRITE_*`; it must not receive the admin database credentials or the route-code encryption key. For remote databases set each `*_SSLMODE=verify-full` and configure the trusted CA using standard libpq settings.

```sh
uvicorn app.admin.main:app --host 127.0.0.1 --port 8001
uvicorn app.canvasser.main:app --host 127.0.0.1 --port 8000
```

Load each service's environment separately using your process manager, or `uvicorn --env-file PATH`. `.env.example` describes the Compose configuration, not a combined runtime environment for both services.

## Verification

```sh
pip install -r requirements-dev.txt
python -m pytest -q
```

Unit checks run without a database. Integration checks explicitly skip unless `TEST_DATABASE_DSN` points at an **isolated test PostgreSQL cluster**. They create/drop temporary databases and set up cluster roles; never use a production cluster.

```sh
export TEST_DATABASE_DSN='host=localhost port=5432 user=postgres dbname=postgres password=YOUR_TEST_PASSWORD'
python -m pytest -q
python -m playwright install chromium
RUN_BROWSER_TESTS=1 python -m pytest -q
pip-audit -r requirements.txt
```

The browser test exercises question creation, editing, removal/restoration and a mobile response submission against actual PostgreSQL role permissions. Email tests substitute a mail sender; no emails are sent. Screenshots under `docs/screenshots` use fictional data. See [verification notes](docs/VERIFICATION.md) for results and limits.

## Licence

Source-available under [PolyForm Noncommercial 1.0.0](LICENSE). Keep the licence and [required notice](NOTICE) with copies. For uses outside its permissions, see [commercial licensing](COMMERCIAL.md). Third-party dependencies retain their own licences.

## Dependencies

Runtime dependencies are pinned with integrity hashes in `requirements.txt`; edit `requirements.in` and regenerate with `uv pip compile requirements.in --python-version 3.12 --generate-hashes --output-file requirements.txt` when updating them. Audit the result and rerun the relevant tests.
