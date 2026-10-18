# Testing

Use Python 3.12 or newer. Install the runtime and development dependencies as described in the README.

```sh
python -m pytest -q
```

Without `TEST_DATABASE_DSN`, database tests skip. Browser tests also require `RUN_BROWSER_TESTS=1` and Playwright Chromium.

For the complete suite, use an isolated, disposable PostgreSQL 17 cluster. Fixtures create and drop databases and change cluster roles. Never use a shared or production cluster.

```sh
export TEST_DATABASE_DSN='host=127.0.0.1 port=55439 user=postgres dbname=postgres'
python -m playwright install chromium
RUN_BROWSER_TESTS=1 python -m pytest -q
```

## Coverage

Tests cover email codes, expiry, retry limits, concurrency, origin and host checks, route-code expiry and revocation, route and area permissions, survey history, duplicate submissions, CSV import and export, and database role permissions. The browser workflow covers signing in, editing and restoring survey questions, and submitting answers on a mobile viewport. It regenerates the screenshots with fictional data.

The browser sends requests to the ASGI applications through test clients backed by PostgreSQL. Email delivery is replaced with a test inbox. These tests do not exercise an SMTP provider, production proxy, HTTPS certificate, backup restoration, or hosting environment.

## Dependency checks

```sh
pip-audit -r requirements.txt --disable-pip --no-deps
```

`requirements.txt` includes pinned transitive dependencies and hashes. Advisory results change over time; check again before a release.
