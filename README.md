# Resea Canvass

A free, self-hosted canvassing app for door-to-door outreach. It's built for charities, community groups and campaigns organising door-knocking: import the addresses and residents your volunteers will visit, hand out a route code, and record each doorstep conversation and survey answer on any phone. You host it yourself, so your data stays with you.

It's free for any non-commercial use, and all the code is public. Have a look at the [screenshots](docs/screenshots.md).

Source: [openresea/canvass](https://github.com/openresea/canvass) · Questions: [resea@tuta.io](mailto:resea@tuta.io)

## What it does

- **Sign in with email.** Anyone can sign in with any email address and a six-digit code. No passwords to remember.
- **Routes and residents.** Import a list of addresses, flats and residents. Volunteers pick the street, the door and the person they spoke to.
- **Route codes.** Volunteers also need a route code from their organiser. Revoke or let a code expire and anyone using it is signed out of that route.
- **Your own questions.** Add written, multiple-choice or yes/no questions, and mark them as required or optional. Change them any time; earlier answers keep the wording they were given with.
- **Every outcome counts.** Record a conversation, no answer, a polite no, or a door you couldn't reach.
- **Safe on bad signal.** If a save fails and the volunteer presses save again, the visit is only recorded once.
- **Exports.** Download visit progress and survey answers as CSV, limited to the areas each organiser looks after.

The question set is shared across one installation. If two separate organisations want different questions, give each their own installation.

## Try it on your computer

You'll need Docker, and Python 3.9 or newer for the setup script.

1. **Get an email account for sending codes.** Any provider with SMTP works. Make sure the sender address is verified. The app only sends over encrypted connections (STARTTLS on port 587, or `SMTP_SECURITY=ssl` on port 465).
2. **Run the setup script:** `python3 scripts/configure.py`. It asks for your email, the sender address and the SMTP server, then writes a `.env` file with fresh random passwords. It never overwrites an existing `.env`.
3. **Add your SMTP login** to `.env` (`SMTP_USERNAME` and `SMTP_PASSWORD`). If a value contains `$` or `#`, wrap it in single quotes.
4. **Start it:** `docker compose up --build`
5. **Open it:** the organiser side is at **http://localhost:8001** and the volunteer side is at **http://localhost:8000/join**. Use `localhost` rather than your computer's network address, because sign-in cookies need it.

Already running an older install under the name `open-canvass`? Add `COMPOSE_PROJECT_NAME=open-canvass` to `.env` so it keeps using your existing database.

Only the email in `ADMIN_EMAIL` gets organiser access to begin with, and only when the database is first created. Changing `.env` later won't change who has access. Please don't delete the database volume to fix a setting once you have real data in it.

### Your first route

1. Sign in on the organiser side and open **Manage survey questions** to add a few questions.
2. Import [the sample route](docs/sample-route.csv) into area `LOCAL_CENTRAL`. It has a few houses, some flats and some made-up residents, so you can see how everything fits together. We'll make a route code for you straight away.
3. Share the route code with your volunteers. They sign in with their own email, enter the code, and start knocking.
4. Come back to see progress and download the answers.

Your CSV needs a `street` column. Everything else is optional: `house`, `flat_number`, `postcode`, `resident_name` and `elector_id`. Fill in what you know and leave the rest blank. It's fine to have names for some doors and not others:

```csv
street,house,flat_number,postcode,resident_name
Example Street,1,,AB1 2CD,Alex Example
Example Street,2,,AB1 2CD,
Example Street,3,A,AB1 2CD,Jordan Sample
Example Street,3,B,AB1 2CD,
```

Put one row per person. Where you don't have a name, volunteers can pick "Name not known" or "Whole household", or type the name in at the door. Headings from an electoral-register export (`street_name`, `building`) work too.

Only import data you're allowed to use. Everything in this repository is made up.

## Putting it online

The database stays inside Docker's private network, and both web ports only listen on your own machine. To put it on the internet you'll need HTTPS, a separate address for the organiser and volunteer sides, and a reverse proxy in front. [SECURITY.md](SECURITY.md) walks through what to set up.

## Running without Docker

Use Python 3.12+ and PostgreSQL 17, and install `requirements.txt` into a virtual environment. Create two **new, empty** databases, then load the schema into each as a PostgreSQL superuser:

```sh
psql -v ON_ERROR_STOP=1 -d YOUR_OPS_DB -f app/sql/ops.sql
psql -v ON_ERROR_STOP=1 -d YOUR_ANSWERS_DB -f app/sql/answers.sql
```

This creates four database logins with only the access each part of the app needs: `ops_admin`, `ops_canvasser`, `answers_admin` and `answers_writer`. Give each its own password. Then add your first region, area and organiser to `boroughs`, `areas` and `users`; `scripts/docker-init.sh` shows how.

Both apps need `EMAIL_CODE_SECRET` (at least 32 random characters), the `SMTP_*` settings, `ALLOWED_HOSTS`, and `OPS_DB_HOST`, `OPS_DB_PORT`, `OPS_DB_NAME`, `OPS_DB_USER` and `OPS_DB_PASS` for their own login.

The organiser app also needs `ROUTE_CODE_FERNET_KEY` and the `ANSWERS_DB_ADMIN_*` settings. The volunteer app needs `ANSWERS_DB_WRITE_*`. Keep the organiser's database login and the route-code key away from the volunteer app. For databases on another machine, set each `*_SSLMODE=verify-full`.

```sh
uvicorn app.admin.main:app --host 127.0.0.1 --port 8001 --no-access-log
uvicorn app.canvasser.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Give each app its own environment, for example with `uvicorn --env-file PATH`. `.env.example` describes the Docker setup, not one combined file for both apps.

## Running the tests

```sh
pip install -r requirements-dev.txt
python -m pytest -q
```

The quick checks run without a database. The rest need a **throwaway** PostgreSQL server that's safe to wipe, because they create and delete databases and change logins. Never point them at a real one.

```sh
export TEST_DATABASE_DSN='host=localhost port=5432 user=postgres dbname=postgres password=YOUR_TEST_PASSWORD'
python -m pytest -q
python -m playwright install chromium
RUN_BROWSER_TESTS=1 python -m pytest -q
pip-audit -r requirements.txt
```

The browser test signs in, edits the questions and saves a visit on a phone-sized screen, then refreshes the screenshots. No real emails are sent. See the [testing notes](docs/VERIFICATION.md) for what is and isn't covered.

## Licence

Resea Canvass is free to use, change and share for any non-commercial purpose, under the [PolyForm Noncommercial licence](LICENSE). Charities, community groups, schools, public bodies and individuals are all welcome. Please keep the licence and the [notice](NOTICE) with any copies.

Because the licence rules out commercial use, it isn't "open source" in the strict OSI sense. The code is all public and you can do almost anything with it, as long as you're not making money from it. If you'd like to use it commercially, please [get in touch](COMMERCIAL.md) first.

## Supporting the project

Resea Canvass is free and made by volunteers. If it's helped your group and you'd like to chip in, you can [buy us a coffee on Ko-fi](https://ko-fi.com/openresea). Every bit helps keep it going. Thank you!

## Dependencies

Dependencies are pinned with checksums in `requirements.txt`. To update them, edit `requirements.in`, then run `uv pip compile requirements.in --python-version 3.12 --generate-hashes --output-file requirements.txt`, check the result with `pip-audit`, and run the tests again.
