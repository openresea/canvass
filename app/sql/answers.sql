-- Answers database: survey responses only.
-- Run once on a new, empty database as a PostgreSQL superuser.
CREATE TABLE responses (
  response_id     uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  submitted_at    timestamptz NOT NULL DEFAULT now(),
  -- Client-generated per visit; makes retried submissions a no-op.
  submission_id   uuid NOT NULL UNIQUE,
  borough_id      text NULL,
  area_id         text NULL,
  route_id        text NOT NULL,
  address_id      uuid NOT NULL,
  flat_id         uuid NOT NULL,
  full_address    text NOT NULL,
  flat_label      text NOT NULL,
  postcode        text NULL,
  elector_id      text NULL,
  canvasser_email text NOT NULL,
  canvasser_name  text NOT NULL,
  contact_status  text NOT NULL CHECK (contact_status IN ('answered', 'no_answer', 'refused', 'inaccessible')),
  answers_json    jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX responses_route_time_idx ON responses(route_id, submitted_at DESC);
CREATE INDEX responses_borough_time_idx ON responses(borough_id, submitted_at DESC);
CREATE INDEX responses_area_time_idx ON responses(area_id, submitted_at DESC);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'answers_admin') THEN
    CREATE ROLE answers_admin LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'answers_writer') THEN
    CREATE ROLE answers_writer LOGIN;
  END IF;
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO answers_admin, answers_writer', current_database());
END $$;
ALTER ROLE answers_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE answers_writer NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO answers_admin, answers_writer;

-- Export is read-only; the public canvasser service can write but never read back.
GRANT SELECT ON responses TO answers_admin;
GRANT INSERT ON responses TO answers_writer;
