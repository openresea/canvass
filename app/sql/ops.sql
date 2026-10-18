-- Operations database: areas, admins, routes, addresses, sign-in and the survey.
-- Run once on a new, empty database as a PostgreSQL superuser.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE boroughs (
  borough_id text PRIMARY KEY,
  name       text NOT NULL
);

CREATE TABLE areas (
  area_id    text PRIMARY KEY,
  borough_id text NOT NULL REFERENCES boroughs(borough_id) ON DELETE CASCADE,
  name       text NOT NULL
);

CREATE TYPE user_role AS ENUM ('GLOBAL_ADMIN', 'BOROUGH_ADMIN', 'AREA_USER');

CREATE TABLE users (
  email      text PRIMARY KEY,
  role       user_role NOT NULL,
  borough_id text NULL REFERENCES boroughs(borough_id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE user_areas (
  email   text NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  area_id text NOT NULL REFERENCES areas(area_id) ON DELETE CASCADE,
  PRIMARY KEY (email, area_id)
);

-- Deleting a user cascades to their sessions, revoking admin access.
CREATE TABLE admin_sessions (
  session_token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);
CREATE INDEX admin_sessions_expires_idx ON admin_sessions(expires_at);

CREATE TABLE routes (
  route_id          text PRIMARY KEY,
  name              text NOT NULL,
  active            boolean NOT NULL DEFAULT true,
  route_number      integer NULL,
  borough_id        text REFERENCES boroughs(borough_id) ON DELETE RESTRICT,
  area_id           text REFERENCES areas(area_id) ON DELETE RESTRICT,
  uploaded_by_email text,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX routes_scope_idx ON routes(borough_id, area_id);

-- Each code is stored twice: a bcrypt hash that sign-in checks, and Fernet
-- ciphertext that only the admin service (which holds the key) can show again.
CREATE TABLE route_codes (
  route_id        text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  code_hash       text NOT NULL,
  code_ciphertext text NOT NULL,
  active          boolean NOT NULL DEFAULT true,
  expires_at      timestamptz NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (route_id, code_hash)
);

-- Bound to the code that created it, so revoking the code ends the session.
CREATE TABLE canvasser_sessions (
  session_token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL,
  display_name  text NOT NULL,
  code_hash     text NOT NULL,
  route_id      text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);

CREATE TABLE addresses (
  address_id   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id     text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  street       text NOT NULL,
  house        text NOT NULL,
  postcode     text NOT NULL,
  full_address text NOT NULL,
  source       text NOT NULL CHECK (source IN ('uploaded', 'manual')),
  created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX addresses_route_norm_uq
  ON addresses(route_id, lower(postcode), lower(street), lower(house));

-- One row per doorstep contact: a resident, an elector, or a whole unit.
CREATE TABLE flats (
  flat_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  address_id    uuid NOT NULL REFERENCES addresses(address_id) ON DELETE CASCADE,
  flat_label    text NOT NULL,
  status        text NOT NULL DEFAULT 'unvisited'
                CHECK (status IN ('unvisited', 'answered', 'no_answer', 'refused', 'inaccessible')),
  resident_name text NULL,
  elector_id    text NULL,
  flat_number   text NULL,
  updated_at    timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX flats_address_label_uq ON flats(address_id, lower(flat_label));

CREATE TABLE survey_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  version   integer NOT NULL DEFAULT 1 CHECK (version > 0)
);
INSERT INTO survey_state(singleton) VALUES (true);

CREATE TABLE survey_questions (
  question_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  prompt      text NOT NULL CHECK (length(prompt) BETWEEN 1 AND 300),
  kind        text NOT NULL CHECK (kind IN ('text', 'single_choice', 'yes_no')),
  required    boolean NOT NULL DEFAULT false,
  options     jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(options) = 'array'),
  position    integer NOT NULL,
  archived    boolean NOT NULL DEFAULT false
);

CREATE TABLE survey_audit (
  audit_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  changed_at  timestamptz NOT NULL DEFAULT now(),
  actor_email text NOT NULL,
  action      text NOT NULL,
  question_id uuid NOT NULL,
  version     integer NOT NULL
);

CREATE FUNCTION forbid_append_only_changes() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Table % is append-only; % is not allowed', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER survey_audit_no_update_delete BEFORE UPDATE OR DELETE ON survey_audit
  FOR EACH ROW EXECUTE FUNCTION forbid_append_only_changes();

-- Only an HMAC of each code is stored. Separate tables keep the canvasser
-- role away from admin codes.
CREATE TABLE admin_login_codes (
  challenge_id uuid PRIMARY KEY,
  email        text NOT NULL,
  code_digest  text NOT NULL,
  expires_at   timestamptz NOT NULL,
  attempts     integer NOT NULL DEFAULT 0,
  consumed     boolean NOT NULL DEFAULT false
);
CREATE TABLE canvasser_login_codes (LIKE admin_login_codes INCLUDING ALL);
CREATE INDEX admin_login_codes_email_idx ON admin_login_codes(email);
CREATE INDEX canvasser_login_codes_email_idx ON canvasser_login_codes(email);

-- Rate-limit counters keyed by an HMAC, so no raw IPs or emails are stored.
CREATE TABLE email_auth_limits (
  key_hash  text PRIMARY KEY,
  hits      integer NOT NULL,
  resets_at timestamptz NOT NULL
);

-- Roles are cluster-wide, so they may already exist from another database.
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_admin') THEN
    CREATE ROLE ops_admin LOGIN;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_canvasser') THEN
    CREATE ROLE ops_canvasser LOGIN;
  END IF;
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO ops_admin, ops_canvasser', current_database());
END $$;
ALTER ROLE ops_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER ROLE ops_canvasser NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ops_admin, ops_canvasser;

GRANT ALL ON ALL TABLES IN SCHEMA public TO ops_admin;
REVOKE ALL ON survey_audit FROM ops_admin;
GRANT SELECT, INSERT ON survey_audit TO ops_admin;

-- The canvasser can verify code hashes but never read the ciphertext.
GRANT SELECT (route_id, code_hash, active, expires_at) ON route_codes TO ops_canvasser;
GRANT SELECT ON routes, survey_state, survey_questions TO ops_canvasser;
GRANT SELECT, INSERT, DELETE ON canvasser_sessions TO ops_canvasser;
GRANT SELECT, INSERT, UPDATE ON addresses, flats, canvasser_login_codes, email_auth_limits
  TO ops_canvasser;
