-- 01_rbac_scope_ops.sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- 1) Boroughs + Areas
CREATE TABLE IF NOT EXISTS boroughs (
  borough_id text PRIMARY KEY,
  name       text NOT NULL
);

CREATE TABLE IF NOT EXISTS areas (
  area_id    text PRIMARY KEY,
  borough_id text NOT NULL REFERENCES boroughs(borough_id) ON DELETE CASCADE,
  name       text NOT NULL
);

-- 2) Users + scope
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'user_role') THEN
    CREATE TYPE user_role AS ENUM ('GLOBAL_ADMIN', 'BOROUGH_ADMIN', 'AREA_USER');
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS users (
  email      text PRIMARY KEY,
  role       user_role NOT NULL,
  borough_id text NULL REFERENCES boroughs(borough_id) ON DELETE RESTRICT,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS user_areas (
  email   text NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  area_id text NOT NULL REFERENCES areas(area_id) ON DELETE CASCADE,
  PRIMARY KEY (email, area_id)
);

-- 2b) Admin app sessions
CREATE TABLE IF NOT EXISTS admin_sessions (
  session_token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL REFERENCES users(email) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS admin_sessions_email_idx
ON admin_sessions(email);

CREATE INDEX IF NOT EXISTS admin_sessions_expires_idx
ON admin_sessions(expires_at);

-- 3) Scope fields on routes
ALTER TABLE routes
  ADD COLUMN IF NOT EXISTS borough_id text,
  ADD COLUMN IF NOT EXISTS area_id text,
  ADD COLUMN IF NOT EXISTS uploaded_by_email text,
  ADD COLUMN IF NOT EXISTS route_number integer;

ALTER TABLE routes
  DROP CONSTRAINT IF EXISTS routes_route_number_ck;

-- Add foreign keys (safe, but will fail if existing rows violate)
-- If you already have routes, you may need to populate borough_id/area_id first.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'routes_borough_fk'
  ) THEN
    ALTER TABLE routes
      ADD CONSTRAINT routes_borough_fk FOREIGN KEY (borough_id)
      REFERENCES boroughs(borough_id) ON DELETE RESTRICT;
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'routes_area_fk'
  ) THEN
    ALTER TABLE routes
      ADD CONSTRAINT routes_area_fk FOREIGN KEY (area_id)
      REFERENCES areas(area_id) ON DELETE RESTRICT;
  END IF;
END $$;

-- Helpful indexes
CREATE INDEX IF NOT EXISTS routes_scope_idx ON routes (borough_id, area_id);
CREATE INDEX IF NOT EXISTS routes_uploaded_by_idx ON routes (uploaded_by_email);
CREATE INDEX IF NOT EXISTS routes_area_route_number_idx ON routes (area_id, route_number);

