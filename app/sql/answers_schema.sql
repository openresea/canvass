CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS responses (
  response_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  submitted_at       timestamptz NOT NULL DEFAULT now(),
  submission_id      uuid NULL,

  borough_id         text NULL,
  area_id            text NULL,
  route_id           text NOT NULL,
  address_id         uuid NOT NULL,
  flat_id            uuid NOT NULL,
  full_address       text NOT NULL,
  flat_label         text NOT NULL,

  canvasser_email    text NOT NULL,
  canvasser_name     text NOT NULL,

  contact_status     text NOT NULL CHECK (contact_status IN ('answered','no_answer','refused','inaccessible')),
  answers_json       jsonb NOT NULL DEFAULT '{}'::jsonb,
  is_duplicate       boolean NOT NULL DEFAULT false,
  duplicate_reason   text NULL,
  postcode           text NULL,
  elector_id         text NULL
);

ALTER TABLE responses
  ADD COLUMN IF NOT EXISTS borough_id text,
  ADD COLUMN IF NOT EXISTS area_id text,
  ADD COLUMN IF NOT EXISTS submission_id uuid,
  ADD COLUMN IF NOT EXISTS is_duplicate boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS duplicate_reason text,
  ADD COLUMN IF NOT EXISTS postcode text,
  ADD COLUMN IF NOT EXISTS elector_id text;



CREATE INDEX IF NOT EXISTS responses_route_time_idx
ON responses(route_id, submitted_at DESC);

CREATE INDEX IF NOT EXISTS responses_borough_time_idx
ON responses(borough_id, submitted_at DESC);

CREATE INDEX IF NOT EXISTS responses_area_time_idx
ON responses(area_id, submitted_at DESC);

CREATE INDEX IF NOT EXISTS responses_submission_id_idx
ON responses(submission_id);

DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM responses
    WHERE submission_id IS NOT NULL
    GROUP BY submission_id
    HAVING COUNT(*) > 1
  ) THEN
    RAISE NOTICE 'Skipping responses_submission_id_uq creation: duplicate submission_id values exist.';
  ELSIF NOT EXISTS (
    SELECT 1
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'i'
      AND c.relname = 'responses_submission_id_uq'
      AND n.nspname = 'public'
  ) THEN
    CREATE UNIQUE INDEX responses_submission_id_uq
    ON responses(submission_id)
    WHERE submission_id IS NOT NULL;
  END IF;
END $$;



