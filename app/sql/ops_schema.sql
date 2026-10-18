CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS routes (
  route_id   text PRIMARY KEY,
  name       text NOT NULL,
  active     boolean NOT NULL DEFAULT true,
  route_number integer NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE routes
  ADD COLUMN IF NOT EXISTS route_number integer;

ALTER TABLE routes
  DROP CONSTRAINT IF EXISTS routes_route_number_ck;

-- Store codes two ways:
-- 1) code_hash (bcrypt) used by canvassers to verify
-- 2) code_ciphertext (Fernet) only admin can read/export
CREATE TABLE IF NOT EXISTS route_codes (
  route_id        text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  code_hash       text NOT NULL,
  code_ciphertext text NOT NULL,
  active          boolean NOT NULL DEFAULT true,
  expires_at      timestamptz NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (route_id, code_hash)
);

CREATE INDEX IF NOT EXISTS route_codes_active_idx
ON route_codes(route_id, active);

CREATE TABLE IF NOT EXISTS canvasser_sessions (
  session_token uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text NOT NULL,
  display_name  text NOT NULL,
  code_hash     text NOT NULL,
  route_id      text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  created_at    timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS canvasser_sessions_route_idx
ON canvasser_sessions(route_id);

CREATE TABLE IF NOT EXISTS addresses (
  address_id    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  route_id      text NOT NULL REFERENCES routes(route_id) ON DELETE CASCADE,
  street        text NOT NULL,
  house         text NOT NULL,
  postcode      text NOT NULL,
  full_address  text NOT NULL,
  source        text NOT NULL CHECK (source IN ('uploaded','manual')),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS addresses_route_norm_uq
ON addresses (route_id, lower(postcode), lower(street), lower(house));

CREATE INDEX IF NOT EXISTS addresses_route_full_idx
ON addresses(route_id, full_address);

CREATE TABLE IF NOT EXISTS flats (
  flat_id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  address_id        uuid NOT NULL REFERENCES addresses(address_id) ON DELETE CASCADE,
  flat_label        text NOT NULL,
  status            text NOT NULL DEFAULT 'unvisited'
                     CHECK (status IN ('unvisited','in_progress','answered','no_answer','refused','inaccessible')),
  resident_name     text NULL,
  elector_id        text NULL,
  flat_number       text NULL,
  updated_at        timestamptz NOT NULL DEFAULT now()
);



ALTER TABLE flats
  ADD COLUMN IF NOT EXISTS resident_name text,
  ADD COLUMN IF NOT EXISTS elector_id text,
  ADD COLUMN IF NOT EXISTS flat_number text;



CREATE UNIQUE INDEX IF NOT EXISTS flats_address_label_uq
ON flats (address_id, lower(flat_label));

CREATE INDEX IF NOT EXISTS flats_address_status_idx
ON flats (address_id, status);



-- Metadata-only durability log for canvasser submissions.
-- Intentionally stores no answer content / notes text.
CREATE TABLE IF NOT EXISTS submission_receipts (
  receipt_id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  received_at              timestamptz NOT NULL DEFAULT now(),
  submission_id            uuid NOT NULL,
  route_id                 text NOT NULL,
  address_id               uuid NOT NULL,
  flat_id                  uuid NOT NULL,
  full_address             text NOT NULL,
  flat_label               text NOT NULL,
  canvasser_email          text NOT NULL,
  canvasser_name           text NOT NULL,
  contact_status           text NOT NULL CHECK (contact_status IN ('answered','no_answer','refused','inaccessible')),
  survey_kind              text NULL CHECK (survey_kind IN ('short','long')),
  revisit_requested        boolean NOT NULL DEFAULT false,
  notes_present            boolean NOT NULL DEFAULT false,
  answer_keys_count        integer NOT NULL DEFAULT 0,
  payload_sha256           text NOT NULL,
  is_duplicate             boolean NOT NULL DEFAULT false,
  duplicate_of_receipt_id  uuid NULL REFERENCES submission_receipts(receipt_id),
  duplicate_reason         text NULL
);

CREATE INDEX IF NOT EXISTS submission_receipts_submission_idx
ON submission_receipts(submission_id, received_at);

CREATE INDEX IF NOT EXISTS submission_receipts_flat_time_idx
ON submission_receipts(flat_id, received_at DESC);

CREATE INDEX IF NOT EXISTS submission_receipts_route_time_idx
ON submission_receipts(route_id, received_at DESC);

CREATE TABLE IF NOT EXISTS submission_receipt_events (
  event_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  event_at        timestamptz NOT NULL DEFAULT now(),
  receipt_id      uuid NOT NULL REFERENCES submission_receipts(receipt_id),
  submission_id   uuid NOT NULL,
  db_name         text NOT NULL CHECK (db_name IN ('ops','answers','short_answers','long_answers')),
  stage           text NOT NULL CHECK (stage IN ('received','answers_written','short_answers_written','long_answers_written','ops_status_updated','failed')),
  ok              boolean NOT NULL DEFAULT true,
  ref_id          uuid NULL,
  detail          text NULL
);

CREATE INDEX IF NOT EXISTS submission_receipt_events_submission_idx
ON submission_receipt_events(submission_id, event_at DESC);

CREATE INDEX IF NOT EXISTS submission_receipt_events_receipt_idx
ON submission_receipt_events(receipt_id, event_at DESC);

CREATE OR REPLACE FUNCTION forbid_append_only_changes()
RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'Table % is append-only; % is not allowed', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS submission_receipts_no_update_delete ON submission_receipts;
CREATE TRIGGER submission_receipts_no_update_delete
BEFORE UPDATE OR DELETE ON submission_receipts
FOR EACH ROW EXECUTE FUNCTION forbid_append_only_changes();

DROP TRIGGER IF EXISTS submission_receipt_events_no_update_delete ON submission_receipt_events;
CREATE TRIGGER submission_receipt_events_no_update_delete
BEFORE UPDATE OR DELETE ON submission_receipt_events
FOR EACH ROW EXECUTE FUNCTION forbid_append_only_changes();
