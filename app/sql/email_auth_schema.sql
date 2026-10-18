CREATE TABLE IF NOT EXISTS admin_login_codes (
  challenge_id uuid PRIMARY KEY,
  email text NOT NULL,
  code_digest text NOT NULL,
  expires_at timestamptz NOT NULL,
  attempts integer NOT NULL DEFAULT 0,
  consumed boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS canvasser_login_codes (LIKE admin_login_codes INCLUDING ALL);
CREATE INDEX IF NOT EXISTS admin_login_codes_email_idx ON admin_login_codes(email);
CREATE INDEX IF NOT EXISTS canvasser_login_codes_email_idx ON canvasser_login_codes(email);
CREATE TABLE IF NOT EXISTS email_auth_limits (
  key_hash text PRIMARY KEY,
  hits integer NOT NULL,
  resets_at timestamptz NOT NULL
);
