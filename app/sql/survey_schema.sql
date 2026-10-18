CREATE TABLE IF NOT EXISTS survey_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
  version integer NOT NULL DEFAULT 1 CHECK(version > 0)
);
INSERT INTO survey_state(singleton) VALUES (true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS survey_questions (
  question_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  prompt text NOT NULL CHECK(length(prompt) BETWEEN 1 AND 300),
  kind text NOT NULL CHECK(kind IN ('text','single_choice','yes_no')),
  required boolean NOT NULL DEFAULT false,
  options jsonb NOT NULL DEFAULT '[]'::jsonb CHECK(jsonb_typeof(options)='array'),
  position integer NOT NULL,
  archived boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS survey_audit (
  audit_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  changed_at timestamptz NOT NULL DEFAULT now(),
  actor_email text NOT NULL,
  action text NOT NULL,
  question_id uuid NOT NULL,
  version integer NOT NULL
);
DROP TRIGGER IF EXISTS survey_audit_no_update_delete ON survey_audit;
CREATE TRIGGER survey_audit_no_update_delete BEFORE UPDATE OR DELETE ON survey_audit
FOR EACH ROW EXECUTE FUNCTION forbid_append_only_changes();
