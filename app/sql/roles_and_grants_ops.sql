-- Create roles (run as postgres/admin)
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_admin') THEN
    CREATE ROLE ops_admin LOGIN;
    RAISE NOTICE 'Created role ops_admin. Set password separately via secure channel.';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ops_canvasser') THEN
    CREATE ROLE ops_canvasser LOGIN;
    RAISE NOTICE 'Created role ops_canvasser. Set password separately via secure channel.';
  END IF;
END $$;

-- Try to harden role attributes (best effort if caller has CREATEROLE).
DO $$
BEGIN
  BEGIN
    ALTER ROLE ops_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ALTER ROLE ops_canvasser NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'Skipping ALTER ROLE hardening (insufficient privilege).';
  END;
END $$;

-- Try to enforce safe owners (best effort).
DO $$
BEGIN
  BEGIN
    EXECUTE format('ALTER DATABASE %I OWNER TO postgres', current_database());
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'Skipping ALTER DATABASE OWNER (insufficient privilege).';
    WHEN undefined_object THEN
      RAISE NOTICE 'Role postgres not found; skip owner change.';
  END;

  BEGIN
    ALTER SCHEMA public OWNER TO postgres;
  EXCEPTION
    WHEN insufficient_privilege THEN
      RAISE NOTICE 'Skipping ALTER SCHEMA OWNER (insufficient privilege).';
    WHEN undefined_object THEN
      RAISE NOTICE 'Role postgres not found; skip owner change.';
  END;
END $$;

-- Lock down database-level privileges in this database.
DO $$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC, ops_admin, ops_canvasser', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO ops_admin, ops_canvasser', current_database());
  EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM ops_admin, ops_canvasser', current_database());
END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC, ops_admin, ops_canvasser;
GRANT USAGE ON SCHEMA public TO ops_admin, ops_canvasser;
REVOKE CREATE ON SCHEMA public FROM ops_admin, ops_canvasser;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, ops_canvasser;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, ops_canvasser;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ops_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ops_admin;

-- Canvasser access:
GRANT SELECT ON routes TO ops_canvasser;

-- Important: column-level SELECT. Canvassers can read hash but not ciphertext.
REVOKE ALL ON route_codes FROM ops_canvasser;
GRANT SELECT (route_id, code_hash, active, expires_at, created_at) ON route_codes TO ops_canvasser;

GRANT INSERT, SELECT ON canvasser_sessions TO ops_canvasser;
GRANT SELECT, INSERT, UPDATE ON addresses TO ops_canvasser;
GRANT SELECT, INSERT, UPDATE ON flats TO ops_canvasser;
REVOKE ALL ON submission_receipts FROM ops_canvasser;
GRANT SELECT, INSERT ON submission_receipts TO ops_canvasser;
REVOKE ALL ON submission_receipt_events FROM ops_canvasser;
GRANT SELECT, INSERT ON submission_receipt_events TO ops_canvasser;

-- Admin web sessions
DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'admin_sessions'
  ) THEN
    GRANT SELECT, INSERT, DELETE ON admin_sessions TO ops_admin;
  END IF;
END $$;

-- Future-proof default privileges for likely object-owner roles (best effort).
DO $$
DECLARE r text;
BEGIN
  FOR r IN SELECT unnest(ARRAY[current_user, 'postgres']) LOOP
    BEGIN
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM PUBLIC', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM PUBLIC', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM ops_canvasser', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM ops_canvasser', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT ALL ON TABLES TO ops_admin', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT ALL ON SEQUENCES TO ops_admin', r);
    EXCEPTION
      WHEN insufficient_privilege THEN
        RAISE NOTICE 'Skipping ALTER DEFAULT PRIVILEGES FOR ROLE % (insufficient privilege).', r;
      WHEN undefined_object THEN
        NULL;
    END;
  END LOOP;
END $$;

GRANT SELECT ON survey_state, survey_questions TO ops_canvasser;
GRANT DELETE ON canvasser_sessions TO ops_canvasser;
REVOKE ALL ON survey_audit FROM ops_admin;
GRANT SELECT, INSERT ON survey_audit TO ops_admin;

GRANT SELECT, INSERT, UPDATE ON canvasser_login_codes, email_auth_limits TO ops_canvasser;
REVOKE ALL ON admin_login_codes FROM ops_canvasser;
