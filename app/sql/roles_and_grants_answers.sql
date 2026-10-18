DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'answers_admin') THEN
    CREATE ROLE answers_admin LOGIN;
    RAISE NOTICE 'Created role answers_admin. Set password separately via secure channel.';
  END IF;

  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'answers_writer') THEN
    CREATE ROLE answers_writer LOGIN;
    RAISE NOTICE 'Created role answers_writer. Set password separately via secure channel.';
  END IF;
END $$;

-- Try to harden role attributes (best effort if caller has CREATEROLE).
DO $$
BEGIN
  BEGIN
    ALTER ROLE answers_admin NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
    ALTER ROLE answers_writer NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
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
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC, answers_admin, answers_writer', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO answers_admin, answers_writer', current_database());
  EXECUTE format('REVOKE CREATE, TEMPORARY ON DATABASE %I FROM answers_admin, answers_writer', current_database());
END $$;

REVOKE ALL ON SCHEMA public FROM PUBLIC, answers_admin, answers_writer;
GRANT USAGE ON SCHEMA public TO answers_admin, answers_writer;
REVOKE CREATE ON SCHEMA public FROM answers_admin, answers_writer;

-- Export/admin app role is read-only on answers data.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, answers_admin, answers_writer;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC, answers_admin, answers_writer;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO answers_admin;

-- Writer is INSERT-only. No SELECT.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = 'public' AND table_name = 'responses'
  ) THEN
    REVOKE ALL ON responses FROM answers_writer;
    GRANT INSERT ON responses TO answers_writer;
  ELSE
    RAISE NOTICE 'Table responses does not exist yet; skipping table grants. Re-run after answers_schema.sql.';
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
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM answers_admin', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM answers_admin', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON TABLES FROM answers_writer', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public REVOKE ALL ON SEQUENCES FROM answers_writer', r);
      EXECUTE format('ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO answers_admin', r);
    EXCEPTION
      WHEN insufficient_privilege THEN
        RAISE NOTICE 'Skipping ALTER DEFAULT PRIVILEGES FOR ROLE % (insufficient privilege).', r;
      WHEN undefined_object THEN
        NULL;
    END;
  END LOOP;
END $$;
