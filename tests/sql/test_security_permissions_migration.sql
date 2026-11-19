-- Runs only against the disposable PostgreSQL service in GitHub Actions.
-- Verifies existing object grants and future objects created by project postgres.
CREATE ROLE anon NOLOGIN;
CREATE ROLE authenticated NOLOGIN;

GRANT USAGE ON SCHEMA public TO anon, authenticated;
CREATE SCHEMA areej_app;
GRANT USAGE ON SCHEMA areej_app TO anon, authenticated;

CREATE TABLE public.security_probe (id bigserial PRIMARY KEY);
GRANT ALL ON TABLE public.security_probe TO anon, authenticated;
GRANT ALL ON SEQUENCE public.security_probe_id_seq TO anon, authenticated;

CREATE FUNCTION public.security_probe_fn()
RETURNS integer LANGUAGE sql AS 'SELECT 1';
GRANT EXECUTE ON FUNCTION public.security_probe_fn() TO PUBLIC, anon, authenticated;

CREATE TABLE areej_app.private_probe (id integer PRIMARY KEY);
GRANT ALL ON TABLE areej_app.private_probe TO PUBLIC, anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT ALL ON TABLES TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT ALL ON SEQUENCES TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  GRANT EXECUTE ON FUNCTIONS TO PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  GRANT ALL ON TABLES TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  GRANT ALL ON SEQUENCES TO anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  GRANT EXECUTE ON FUNCTIONS TO anon, authenticated;

\ir ../../migrations/003_areej_public_permissions_hardening.sql

CREATE TABLE public.future_postgres_table (id bigserial PRIMARY KEY);
CREATE FUNCTION public.future_postgres_function()
RETURNS integer LANGUAGE sql AS 'SELECT 1';

DO $$
DECLARE client_role text;
BEGIN
  FOREACH client_role IN ARRAY ARRAY['anon', 'authenticated'] LOOP
    IF has_table_privilege(client_role, 'public.security_probe', 'TRUNCATE')
       OR has_table_privilege(client_role, 'public.security_probe', 'REFERENCES')
       OR has_table_privilege(client_role, 'public.security_probe', 'TRIGGER')
       OR has_table_privilege(client_role, 'public.security_probe', 'MAINTAIN') THEN
      RAISE EXCEPTION 'Dangerous table privilege remains for %', client_role;
    END IF;
    IF NOT has_table_privilege(client_role, 'public.security_probe', 'SELECT')
       OR NOT has_table_privilege(client_role, 'public.security_probe', 'INSERT') THEN
      RAISE EXCEPTION 'Existing CRUD grants were not preserved for %', client_role;
    END IF;
    IF has_sequence_privilege(client_role, 'public.security_probe_id_seq', 'USAGE') THEN
      RAISE EXCEPTION 'Client sequence privilege remains for %', client_role;
    END IF;
    IF has_function_privilege(client_role, 'public.security_probe_fn()', 'EXECUTE') THEN
      RAISE EXCEPTION 'Existing public function remains executable by %', client_role;
    END IF;
    IF has_schema_privilege(client_role, 'areej_app', 'USAGE')
       OR has_table_privilege(client_role, 'areej_app.private_probe', 'SELECT') THEN
      RAISE EXCEPTION 'Compatibility schema remains accessible to %', client_role;
    END IF;
    IF has_table_privilege(client_role, 'public.future_postgres_table', 'SELECT')
       OR has_table_privilege(client_role, 'public.future_postgres_table', 'INSERT')
       OR has_table_privilege(client_role, 'public.future_postgres_table', 'TRUNCATE') THEN
      RAISE EXCEPTION 'Unsafe future table privileges remain for %', client_role;
    END IF;
    IF has_sequence_privilege(client_role, 'public.future_postgres_table_id_seq', 'USAGE') THEN
      RAISE EXCEPTION 'Unsafe future sequence privilege remains for %', client_role;
    END IF;
    IF has_function_privilege(client_role, 'public.future_postgres_function()', 'EXECUTE') THEN
      RAISE EXCEPTION 'Unsafe future function privilege remains for %', client_role;
    END IF;
  END LOOP;
END
$$;
