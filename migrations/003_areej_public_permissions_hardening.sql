-- Least-privilege hardening for the Supabase API-facing public schema.
-- Keep existing CRUD grants used by reviewed RLS policies; remove dangerous
-- maintenance privileges. Flask's compatibility schema stays server-only.
-- Supabase-hosted postgres cannot alter supabase_admin-owned default ACLs;
-- this migration therefore changes only objects and defaults owned by postgres.
BEGIN;

REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN
ON ALL TABLES IN SCHEMA public
FROM anon, authenticated;

-- No client-callable RPC functions are currently defined in public.
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public
FROM PUBLIC, anon, authenticated;

-- The only public sequence is audit_logs_id_seq; no client insert policy uses it.
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public
FROM PUBLIC, anon, authenticated;

REVOKE ALL ON SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;

-- Tighten future application objects created by the project postgres role.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

COMMIT;
