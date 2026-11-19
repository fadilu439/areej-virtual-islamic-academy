-- Least-privilege hardening for the Supabase API-facing public schema.
-- Keep the existing CRUD grants used by the reviewed RLS policies, but remove
-- table-maintenance privileges from client roles. The Flask compatibility
-- schema remains server-side only and is explicitly inaccessible to API roles.
BEGIN;

-- Existing public tables: preserve SELECT/INSERT/UPDATE/DELETE where granted
-- (RLS remains the row-level gate), but remove powerful maintenance privileges.
REVOKE TRUNCATE, REFERENCES, TRIGGER, MAINTAIN
ON ALL TABLES IN SCHEMA public
FROM anon, authenticated;

-- The public schema currently has no client-callable RPC functions. Remove
-- existing client/PUBLIC EXECUTE grants; future RPCs must be granted explicitly.
REVOKE ALL
ON ALL FUNCTIONS IN SCHEMA public
FROM PUBLIC, anon, authenticated;

-- Public sequences are not directly used by client-facing insert policies.
REVOKE ALL
ON ALL SEQUENCES IN SCHEMA public
FROM PUBLIC, anon, authenticated;

-- The Flask compatibility schema must only be accessed by the server-side
-- database role. Do not enable RLS here: Flask connects as the database owner.
REVOKE ALL ON SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL TABLES IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA areej_app FROM PUBLIC, anon, authenticated;

-- Secure future objects created by either role that currently owns/creates
-- application objects. New client-facing access must be granted deliberately.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA public
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

-- Also keep future compatibility-schema objects inaccessible to API roles.
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA areej_app
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA areej_app
  REVOKE ALL ON TABLES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA areej_app
  REVOKE ALL ON SEQUENCES FROM PUBLIC, anon, authenticated;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin
  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE supabase_admin IN SCHEMA areej_app
  REVOKE EXECUTE ON FUNCTIONS FROM anon, authenticated;

COMMIT;
