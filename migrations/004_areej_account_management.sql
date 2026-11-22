-- Add reversible account deactivation for the AREEJ admin account manager.
-- Existing accounts remain active; no user or academic records are deleted.
BEGIN;
ALTER TABLE areej_app.users
    ADD COLUMN IF NOT EXISTS is_active boolean NOT NULL DEFAULT true;
CREATE INDEX IF NOT EXISTS idx_areej_users_active_role
    ON areej_app.users(role, is_active);
COMMIT;
