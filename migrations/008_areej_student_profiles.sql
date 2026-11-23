-- Student registration details and controlled portal profile visibility.
BEGIN;
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS age integer;
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS date_of_birth date;
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS gender text;
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS country text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS state text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS phone text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS email text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS guardian_name text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS programme text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS bio text NOT NULL DEFAULT '';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS profile_visibility text NOT NULL DEFAULT 'contacts';
ALTER TABLE areej_app.users ADD COLUMN IF NOT EXISTS show_location boolean NOT NULL DEFAULT false;
ALTER TABLE areej_app.users ADD CONSTRAINT users_profile_visibility_check CHECK (profile_visibility IN ('contacts','private'));
COMMIT;
