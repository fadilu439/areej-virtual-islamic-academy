-- Add an optional private-storage object path for each user's profile picture.
BEGIN;
ALTER TABLE areej_app.users
    ADD COLUMN IF NOT EXISTS profile_picture text;
COMMIT;
