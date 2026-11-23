-- Message editing, participant-specific deletion and safe forwarding.
-- Original message rows remain in place; edits and delete-for-everyone actions
-- preserve the previous text in an internal history table.
BEGIN;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS edited_at timestamptz;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS hidden_for_sender boolean NOT NULL DEFAULT false;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS hidden_for_recipient boolean NOT NULL DEFAULT false;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS deleted_for_everyone boolean NOT NULL DEFAULT false;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS forwarded_from_id bigint;
CREATE TABLE IF NOT EXISTS areej_app.message_history (
    id bigserial PRIMARY KEY,
    message_id bigint NOT NULL REFERENCES areej_app.messages(id) ON DELETE CASCADE,
    actor_id bigint NOT NULL REFERENCES areej_app.users(id),
    action text NOT NULL CHECK (action IN ('edit','delete_for_everyone')),
    previous_body text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_areej_message_history_message ON areej_app.message_history(message_id, created_at);
REVOKE ALL ON TABLE areej_app.message_history FROM PUBLIC, anon, authenticated;
COMMIT;
