-- Private chat receipts and per-account messaging/appearance preferences.
-- Existing message history is preserved; old messages remain readable.
BEGIN;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS read_at timestamptz;
ALTER TABLE areej_app.messages ADD COLUMN IF NOT EXISTS delivered_at timestamptz;
CREATE INDEX IF NOT EXISTS idx_areej_messages_recipient_unread ON areej_app.messages(recipient_id, is_read, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_areej_messages_sender_recipient ON areej_app.messages(sender_id, recipient_id, created_at);
CREATE TABLE IF NOT EXISTS areej_app.user_preferences (
    user_id bigint PRIMARY KEY REFERENCES areej_app.users(id) ON DELETE CASCADE,
    theme text NOT NULL DEFAULT 'light' CHECK (theme IN ('light','dark','system')),
    message_notifications boolean NOT NULL DEFAULT true,
    read_receipts boolean NOT NULL DEFAULT true,
    updated_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP
);
REVOKE ALL ON TABLE areej_app.user_preferences FROM PUBLIC, anon, authenticated;
COMMIT;
