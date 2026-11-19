-- Required by the hardened login throttling in app.py.
-- The compatibility schema remains server-side only.
CREATE TABLE IF NOT EXISTS areej_app.login_attempts (
    attempt_key text PRIMARY KEY,
    window_started_at double precision NOT NULL,
    failed_attempts integer NOT NULL DEFAULT 0,
    blocked_until double precision
);

CREATE INDEX IF NOT EXISTS idx_areej_login_attempts_window
    ON areej_app.login_attempts(window_started_at);

REVOKE ALL ON TABLE areej_app.login_attempts FROM PUBLIC, anon, authenticated;
