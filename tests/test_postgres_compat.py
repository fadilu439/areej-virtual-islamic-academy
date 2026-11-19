import pytest

from postgres_compat import PostgresCompatConnection


def test_qmark_placeholders_are_translated():
    assert PostgresCompatConnection._translate(
        "SELECT * FROM users WHERE username=? AND role=?"
    ) == "SELECT * FROM users WHERE username=%s AND role=%s"


def test_insert_or_ignore_is_translated():
    assert PostgresCompatConnection._translate(
        "INSERT OR IGNORE INTO parent_links(parent_id,student_id) VALUES(?,?)"
    ) == "INSERT INTO parent_links(parent_id,student_id) VALUES(%s,%s) ON CONFLICT DO NOTHING"


def test_attendance_replace_uses_the_unique_key():
    query = PostgresCompatConnection._translate(
        "INSERT OR REPLACE INTO attendance(class_id,student_id,lesson_date,status,recorded_by) VALUES(?,?,?,?,?)"
    )
    assert "ON CONFLICT (class_id, student_id, lesson_date) DO UPDATE SET" in query
    assert "status = EXCLUDED.status" in query


def test_assignment_submission_replace_uses_the_unique_key():
    query = PostgresCompatConnection._translate(
        "INSERT OR REPLACE INTO assignment_submissions(assignment_id,student_id,content,file_name,file_path) VALUES(?,?,?,?,?)"
    )
    assert "ON CONFLICT (assignment_id, student_id) DO UPDATE SET" in query
    assert "file_path = EXCLUDED.file_path" in query


def test_unsupported_replace_is_rejected():
    with pytest.raises(ValueError):
        PostgresCompatConnection._translate(
            "INSERT OR REPLACE INTO users(username) VALUES(?)"
        )
