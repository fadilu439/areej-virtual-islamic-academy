import os
import tempfile

# Give every test run an isolated SQLite database before importing the app.
_TEST_DATA = tempfile.mkdtemp(prefix="areej-tests-")
os.environ["AREEJ_DATA_DIR"] = _TEST_DATA
os.environ["AREEJ_DB_PATH"] = os.path.join(_TEST_DATA, "test.db")
os.environ["AREEJ_SECRET_KEY"] = "test-only-secret-key-not-for-production"

import pytest
import app as app_module
from werkzeug.security import generate_password_hash


app_module.app.config.update(TESTING=True, SECRET_KEY="test-only-secret-key")


@pytest.fixture(autouse=True)
def clean_database():
    with app_module.app.app_context():
        conn = app_module.db()
        for table in (
            "assignment_submissions", "attendance", "results", "assignments",
            "learning_materials", "announcements", "parent_links",
            "enrollments_academic", "classes", "messages", "enrollments",
            "courses", "login_attempts", "users",
        ):
            conn.execute(f"DELETE FROM {table}")
        conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("admin-test", generate_password_hash("correct horse battery staple"), "admin", "Test Admin"),
        )
        conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("student-test", generate_password_hash("student password 123"), "student", "Test Student"),
        )
        conn.commit()
    yield


@pytest.fixture
def client():
    return app_module.app.test_client()


def csrf_token(client):
    client.get("/login")
    with client.session_transaction() as session:
        return session["csrf_token"]


def test_login_post_requires_csrf(client):
    response = client.post("/login", data={"username": "admin-test", "password": "wrong"})
    assert response.status_code == 403


def test_successful_login_regenerates_session_and_csrf(client):
    token = csrf_token(client)
    with client.session_transaction() as session:
        session["pre_login_marker"] = "must be cleared"
        old_token = session["csrf_token"]

    response = client.post(
        "/login",
        data={"csrf_token": token, "username": "admin-test", "password": "correct horse battery staple"},
    )

    assert response.status_code == 302
    with client.session_transaction() as session:
        assert session["user_id"] is not None
        assert session["role"] == "admin"
        assert "pre_login_marker" not in session
        assert session["csrf_token"] != old_token


def test_login_throttles_repeated_failures_for_same_username_and_ip(client):
    token = csrf_token(client)
    environ = {"REMOTE_ADDR": "198.51.100.25"}

    for _ in range(8):
        response = client.post(
            "/login",
            data={"csrf_token": token, "username": "unknown-user", "password": "wrong"},
            environ_base=environ,
        )
        assert response.status_code == 200

    blocked = client.post(
        "/login",
        data={"csrf_token": token, "username": "unknown-user", "password": "wrong"},
        environ_base=environ,
    )
    assert blocked.status_code == 429


def test_admin_cannot_create_account_with_short_password(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")

    response = client.post(
        "/admin",
        data={
            "csrf_token": "test-csrf",
            "action": "add_student",
            "student_name": "New Student",
            "student_username": "new-student",
            "student_password": "short-pass",
        },
    )

    assert response.status_code == 302
    with app_module.app.app_context():
        assert app_module.db().execute(
            "SELECT id FROM users WHERE username=?", ("new-student",)
        ).fetchone() is None


def test_admin_can_create_account_with_12_character_password(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")

    response = client.post(
        "/admin",
        data={
            "csrf_token": "test-csrf",
            "action": "add_student",
            "student_name": "New Student",
            "student_username": "new-student",
            "student_password": "a-strong-pass",
        },
    )

    assert response.status_code == 302
    with app_module.app.app_context():
        user = app_module.db().execute(
            "SELECT password_hash FROM users WHERE username=?", ("new-student",)
        ).fetchone()
        assert user is not None
        from werkzeug.security import check_password_hash
        assert check_password_hash(user["password_hash"], "a-strong-pass")


def test_student_cannot_access_admin_portal(client):
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")

    response = client.get("/admin")
    assert response.status_code == 403


def test_upload_signature_rejects_mismatched_extension():
    from io import BytesIO
    from werkzeug.datastructures import FileStorage

    fake_png = FileStorage(stream=BytesIO(b"this is not a PNG file"), filename="proof.png")
    assert app_module.valid_upload_signature(fake_png, "png") is False


def test_upload_signature_accepts_png_header():
    from io import BytesIO
    from werkzeug.datastructures import FileStorage

    png = FileStorage(
        stream=BytesIO(b"\x89PNG\r\n\x1a\n" + b"test payload"),
        filename="proof.png",
    )
    assert app_module.valid_upload_signature(png, "png") is True


def test_staff_sees_only_students_enrolled_in_their_classes(client):
    with app_module.app.app_context():
        conn = app_module.db()
        teacher_id = conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("teacher-test", generate_password_hash("teacher password 123"), "staff", "Test Teacher"),
        ).lastrowid
        private_student_id = conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("private-student", generate_password_hash("private password 123"), "student", "Private Student"),
        ).lastrowid
        student_id = conn.execute(
            "SELECT id FROM users WHERE username=?", ("student-test",)
        ).fetchone()["id"]
        admin_id = conn.execute(
            "SELECT id FROM users WHERE username=?", ("admin-test",)
        ).fetchone()["id"]
        teacher_class_id = conn.execute(
            "INSERT INTO classes(teacher_id,name) VALUES(?,?)", (teacher_id, "Teacher's Class")
        ).lastrowid
        admin_class_id = conn.execute(
            "INSERT INTO classes(teacher_id,name) VALUES(?,?)", (admin_id, "Admin's Class")
        ).lastrowid
        conn.execute(
            "INSERT INTO enrollments_academic(student_id,class_id) VALUES(?,?)",
            (student_id, teacher_class_id),
        )
        conn.execute(
            "INSERT INTO enrollments_academic(student_id,class_id) VALUES(?,?)",
            (private_student_id, admin_class_id),
        )
        conn.commit()

    with client.session_transaction() as session:
        session.update(user_id=teacher_id, username="teacher-test", role="staff", csrf_token="teacher-csrf")

    response = client.get("/staff")
    assert response.status_code == 200
    assert b"Test Student" in response.data
    assert b"Private Student" not in response.data
    assert b"Teacher's Class" in response.data


def test_health_endpoint_checks_database(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_health_endpoint_reports_database_failure(client):
    from unittest.mock import patch

    with patch.object(app_module, "db", side_effect=RuntimeError("database unavailable")):
        response = client.get("/health")
    assert response.status_code == 503
    assert response.get_json()["status"] == "unhealthy"
