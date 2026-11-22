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
            "learning_materials", "announcements", "parent_links", "user_preferences",
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
            "student_password": "short7!",
        },
    )

    assert response.status_code == 302
    with app_module.app.app_context():
        assert app_module.db().execute(
            "SELECT id FROM users WHERE username=?", ("new-student",)
        ).fetchone() is None


def test_admin_can_create_account_with_8_character_password(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")

    response = client.post(
        "/admin",
        data={
            "csrf_token": "test-csrf",
            "action": "add_student",
            "student_name": "New Student",
            "student_username": "new-student",
            "student_password": "pass1234",
        },
    )

    assert response.status_code == 302
    with app_module.app.app_context():
        user = app_module.db().execute(
            "SELECT password_hash FROM users WHERE username=?", ("new-student",)
        ).fetchone()
        assert user is not None
        from werkzeug.security import check_password_hash
        assert check_password_hash(user["password_hash"], "pass1234")


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
    from html import unescape
    assert "Teacher's Class" in unescape(response.get_data(as_text=True))


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


def test_render_requires_stable_session_secret(monkeypatch):
    monkeypatch.setenv("RENDER", "true")
    monkeypatch.delenv("AREEJ_SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AREEJ_SECRET_KEY must be configured on Render"):
        app_module.configured_secret_key()


def test_local_development_can_generate_session_secret(monkeypatch):
    monkeypatch.delenv("RENDER", raising=False)
    monkeypatch.delenv("AREEJ_SECRET_KEY", raising=False)
    assert len(app_module.configured_secret_key()) >= 32


def test_admin_can_edit_account_without_changing_password_unless_provided(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    with app_module.app.app_context():
        conn=app_module.db()
        conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
                     ("edit-student", generate_password_hash("original password"), "student", "Old Name"))
        conn.commit()
        account_id=conn.execute("SELECT id FROM users WHERE username='edit-student'").fetchone()["id"]
    response=client.post(f"/admin/accounts/{account_id}/update", data={
        "csrf_token":"test-csrf", "display_name":"Corrected Name", "username":"corrected-student", "new_password":""
    })
    assert response.status_code==302
    with app_module.app.app_context():
        user=app_module.db().execute("SELECT * FROM users WHERE id=?", (account_id,)).fetchone()
        from werkzeug.security import check_password_hash
        assert user["display_name"]=="Corrected Name"
        assert user["username"]=="corrected-student"
        assert check_password_hash(user["password_hash"], "original password")


def test_admin_can_deactivate_and_restore_account_without_deleting_it(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    with app_module.app.app_context():
        conn=app_module.db()
        conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
                     ("switch-user", generate_password_hash("password 1234"), "student", "Switch User"))
        conn.commit()
        account_id=conn.execute("SELECT id FROM users WHERE username='switch-user'").fetchone()["id"]
    assert client.post(f"/admin/accounts/{account_id}/toggle", data={"csrf_token":"test-csrf"}).status_code==302
    with app_module.app.app_context():
        row=app_module.db().execute("SELECT is_active FROM users WHERE id=?", (account_id,)).fetchone()
        assert row["is_active"] in (0, False)
    assert client.post(f"/admin/accounts/{account_id}/toggle", data={"csrf_token":"test-csrf"}).status_code==302
    with app_module.app.app_context():
        row=app_module.db().execute("SELECT is_active FROM users WHERE id=?", (account_id,)).fetchone()
        assert row["is_active"] in (1, True)


def test_admin_cannot_deactivate_last_admin_or_self(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    own=client.post("/admin/accounts/1/toggle", data={"csrf_token":"test-csrf"})
    assert own.status_code==302
    with app_module.app.app_context():
        active=app_module.db().execute("SELECT is_active FROM users WHERE id=1").fetchone()["is_active"]
        assert active in (1, True)


def test_staff_can_edit_only_own_class_and_assignment(client):
    with app_module.app.app_context():
        conn=app_module.db()
        staff_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("staff-owner", generate_password_hash("staff password 123"), "staff", "Staff Owner")).lastrowid
        other_staff=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("staff-other", generate_password_hash("other password 123"), "staff", "Other Staff")).lastrowid
        own_class=conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)", (staff_id,"Own Class")).lastrowid
        other_class=conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)", (other_staff,"Other Class")).lastrowid
        own_assignment=conn.execute("INSERT INTO assignments(class_id,title) VALUES(?,?)", (own_class,"Own Assignment")).lastrowid
        other_assignment=conn.execute("INSERT INTO assignments(class_id,title) VALUES(?,?)", (other_class,"Other Assignment")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=staff_id, username="staff-owner", role="staff", csrf_token="staff-csrf")
    ok=client.post("/staff/work", data={"csrf_token":"staff-csrf","action":"update_assignment",
        "assignment_id":str(own_assignment),"title":"Corrected Assignment","instructions":"Updated","due_date":""})
    assert ok.status_code==302
    denied=client.post("/staff/work", data={"csrf_token":"staff-csrf","action":"update_assignment",
        "assignment_id":str(other_assignment),"title":"Unauthorized","instructions":"","due_date":""})
    assert denied.status_code==403
    with app_module.app.app_context():
        title=app_module.db().execute("SELECT title FROM assignments WHERE id=?", (own_assignment,)).fetchone()["title"]
        assert title=="Corrected Assignment"



def test_message_inbox_marks_delivery_and_conversation_marks_read(client):
    with app_module.app.app_context():
        conn = app_module.db()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin-test'").fetchone()["id"]
        student_id = conn.execute("SELECT id FROM users WHERE username='student-test'").fetchone()["id"]
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)",
                     (student_id, admin_id, "Assalamu alaikum"))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=admin_id, username="admin-test", role="admin", csrf_token="admin-csrf")
    assert client.get("/messages").status_code == 200
    with app_module.app.app_context():
        delivered = app_module.db().execute("SELECT delivered_at FROM messages").fetchone()
        assert delivered["delivered_at"] is not None
    conversation = client.get(f"/messages/{student_id}")
    assert conversation.status_code == 200 and b"Assalamu alaikum" in conversation.data
    with app_module.app.app_context():
        read = app_module.db().execute("SELECT is_read, read_at FROM messages").fetchone()
        assert read["is_read"] == 1 and read["read_at"] is not None


def test_settings_persist_theme_and_privacy_preferences(client):
    with app_module.app.app_context():
        admin_id = app_module.db().execute("SELECT id FROM users WHERE username='admin-test'").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=admin_id, username="admin-test", role="admin", csrf_token="settings-csrf")
    assert client.get("/settings").status_code == 200
    response = client.post("/settings", data={"csrf_token": "settings-csrf", "theme": "dark", "message_notifications": "on", "display_name": "Test Admin"})
    assert response.status_code == 302
    with app_module.app.app_context():
        prefs = app_module.db().execute("SELECT theme, message_notifications, read_receipts FROM user_preferences WHERE user_id=?", (admin_id,)).fetchone()
        assert prefs["theme"] == "dark" and prefs["message_notifications"] == 1 and prefs["read_receipts"] == 0


def test_staff_cannot_message_unrelated_student(client):
    with app_module.app.app_context():
        conn = app_module.db()
        staff_id = conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("staff-private", generate_password_hash("staff password 123"), "staff", "Private Staff")).lastrowid
        unrelated_id = conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("unrelated-student", generate_password_hash("student password 123"), "student", "Unrelated Student")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=staff_id, username="staff-private", role="staff", csrf_token="staff-csrf")
    response = client.post("/messages/send", data={"csrf_token": "staff-csrf", "recipient_id": str(unrelated_id), "body": "Hello"})
    assert response.status_code == 403
