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
            "payments", "invoices", "finance_settings", "message_history", "academic_reports", "assignment_submissions", "attendance", "results", "assignments",
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


def test_login_post_with_missing_csrf_refreshes_login_form(client):
    response = client.post("/login", data={"username": "admin-test", "password": "wrong"})
    assert response.status_code == 302
    refreshed = client.get("/login")
    assert refreshed.status_code == 200
    assert b"Your sign-in page expired" in refreshed.data
    with client.session_transaction() as session:
        assert "user_id" not in session
        assert session.get("csrf_token")


def test_login_post_with_stale_csrf_refreshes_login_form(client):
    old_token = csrf_token(client)
    with client.session_transaction() as session:
        session["csrf_token"] = "rotated-by-another-tab"
    response = client.post(
        "/login",
        data={"csrf_token": old_token, "username": "admin-test", "password": "wrong"},
    )
    assert response.status_code == 302
    refreshed = client.get("/login")
    assert refreshed.status_code == 200
    assert b"Your sign-in page expired" in refreshed.data


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
            "student_age": "8", "gender": "Female", "country": "Nigeria", "state": "Kano", "programme": "Islamic Studies",
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
            "student_age": "8", "gender": "Female", "country": "Nigeria", "state": "Kano", "programme": "Islamic Studies",
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


def test_staff_can_submit_report_only_for_owned_class(client):
    with app_module.app.app_context():
        conn = app_module.db()
        staff_id = conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("report-teacher", generate_password_hash("teacher password 123"), "staff", "Report Teacher"),
        ).lastrowid
        other_staff_id = conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("other-teacher", generate_password_hash("teacher password 123"), "staff", "Other Teacher"),
        ).lastrowid
        owned_class = conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)", (staff_id, "Owned Class")).lastrowid
        foreign_class = conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)", (other_staff_id, "Other Class")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=staff_id, username="report-teacher", role="staff", csrf_token="report-csrf")
    good = client.post("/staff/reports/create", data={
        "csrf_token":"report-csrf","report_type":"daily","class_id":str(owned_class),
        "report_date":"2026-11-23","topic":"Tajweed lesson","duration_minutes":"40",
        "attendance_count":"5","progress_notes":"Students practised articulation.",
        "submit_action":"submit",
    })
    assert good.status_code == 302
    with app_module.app.app_context():
        assert app_module.db().execute("SELECT COUNT(*) AS n FROM academic_reports WHERE staff_id=?", (staff_id,)).fetchone()["n"] == 1
    denied = client.post("/staff/reports/create", data={
        "csrf_token":"report-csrf","report_type":"daily","class_id":str(foreign_class),
        "report_date":"2026-11-23","topic":"Unauthorized","duration_minutes":"40",
        "attendance_count":"0","submit_action":"submit",
    })
    assert denied.status_code == 403


def test_student_cannot_open_staff_or_admin_report_workspaces(client):
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")
    assert client.get("/staff/reports").status_code == 403
    assert client.get("/admin/reports").status_code == 403


def test_admin_can_review_submitted_academic_report(client):
    with app_module.app.app_context():
        conn = app_module.db()
        staff_id = conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("review-teacher", generate_password_hash("teacher password 123"), "staff", "Review Teacher"),
        ).lastrowid
        class_id = conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)", (staff_id, "Review Class")).lastrowid
        report_id = conn.execute("""INSERT INTO academic_reports
            (report_type,class_id,staff_id,report_date,topic,status)
            VALUES('daily',?,?,?,'Lesson','submitted')""", (class_id,staff_id,"2026-11-23")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="admin-review-csrf")
    response = client.post(f"/admin/reports/{report_id}/review", data={
        "csrf_token":"admin-review-csrf","decision":"approved","review_note":"Reviewed and approved."
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        report = app_module.db().execute("SELECT status,reviewer_id,review_note FROM academic_reports WHERE id=?", (report_id,)).fetchone()
        assert report["status"] == "approved"
        assert report["reviewer_id"] == 1
        assert report["review_note"] == "Reviewed and approved."


def test_student_learning_centre_shows_only_enrolled_class_resources(client):
    with app_module.app.app_context():
        conn = app_module.db()
        student_id = conn.execute("SELECT id FROM users WHERE username=?", ("student-test",)).fetchone()["id"]
        course_id = conn.execute("INSERT INTO courses(name,description) VALUES(?,?)", ("Arabic", "Arabic course")).lastrowid
        own_class = conn.execute("INSERT INTO classes(course_id,name) VALUES(?,?)", (course_id,"Enrolled Arabic")).lastrowid
        private_class = conn.execute("INSERT INTO classes(name) VALUES(?)", ("Not Enrolled",)).lastrowid
        conn.execute("INSERT INTO enrollments_academic(student_id,class_id) VALUES(?,?)", (student_id,own_class))
        conn.execute("INSERT INTO learning_materials(class_id,title,url) VALUES(?,?,?)", (own_class,"Arabic Notes","https://example.com/notes"))
        conn.execute("INSERT INTO learning_materials(class_id,title,url) VALUES(?,?,?)", (private_class,"Private Notes","https://example.com/private"))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=2,username="student-test",role="student",csrf_token="student-learning")
    response=client.get("/student/learning")
    assert response.status_code==200
    assert b"Enrolled Arabic" in response.data
    assert b"Arabic Notes" in response.data
    assert b"Not Enrolled" not in response.data
    assert b"Private Notes" not in response.data


def test_parent_can_only_view_linked_child_progress(client):
    with app_module.app.app_context():
        conn=app_module.db()
        parent_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("parent-test",generate_password_hash("parent password 123"),"parent","Test Parent")).lastrowid
        child_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("child-test",generate_password_hash("child password 123"),"student","Linked Child")).lastrowid
        other_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("other-child",generate_password_hash("child password 123"),"student","Other Child")).lastrowid
        conn.execute("INSERT INTO parent_links(parent_id,student_id) VALUES(?,?)",(parent_id,child_id))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=parent_id,username="parent-test",role="parent",csrf_token="parent-progress")
    allowed=client.get(f"/parent/children/{child_id}/progress")
    denied=client.get(f"/parent/children/{other_id}/progress")
    assert allowed.status_code==200
    assert b"Linked Child" in allowed.data
    assert denied.status_code==404


def test_finance_starts_disabled_and_admin_controls_private_invoices(client):
    with app_module.app.app_context():
        conn=app_module.db()
        student_id=conn.execute("SELECT id FROM users WHERE username=?",("student-test",)).fetchone()["id"]
        assert conn.execute("SELECT COUNT(*) AS n FROM invoices").fetchone()["n"]==0
    with client.session_transaction() as session:
        session.update(user_id=1,username="admin-test",role="admin",csrf_token="finance-admin")
    disabled=client.post("/admin/finance/invoices/create",data={
        "csrf_token":"finance-admin","student_id":str(student_id),"title":"Course invoice","amount":"100"
    })
    assert disabled.status_code==302
    with app_module.app.app_context():
        assert app_module.db().execute("SELECT COUNT(*) AS n FROM invoices").fetchone()["n"]==0
    client.post("/admin/finance/settings",data={
        "csrf_token":"finance-admin","currency":"NGN","fees_enabled":"1"
    })
    enabled=client.post("/admin/finance/invoices/create",data={
        "csrf_token":"finance-admin","student_id":str(student_id),"title":"Private course invoice",
        "description":"Issued privately","amount":"25000","due_date":"2026-12-01"
    })
    assert enabled.status_code==302
    with app_module.app.app_context():
        invoice=app_module.db().execute("SELECT amount,currency,status FROM invoices").fetchone()
        assert invoice["amount"]==25000
        assert invoice["currency"]=="NGN"
        assert invoice["status"]=="unpaid"


def test_student_finance_view_is_limited_to_own_invoices_and_parent_to_linked_children(client):
    with app_module.app.app_context():
        conn=app_module.db()
        student_id=conn.execute("SELECT id FROM users WHERE username=?",("student-test",)).fetchone()["id"]
        other_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("finance-other",generate_password_hash("other password 123"),"student","Other Finance Student")).lastrowid
        parent_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("finance-parent",generate_password_hash("parent password 123"),"parent","Finance Parent")).lastrowid
        conn.execute("INSERT INTO parent_links(parent_id,student_id) VALUES(?,?)",(parent_id,student_id))
        conn.execute("INSERT INTO invoices(student_id,title,amount,currency,created_by) VALUES(?,?,?,?,?)",
            (student_id,"Linked Invoice",1000,"NGN",1))
        conn.execute("INSERT INTO invoices(student_id,title,amount,currency,created_by) VALUES(?,?,?,?,?)",
            (other_id,"Private Invoice",2000,"NGN",1))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=student_id,username="student-test",role="student",csrf_token="finance-student")
    student_page=client.get("/finance")
    assert b"Linked Invoice" in student_page.data
    assert b"Private Invoice" not in student_page.data
    with client.session_transaction() as session:
        session.update(user_id=parent_id,username="finance-parent",role="parent",csrf_token="finance-parent")
    parent_page=client.get("/finance")
    assert b"Linked Invoice" in parent_page.data
    assert b"Private Invoice" not in parent_page.data


def test_manual_payment_proof_requires_admin_confirmation_before_receipt(client):
    from io import BytesIO
    with app_module.app.app_context():
        conn=app_module.db()
        student_id=conn.execute("SELECT id FROM users WHERE username=?",("student-test",)).fetchone()["id"]
        conn.execute("INSERT INTO finance_settings(id,currency,fees_enabled) VALUES(1,'NGN',1)")
        invoice_id=conn.execute("INSERT INTO invoices(student_id,title,amount,currency,created_by) VALUES(?,?,?,?,?)",
            (student_id,"Installment invoice",5000,"NGN",1)).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=student_id,username="student-test",role="student",csrf_token="student-payment")
    proof=b"\x89PNG\r\n\x1a\n"+"valid test image".encode()
    submitted=client.post(f"/finance/invoices/{invoice_id}/pay",data={
        "csrf_token":"student-payment","amount":"2000","reference":"BANK-REF-001",
        "payment_proof":(BytesIO(proof),"proof.png")
    },content_type="multipart/form-data")
    assert submitted.status_code==302
    with app_module.app.app_context():
        payment=app_module.db().execute("SELECT id,status,receipt_number FROM payments WHERE invoice_id=?",(invoice_id,)).fetchone()
        assert payment["status"]=="pending"
        assert payment["receipt_number"] is None
    with client.session_transaction() as session:
        session.update(user_id=1,username="admin-test",role="admin",csrf_token="admin-payment")
    reviewed=client.post(f"/admin/finance/payments/{payment['id']}/review",data={
        "csrf_token":"admin-payment","decision":"confirmed"
    })
    assert reviewed.status_code==302
    with app_module.app.app_context():
        payment=app_module.db().execute("SELECT status,receipt_number FROM payments WHERE id=?",(payment["id"],)).fetchone()
        invoice=app_module.db().execute("SELECT status FROM invoices WHERE id=?",(invoice_id,)).fetchone()
        assert payment["status"]=="confirmed"
        assert payment["receipt_number"].startswith("AREEJ-")
        assert invoice["status"]=="partial"


def test_parent_cannot_submit_payment_for_unlinked_student_invoice(client):
    with app_module.app.app_context():
        conn=app_module.db()
        other_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("unlinked-invoice",generate_password_hash("other password 123"),"student","Unlinked Student")).lastrowid
        invoice_id=conn.execute("INSERT INTO invoices(student_id,title,amount,currency,created_by) VALUES(?,?,?,?,?)",
            (other_id,"Unlinked invoice",1000,"NGN",1)).lastrowid
        parent_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("unlinked-parent",generate_password_hash("parent password 123"),"parent","Unlinked Parent")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=parent_id,username="unlinked-parent",role="parent",csrf_token="parent-pay")
    response=client.post(f"/finance/invoices/{invoice_id}/pay",data={"csrf_token":"parent-pay","amount":"100"})
    assert response.status_code==404


def test_staff_can_grade_only_submissions_from_owned_classes(client):
    with app_module.app.app_context():
        conn=app_module.db()
        staff_id=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("marker-teacher",generate_password_hash("teacher password 123"),"staff","Marker Teacher")).lastrowid
        other_staff=conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("other-marker",generate_password_hash("teacher password 123"),"staff","Other Marker")).lastrowid
        student_id=conn.execute("SELECT id FROM users WHERE username=?",("student-test",)).fetchone()["id"]
        own_class=conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)",(staff_id,"Marking Class")).lastrowid
        foreign_class=conn.execute("INSERT INTO classes(teacher_id,name) VALUES(?,?)",(other_staff,"Foreign Class")).lastrowid
        own_assignment=conn.execute("INSERT INTO assignments(class_id,title) VALUES(?,?)",(own_class,"Own Assignment")).lastrowid
        foreign_assignment=conn.execute("INSERT INTO assignments(class_id,title) VALUES(?,?)",(foreign_class,"Foreign Assignment")).lastrowid
        own_submission=conn.execute("INSERT INTO assignment_submissions(assignment_id,student_id,content) VALUES(?,?,?)",(own_assignment,student_id,"My answer")).lastrowid
        foreign_submission=conn.execute("INSERT INTO assignment_submissions(assignment_id,student_id,content) VALUES(?,?,?)",(foreign_assignment,student_id,"Private answer")).lastrowid
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=staff_id,username="marker-teacher",role="staff",csrf_token="marking-csrf")
    saved=client.post(f"/staff/submissions/{own_submission}/grade",data={
        "csrf_token":"marking-csrf","score":"8","maximum_score":"10","feedback":"Good work."
    })
    assert saved.status_code==302
    denied=client.post(f"/staff/submissions/{foreign_submission}/grade",data={
        "csrf_token":"marking-csrf","score":"8","maximum_score":"10","feedback":"Not yours."
    })
    assert denied.status_code==403
    with app_module.app.app_context():
        marked=app_module.db().execute("SELECT score,feedback,status FROM assignment_submissions WHERE id=?",(own_submission,)).fetchone()
        assert marked["score"]==8
        assert marked["feedback"]=="Good work."
        assert marked["status"]=="graded"


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



def test_settings_password_change_requires_current_password_and_updates_hash(client):
    with app_module.app.app_context():
        admin_id = app_module.db().execute("SELECT id FROM users WHERE username='admin-test'").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=admin_id, username="admin-test", role="admin", csrf_token="password-csrf")
    response = client.post("/settings", data={
        "csrf_token": "password-csrf", "display_name": "Test Admin",
        "theme": "light", "current_password": "correct horse battery staple",
        "new_password": "new-secure-password", "confirm_password": "new-secure-password",
        "message_notifications": "on", "read_receipts": "on",
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        stored = app_module.db().execute("SELECT password_hash FROM users WHERE id=?", (admin_id,)).fetchone()
        from werkzeug.security import check_password_hash
        assert check_password_hash(stored["password_hash"], "new-secure-password")


def test_disabling_read_receipts_keeps_sender_from_seeing_read_tick(client):
    with app_module.app.app_context():
        conn = app_module.db()
        admin_id = conn.execute("SELECT id FROM users WHERE username='admin-test'").fetchone()["id"]
        student_id = conn.execute("SELECT id FROM users WHERE username='student-test'").fetchone()["id"]
        conn.execute("INSERT INTO user_preferences(user_id,theme,message_notifications,read_receipts) VALUES(?,?,?,?)",
                     (admin_id, "light", 1, 0))
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)",
                     (student_id, admin_id, "Private note"))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=admin_id, username="admin-test", role="admin", csrf_token="receipt-csrf")
    response = client.get(f"/messages/{student_id}")
    assert response.status_code == 200
    with app_module.app.app_context():
        state = app_module.db().execute("SELECT is_read, read_at FROM messages").fetchone()
        assert state["is_read"] == 1 and state["read_at"] is None


def test_profile_picture_upload_is_saved_to_the_signed_in_users_own_account(client):
    from io import BytesIO
    from werkzeug.datastructures import FileStorage

    token = csrf_token(client)
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token=token)

    response = client.post(
        "/settings",
        data={
            "csrf_token": token,
            "display_name": "Test Student",
            "theme": "light",
            "profile_picture": (BytesIO(b"\x89PNG\r\n\x1a\nprofile-test"), "student.png", "image/png"),
        },
        content_type="multipart/form-data",
    )
    assert response.status_code == 302
    with app_module.app.app_context():
        user = app_module.db().execute(
            "SELECT profile_picture FROM users WHERE id=?", (2,)
        ).fetchone()
        assert user["profile_picture"]
        assert user["profile_picture"].endswith(".png")


def test_profile_picture_route_requires_authenticated_portal_user(client):
    response = client.get("/profile/avatar/2")
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_help_center_is_available_to_student_and_role_specific(client):
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")
    response = client.get("/help")
    assert response.status_code == 200
    assert b"Your Student Dashboard" in response.data
    assert b"Your Parent Dashboard" not in response.data


def test_help_center_search_filters_role_specific_articles(client):
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")
    response = client.get("/help?q=examinations")
    assert response.status_code == 200
    assert b"Assignments and examinations" in response.data
    assert b"Joining lessons" not in response.data



def test_sender_can_edit_own_message_and_history_is_preserved(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(1,2,'Original text')")
        conn.commit()
        message_id = conn.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.post(f"/messages/{message_id}/action", data={
        "csrf_token": "test-csrf", "action": "edit", "body": "Corrected text"
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        conn = app_module.db()
        assert conn.execute("SELECT body FROM messages WHERE id=?", (message_id,)).fetchone()["body"] == "Corrected text"
        history = conn.execute("SELECT action, previous_body FROM message_history WHERE message_id=?", (message_id,)).fetchone()
        assert history["action"] == "edit"
        assert history["previous_body"] == "Original text"


def test_recipient_cannot_edit_another_users_message(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(1,2,'Sender text')")
        conn.commit()
        message_id = conn.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")
    response = client.post(f"/messages/{message_id}/action", data={
        "csrf_token": "student-csrf", "action": "edit", "body": "Tampered text"
    })
    assert response.status_code == 403
    with app_module.app.app_context():
        assert app_module.db().execute("SELECT body FROM messages WHERE id=?", (message_id,)).fetchone()["body"] == "Sender text"


def test_sender_can_delete_message_for_everyone_with_audit_history(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(1,2,'Sensitive old text')")
        conn.commit()
        message_id = conn.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.post(f"/messages/{message_id}/action", data={
        "csrf_token": "test-csrf", "action": "delete_everyone"
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        conn = app_module.db()
        row = conn.execute("SELECT body, deleted_for_everyone FROM messages WHERE id=?", (message_id,)).fetchone()
        assert row["body"] == ""
        assert row["deleted_for_everyone"] in (1, True)
        history = conn.execute("SELECT action, previous_body FROM message_history WHERE message_id=?", (message_id,)).fetchone()
        assert history["action"] == "delete_for_everyone"
        assert history["previous_body"] == "Sensitive old text"


def test_user_can_hide_message_from_own_chat_only(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(1,2,'Keep for recipient')")
        conn.commit()
        message_id = conn.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.post(f"/messages/{message_id}/action", data={
        "csrf_token": "test-csrf", "action": "delete_me"
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        row = app_module.db().execute("SELECT hidden_for_sender, hidden_for_recipient FROM messages WHERE id=?", (message_id,)).fetchone()
        assert row["hidden_for_sender"] in (1, True)
        assert row["hidden_for_recipient"] in (0, False)



def test_admin_directory_search_is_paginated_and_role_scoped(client):
    with app_module.app.app_context():
        conn = app_module.db()
        for index in range(30):
            conn.execute(
                "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
                (f"directory-{index}", generate_password_hash("password 1234"), "student", f"Directory Student {index:02d}"),
            )
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    first = client.get("/admin/directory/students")
    assert first.status_code == 200
    assert b"Page 1 of 2" in first.data
    assert b"Directory Student 00" in first.data
    assert b"Directory Student 29" not in first.data
    second = client.get("/admin/directory/students?page=2")
    assert second.status_code == 200
    assert b"Directory Student 29" in second.data
    search = client.get("/admin/directory/students?q=Directory%20Student%2029")
    assert search.status_code == 200
    assert b"Directory Student 29" in search.data
    assert b"admin-test" not in search.data


def test_non_admin_cannot_open_admin_directory(client):
    with client.session_transaction() as session:
        session.update(user_id=2, username="student-test", role="student", csrf_token="student-csrf")
    assert client.get("/admin/directory/students").status_code == 403



def test_user_can_forward_visible_message_only_to_authorized_contact(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute(
            "INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
            ("second-student", generate_password_hash("second student password"), "student", "Second Student"),
        )
        second_student_id = conn.execute("SELECT id FROM users WHERE username='second-student'").fetchone()["id"]
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(2,1,'Please share this lesson note')")
        conn.commit()
        source_id = conn.execute("SELECT id FROM messages ORDER BY id DESC LIMIT 1").fetchone()["id"]
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.post(f"/messages/{source_id}/action", data={
        "csrf_token": "test-csrf", "action": "forward", "recipient_id": str(second_student_id)
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        forwarded = app_module.db().execute(
            "SELECT sender_id, recipient_id, body, forwarded_from_id FROM messages WHERE recipient_id=? ORDER BY id DESC LIMIT 1",
            (second_student_id,),
        ).fetchone()
        assert forwarded["sender_id"] == 1
        assert forwarded["body"] == "Please share this lesson note"
        assert forwarded["forwarded_from_id"] == source_id


def test_student_registration_generates_secure_account_and_saves_private_details(client):
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.post("/admin", data={
        "csrf_token": "test-csrf", "action": "add_student",
        "student_name": "Generated Learner", "student_age": "9",
        "date_of_birth": "2017-06-01", "gender": "Female",
        "country": "Nigeria", "state": "Kano", "student_phone": "08000000000",
        "student_email": "learner@example.test", "guardian_name": "Parent Name",
        "programme": "Arabic Language",
    })
    assert response.status_code == 302
    with app_module.app.app_context():
        user = app_module.db().execute("SELECT * FROM users WHERE display_name=?", ("Generated Learner",)).fetchone()
        assert user is not None
        assert user["role"] == "student"
        assert user["age"] == 9
        assert user["date_of_birth"] == "2017-06-01"
        assert user["gender"] == "Female"
        assert user["country"] == "Nigeria" and user["state"] == "Kano"
        assert user["guardian_name"] == "Parent Name"
        assert user["programme"] == "Arabic Language"
        assert user["username"]
        assert user["password_hash"] != ""
        from werkzeug.security import check_password_hash
        assert not check_password_hash(user["password_hash"], user["username"])


def test_private_profile_hides_profile_from_other_portal_users(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("UPDATE users SET profile_visibility='private', bio='Private biography', phone='08012345678' WHERE id=2")
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    assert client.get("/profile/2").status_code == 403


def test_contact_profile_shows_only_opted_in_public_fields(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("UPDATE users SET bio='Quran learner', country='Nigeria', state='Kano', show_location=1, phone='08012345678', email='private@example.test', date_of_birth='2017-01-01' WHERE id=2")
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.get("/profile/2")
    assert response.status_code == 200
    assert b"Quran learner" in response.data
    assert b"Nigeria" in response.data
    assert b"08012345678" not in response.data
    assert b"private@example.test" not in response.data
    assert b"2017-01-01" not in response.data


def test_message_search_filters_contacts_by_name_or_message_body(client):
    with app_module.app.app_context():
        conn = app_module.db()
        conn.execute("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)", (2,1,"Tajweed lesson reminder"))
        conn.commit()
    with client.session_transaction() as session:
        session.update(user_id=1, username="admin-test", role="admin", csrf_token="test-csrf")
    response = client.get("/messages?q=Tajweed")
    assert response.status_code == 200
    assert b"Test Student" in response.data
    assert b"Search" in response.data
