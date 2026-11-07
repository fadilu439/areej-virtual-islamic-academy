import datetime
import hmac
import io
import os
import secrets
import sqlite3
import zipfile
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, send_from_directory, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("AREEJ_DATA_DIR", BASE))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = Path(os.environ.get("AREEJ_DB_PATH", DATA_DIR / "areej_academy.db"))
UPLOAD_FOLDER = DATA_DIR / "uploads" / "payment-proofs"
MESSAGE_FOLDER = DATA_DIR / "uploads" / "messages"
UPLOAD_FOLDER.mkdir(parents=True, exist_ok=True)
MESSAGE_FOLDER.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
app.secret_key = os.environ.get("AREEJ_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("AREEJ_COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)

@app.before_request
def csrf_guard():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        if not submitted or not hmac.compare_digest(session["csrf_token"], submitted):
            abort(403)

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL,
      display_name TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS courses (
      id INTEGER PRIMARY KEY, name TEXT NOT NULL,
      description TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS enrollments (
      id INTEGER PRIMARY KEY, student_name TEXT NOT NULL, age TEXT,
      programme TEXT NOT NULL, guardian_name TEXT, contact TEXT,
      location TEXT, payment_proof TEXT, status TEXT DEFAULT 'Pending review',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY, sender_id INTEGER NOT NULL, recipient_id INTEGER NOT NULL,
      body TEXT DEFAULT '', is_read INTEGER DEFAULT 0, attachment_name TEXT DEFAULT '',
      attachment_path TEXT DEFAULT '', attachment_type TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(sender_id) REFERENCES users(id), FOREIGN KEY(recipient_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY, course_id INTEGER, teacher_id INTEGER, name TEXT NOT NULL,
      description TEXT DEFAULT '', schedule TEXT DEFAULT '', meeting_url TEXT DEFAULT '',
      channel TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS enrollments_academic (
      id INTEGER PRIMARY KEY, student_id INTEGER NOT NULL, class_id INTEGER NOT NULL,
      enrolled_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(student_id,class_id)
    );
    CREATE TABLE IF NOT EXISTS attendance (
      id INTEGER PRIMARY KEY, class_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
      lesson_date TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'present',
      recorded_by INTEGER, UNIQUE(class_id,student_id,lesson_date)
    );
    CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY, class_id INTEGER NOT NULL, title TEXT NOT NULL,
      instructions TEXT DEFAULT '', due_date TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS assignment_submissions (
      id INTEGER PRIMARY KEY, assignment_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
      content TEXT DEFAULT '', file_name TEXT DEFAULT '', file_path TEXT DEFAULT '',
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(assignment_id,student_id)
    );
    CREATE TABLE IF NOT EXISTS results (
      id INTEGER PRIMARY KEY, class_id INTEGER NOT NULL, student_id INTEGER NOT NULL,
      assessment TEXT NOT NULL, score REAL NOT NULL, maximum_score REAL DEFAULT 100,
      feedback TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS learning_materials (
      id INTEGER PRIMARY KEY, class_id INTEGER NOT NULL, title TEXT NOT NULL,
      file_name TEXT DEFAULT '', file_path TEXT DEFAULT '', url TEXT DEFAULT '', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS announcements (
      id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
      audience TEXT DEFAULT 'all', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS parent_links (
      parent_id INTEGER NOT NULL, student_id INTEGER NOT NULL, PRIMARY KEY(parent_id,student_id)
    );
    """)
    message_columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
    for column, definition in {
        "is_read": "INTEGER DEFAULT 0", "attachment_name": "TEXT DEFAULT ''",
        "attachment_path": "TEXT DEFAULT ''", "attachment_type": "TEXT DEFAULT ''"
    }.items():
        if column not in message_columns:
            conn.execute(f"ALTER TABLE messages ADD COLUMN {column} {definition}")
    demos = [
      ("admin","Admin123!","admin","Academy Administrator"),
      ("staff","Staff123!","staff","Staff Member"),
      ("student","Student123!","student","Student Account"),
      ("parent","Parent123!","parent","Parent Account")
    ]
    for username,password,role,name in demos:
        if not conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
            conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
                         (username,generate_password_hash(password),role,name))
    conn.commit(); conn.close()

init_db()

@app.context_processor
def context_user():
    unread_count = 0
    if session.get("user_id"):
        unread_count = db().execute(
            "SELECT COUNT(*) AS n FROM messages WHERE recipient_id=? AND is_read=0",
            (session["user_id"],),
        ).fetchone()["n"]
    return {
        "csrf_token": session.get("csrf_token", ""),
        "unread_message_count": unread_count,
        "current_user_id": session.get("user_id"),
        "current_user": {
            "username": session.get("username", ""),
            "display_name": session.get("display_name", "User"),
            "role": session.get("role", "")
        }
    }

def roles(*allowed):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if "user_id" not in session: return redirect(url_for("login"))
            if session.get("role") not in allowed: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

@app.route("/")
def index():
    return render_template("home.html", year=datetime.datetime.now().year)

@app.route("/health")
def health():
    return {"status": "ok", "service": "Areej Virtual Islamic Academy"}

@app.route("/robots.txt")
def robots():
    return ("User-agent: *\nAllow: /\nSitemap: https://areejacademy.com/sitemap.xml\n", 200, {"Content-Type": "text/plain"})

@app.route("/sitemap.xml")
def sitemap():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://areejacademy.com/</loc><changefreq>weekly</changefreq><priority>1.0</priority></url>
  <url><loc>https://areejacademy.com/login</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>
</urlset>"""
    return xml, 200, {"Content-Type": "application/xml"}

@app.route("/admin/backup/download")
@roles("admin")
def download_backup():
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as archive:
        if DB_PATH.exists():
            archive.write(DB_PATH, "areej_academy.db")
        for directory in (UPLOAD_FOLDER, MESSAGE_FOLDER):
            if directory.exists():
                for file_path in directory.rglob("*"):
                    if file_path.is_file():
                        archive.write(file_path, file_path.relative_to(DATA_DIR).as_posix())
    memory_file.seek(0)
    filename = f"areej-backup-{datetime.datetime.now(datetime.UTC).strftime('%Y-%m-%d')}.zip"
    return send_file(memory_file, mimetype="application/zip", as_attachment=True, download_name=filename)

@app.route("/admissions/enquire", methods=["POST"])
def admission_enquiry():
    student_name = request.form.get("student_name", "").strip()
    programme = request.form.get("programme", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    contact = phone or request.form.get("contact", "").strip()
    if email:
        contact = f"{contact} / {email}" if contact else email

    if not student_name or not programme or not contact:
        flash("Please complete the required student, programme and contact fields.", "error")
        return redirect(url_for("index", _anchor="admissions"))

    proof_name = ""
    proof = request.files.get("payment_proof")
    if proof and proof.filename:
        allowed_extensions = {"jpg", "jpeg", "png", "pdf"}
        extension = secure_filename(proof.filename).rsplit(".", 1)[-1].lower()
        if extension not in allowed_extensions:
            flash("Payment proof must be a JPG, PNG or PDF file.", "error")
            return redirect(url_for("index", _anchor="admissions"))
        proof_name = secure_filename(f"{secrets.token_hex(12)}_{proof.filename}")
        proof.save(UPLOAD_FOLDER / proof_name)

    db().execute("""INSERT INTO enrollments
        (student_name, age, programme, guardian_name, contact, location, payment_proof)
        VALUES (?, ?, ?, ?, ?, ?, ?)""", (
        student_name,
        request.form.get("age", "").strip(),
        programme,
        request.form.get("guardian_name", "").strip(),
        contact,
        request.form.get("location", "").strip(),
        proof_name,
    ))
    db().commit()
    if proof_name:
        flash("Your enrollment enquiry and payment proof were submitted successfully.", "success")
    else:
        flash("Your enrollment enquiry was submitted successfully. You may upload payment proof later.", "success")
    return redirect(url_for("index", _anchor="admissions"))

@app.route("/login", methods=["GET","POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("portal_home"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = db().execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.update(
                user_id=user["id"],
                username=user["username"],
                display_name=user["display_name"],
                role=user["role"],
                csrf_token=secrets.token_hex(32),
            )
            return redirect(url_for("portal_home"))
        flash("The username or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/portal")
@roles("admin","staff","student","parent")
def portal_home():
    endpoints = {"admin":"admin_dashboard","staff":"staff_dashboard",
                 "student":"student_dashboard","parent":"parent_dashboard"}
    return redirect(url_for(endpoints[session["role"]]))

def portal_contacts(conn, role):
    return conn.execute(
        "SELECT id, display_name, role FROM users WHERE id != ? ORDER BY role, display_name",
        (session["user_id"],),
    ).fetchall()

@app.route("/messages/open")
@roles("admin","staff","student","parent")
def open_messages():
    db().execute("UPDATE messages SET is_read=1 WHERE recipient_id=? AND is_read=0", (session["user_id"],))
    db().commit()
    dashboard = {"admin":"admin_dashboard", "staff":"staff_dashboard", "student":"student_dashboard", "parent":"parent_dashboard"}[session["role"]]
    return redirect(url_for(dashboard, _anchor="messages"))

@app.route("/messages/send", methods=["POST"])
@roles("admin","staff","student","parent")
def send_message():
    recipient_id = request.form.get("recipient_id", "")
    body = request.form.get("body", "").strip()
    recipient = db().execute("SELECT id FROM users WHERE id=?", (recipient_id,)).fetchone()
    upload = request.files.get("attachment")
    attachment_name = attachment_path = attachment_type = ""
    allowed_types = ("image/jpeg", "image/png", "image/webp", "application/pdf", "text/plain",
                     "application/msword", "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                     "audio/webm", "audio/ogg", "audio/mpeg")
    if upload and upload.filename:
        if upload.content_type not in allowed_types:
            flash("That attachment type is not allowed.", "error")
            return redirect(request.referrer or url_for("portal") )
        attachment_name = secure_filename(upload.filename)
        if not attachment_name: attachment_name = "attachment"
        unique_name = f"{secrets.token_hex(12)}_{attachment_name}"
        upload.save(MESSAGE_FOLDER / unique_name)
        attachment_path, attachment_type = unique_name, upload.content_type
    if not recipient or (not body and not attachment_path):
        flash("Choose a recipient and add a message or attachment.", "error")
    else:
        db().execute("INSERT INTO messages(sender_id,recipient_id,body,attachment_name,attachment_path,attachment_type) VALUES(?,?,?,?,?,?)",
                     (session["user_id"], recipient["id"], body, attachment_name, attachment_path, attachment_type))
        db().commit()
        flash("Message sent successfully.", "success")
    dashboard = {"admin":"admin_dashboard", "staff":"staff_dashboard", "student":"student_dashboard", "parent":"parent_dashboard"}[session["role"]]
    return redirect(url_for(dashboard, _anchor="messages"))

@app.route("/messages/attachment/<path:filename>")
@roles("admin","staff","student","parent")
def message_attachment(filename):
    permitted = db().execute("SELECT id FROM messages WHERE attachment_path=? AND (sender_id=? OR recipient_id=?)",
                             (filename, session["user_id"], session["user_id"])).fetchone()
    if not permitted: abort(403)
    return send_from_directory(MESSAGE_FOLDER, filename, as_attachment=True)

@app.route("/student")
@roles("student")
def student_dashboard():
    conn = db()
    courses = conn.execute("SELECT DISTINCT c.* FROM courses c JOIN classes cl ON cl.course_id=c.id JOIN enrollments_academic ea ON ea.class_id=cl.id WHERE ea.student_id=? ORDER BY c.name", (session["user_id"],)).fetchall()
    if not courses: courses = conn.execute("SELECT * FROM courses ORDER BY name LIMIT 20").fetchall()
    classes = conn.execute("SELECT cl.* FROM classes cl JOIN enrollments_academic ea ON ea.class_id=cl.id WHERE ea.student_id=? ORDER BY cl.schedule", (session["user_id"],)).fetchall()
    assignments = conn.execute("SELECT a.*, cl.name AS class_name FROM assignments a JOIN classes cl ON cl.id=a.class_id JOIN enrollments_academic ea ON ea.class_id=cl.id WHERE ea.student_id=? ORDER BY a.due_date", (session["user_id"],)).fetchall()
    results = conn.execute("SELECT * FROM results WHERE student_id=? ORDER BY created_at DESC", (session["user_id"],)).fetchall()
    attendance_count = conn.execute("SELECT COUNT(*) n FROM attendance WHERE student_id=? AND status='present'", (session["user_id"],)).fetchone()["n"]
    messages = conn.execute("SELECT m.*, u.display_name AS sender_name, u.role AS sender_role, r.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.created_at ASC LIMIT 50", (session["user_id"], session["user_id"])).fetchall()
    return render_template("student.html", courses=courses, classes=classes, assignments=assignments,
                           results=results, attendance_count=attendance_count, portal_messages=messages,
                           recipients=portal_contacts(conn, "student"))

@app.route("/parent")
@roles("parent")
def parent_dashboard():
    conn=db(); messages=conn.execute("SELECT m.*, u.display_name AS sender_name, u.role AS sender_role, r.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.created_at ASC LIMIT 50", (session["user_id"], session["user_id"])).fetchall()
    children = conn.execute("SELECT u.* FROM users u JOIN parent_links p ON p.student_id=u.id WHERE p.parent_id=? ORDER BY u.display_name", (session["user_id"],)).fetchall()
    child_results = []
    if children:
        placeholders = ",".join("?" for _ in children)
        child_results = conn.execute(f"SELECT r.*, u.display_name AS student_name FROM results r JOIN users u ON u.id=r.student_id WHERE r.student_id IN ({placeholders}) ORDER BY r.created_at DESC", [c["id"] for c in children]).fetchall()
    return render_template("parent.html", children=children, child_results=child_results,
                           portal_messages=messages, recipients=portal_contacts(conn, "parent"))

@app.route("/staff")
@roles("staff")
def staff_dashboard():
    conn=db(); messages=conn.execute("SELECT m.*, u.display_name AS sender_name, u.role AS sender_role, r.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.created_at ASC LIMIT 50", (session["user_id"], session["user_id"])).fetchall()
    classes = conn.execute("SELECT * FROM classes WHERE teacher_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    courses = conn.execute("SELECT * FROM courses ORDER BY name").fetchall()
    students = conn.execute("SELECT id,display_name FROM users WHERE role='student' ORDER BY display_name").fetchall()
    assignments = conn.execute("SELECT a.*, cl.name AS class_name FROM assignments a JOIN classes cl ON cl.id=a.class_id WHERE cl.teacher_id=? ORDER BY a.created_at DESC", (session["user_id"],)).fetchall()
    return render_template("staff.html", classes=classes, courses=courses, students=students,
                           assignments=assignments, portal_messages=messages,
                           recipients=portal_contacts(conn, "staff"))

@app.route("/admin", methods=["GET","POST"])
@roles("admin")
def admin_dashboard():
    conn = db()
    if request.method == "POST":
        action = request.form.get("action", "add_course")
        account_actions = {"add_student": ("student", "student_name", "student_username", "student_password", "Student", "students"),
                           "add_staff": ("staff", "staff_name", "staff_username", "staff_password", "Staff member", "staff"),
                           "add_parent": ("parent", "parent_name", "parent_username", "parent_password", "Parent", "parents")}
        if action in account_actions:
            role, name_field, username_field, password_field, label, anchor = account_actions[action]
            display_name = request.form.get(name_field, "").strip()
            username = request.form.get(username_field, "").strip().lower()
            password = request.form.get(password_field, "")
            if not display_name or not username or not password:
                flash(f"Please enter the {label.lower()} name, username and password.", "error")
            elif len(password) < 6:
                flash("The password must contain at least 6 characters.", "error")
            elif conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                flash("That username is already in use. Please choose another one.", "error")
            else:
                conn.execute("INSERT INTO users(username,password_hash,role,display_name) VALUES(?,?,?,?)",
                             (username, generate_password_hash(password), role, display_name))
                conn.commit()
                flash(f"{label} account created for {display_name}. Username: {username}", "success")
            return redirect(url_for("admin_dashboard", _anchor=anchor))

        name = request.form.get("name","").strip()
        description = request.form.get("description","").strip()
        if not name: flash("Please enter a course name.", "error")
        else:
            conn.execute("INSERT INTO courses(name,description) VALUES(?,?)",(name,description))
            conn.commit(); flash("Course added successfully.", "success")
            return redirect(url_for("admin_dashboard"))
    courses = conn.execute("SELECT * FROM courses ORDER BY id DESC").fetchall()
    course_count = conn.execute("SELECT COUNT(*) AS n FROM courses").fetchone()["n"]
    enrollment_count = conn.execute("SELECT COUNT(*) AS n FROM enrollments").fetchone()["n"]
    pending_enrollments = conn.execute(
        "SELECT COUNT(*) AS n FROM enrollments WHERE status = 'Pending review'"
    ).fetchone()["n"]
    enrollments = conn.execute("SELECT * FROM enrollments ORDER BY created_at DESC LIMIT 6").fetchall()
    user_counts = {r["role"]:r["n"] for r in conn.execute(
        "SELECT role, COUNT(*) AS n FROM users GROUP BY role").fetchall()}
    students = conn.execute("SELECT id, username, display_name FROM users WHERE role='student' ORDER BY display_name").fetchall()
    staff_accounts = conn.execute("SELECT id, username, display_name FROM users WHERE role='staff' ORDER BY display_name").fetchall()
    parent_accounts = conn.execute("SELECT id, username, display_name FROM users WHERE role='parent' ORDER BY display_name").fetchall()
    portal_messages = conn.execute("SELECT m.*, u.display_name AS sender_name, u.role AS sender_role, r.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.created_at ASC LIMIT 50", (session["user_id"], session["user_id"])).fetchall()
    classes = conn.execute("SELECT cl.*, u.display_name AS teacher_name FROM classes cl LEFT JOIN users u ON u.id=cl.teacher_id ORDER BY cl.id DESC").fetchall()
    return render_template("admin.html", courses=courses, course_count=course_count,
                           enrollment_count=enrollment_count, pending_enrollments=pending_enrollments,
                           enrollments=enrollments, user_counts=user_counts, students=students,
                           staff_accounts=staff_accounts, parent_accounts=parent_accounts, classes=classes,
                           portal_messages=portal_messages, recipients=portal_contacts(conn, "admin"))

@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
@roles("admin")
def delete_course(course_id):
    db().execute("DELETE FROM courses WHERE id=?", (course_id,)); db().commit()
    flash("Course deleted if it existed.", "success")
    return redirect(url_for("admin_dashboard"))

@app.route("/staff/work", methods=["POST"])
@roles("staff")
def staff_work():
    conn = db(); action = request.form.get("action")
    if action == "create_class":
        conn.execute("INSERT INTO classes(course_id,teacher_id,name,description,schedule,meeting_url,channel) VALUES(?,?,?,?,?,?,?)",
                     (request.form.get("course_id") or None, session["user_id"], request.form.get("name","").strip(),
                      request.form.get("description","").strip(), request.form.get("schedule","").strip(),
                      request.form.get("meeting_url","").strip(), request.form.get("channel","General")))
        conn.commit(); flash("Class and channel created.", "success")
    elif action == "create_assignment":
        conn.execute("INSERT INTO assignments(class_id,title,instructions,due_date) VALUES(?,?,?,?)",
                     (request.form.get("class_id"), request.form.get("title","").strip(),
                      request.form.get("instructions","").strip(), request.form.get("due_date","")))
        conn.commit(); flash("Assignment published.", "success")
    elif action == "record_attendance":
        class_id, student_id = request.form.get("class_id"), request.form.get("student_id")
        if class_id and student_id:
            conn.execute("INSERT OR REPLACE INTO attendance(class_id,student_id,lesson_date,status,recorded_by) VALUES(?,?,?,?,?)",
                         (class_id, student_id, request.form.get("lesson_date") or datetime.date.today().isoformat(),
                          request.form.get("status","present"), session["user_id"]))
            conn.commit(); flash("Attendance recorded.", "success")
    elif action == "record_result":
        conn.execute("INSERT INTO results(class_id,student_id,assessment,score,maximum_score,feedback) VALUES(?,?,?,?,?,?)",
                     (request.form.get("class_id"), request.form.get("student_id"), request.form.get("assessment","").strip(),
                      request.form.get("score",0), request.form.get("maximum_score",100), request.form.get("feedback","").strip()))
        conn.commit(); flash("Result saved.", "success")
    return redirect(url_for("staff_dashboard", _anchor="classes"))

@app.route("/student/submit", methods=["POST"])
@roles("student")
def submit_assignment():
    assignment_id = request.form.get("assignment_id")
    content = request.form.get("content", "").strip()
    upload = request.files.get("submission_file")
    file_name = file_path = ""
    if upload and upload.filename:
        file_name = secure_filename(upload.filename)
        file_path = f"{secrets.token_hex(12)}_{file_name}"; upload.save(MESSAGE_FOLDER / file_path)
    db().execute("INSERT OR REPLACE INTO assignment_submissions(assignment_id,student_id,content,file_name,file_path) VALUES(?,?,?,?,?)",
                 (assignment_id, session["user_id"], content, file_name, file_path))
    db().commit(); flash("Assignment submitted successfully.", "success")
    return redirect(url_for("student_dashboard", _anchor="assignments"))

@app.route("/admin/link", methods=["POST"])
@roles("admin")
def admin_link_student():
    conn = db(); action = request.form.get("action")
    if action == "link_parent":
        conn.execute("INSERT OR IGNORE INTO parent_links(parent_id,student_id) VALUES(?,?)",
                     (request.form.get("parent_id"), request.form.get("student_id")))
        conn.commit(); flash("Parent and student linked.", "success")
    elif action == "approve_enrollment":
        conn.execute("UPDATE enrollments SET status=? WHERE id=?", (request.form.get("status","Approved"), request.form.get("enrollment_id")))
        conn.commit(); flash("Admission status updated.", "success")
    elif action == "enroll_student":
        conn.execute("INSERT OR IGNORE INTO enrollments_academic(student_id,class_id) VALUES(?,?)",
                     (request.form.get("student_id"), request.form.get("class_id")))
        conn.commit(); flash("Student enrolled in class.", "success")
    return redirect(url_for("admin_dashboard", _anchor="admissions"))

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.errorhandler(403)
def forbidden(error): return render_template("error.html", code=403, message="You do not have permission to view this page."), 403
@app.errorhandler(404)
def missing(error): return render_template("error.html", code=404, message="This page could not be found."), 404

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
