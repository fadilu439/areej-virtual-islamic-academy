import datetime
import hashlib
import hmac
import io
import math
import os
import secrets
import sqlite3
import zipfile
from postgres_compat import PostgresCompatConnection
from storage_backend import save_upload, read_upload
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

@app.route("/service-worker.js")
def service_worker():
    response = send_from_directory(BASE / "static", "service-worker.js", mimetype="application/javascript", max_age=0)
    response.headers["Service-Worker-Allowed"] = "/"
    response.headers["Cache-Control"] = "no-cache"
    return response

def configured_secret_key():
    """Require a stable secret on Render; allow an ephemeral key for local development."""
    configured = os.environ.get("AREEJ_SECRET_KEY", "").strip()
    if not configured and os.environ.get("RENDER", "").lower() == "true":
        raise RuntimeError("AREEJ_SECRET_KEY must be configured on Render before the app can start.")
    return configured or secrets.token_hex(32)

app.secret_key = configured_secret_key()
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

def valid_upload_signature(upload, extension):
    """Check basic file signatures instead of trusting the browser MIME type."""
    header = upload.stream.read(16)
    upload.stream.seek(0)
    signatures = {
        "jpg": header.startswith(b"\xff\xd8\xff"),
        "jpeg": header.startswith(b"\xff\xd8\xff"),
        "png": header.startswith(b"\x89PNG\r\n\x1a\n"),
        "pdf": header.startswith(b"%PDF-"),
        "webp": len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP",
        "ogg": header.startswith(b"OggS"),
        "mp3": header.startswith(b"ID3") or (len(header) >= 2 and header[0] == 0xFF and (header[1] & 0xE0) == 0xE0),
        "wav": len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WAVE",
        "webm": header.startswith(b"\x1a\x45\xdf\xa3"),
        "doc": header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),
        "docx": header.startswith(b"PK\x03\x04"),
    }
    if extension == "txt":
        try:
            upload.stream.read().decode("utf-8")
            return True
        except UnicodeDecodeError:
            return False
        finally:
            upload.stream.seek(0)
    return signatures.get(extension, False)

def save_validated_upload(upload, folder, allowed_extensions):
    if not upload or not upload.filename:
        return None
    safe_name = secure_filename(upload.filename)
    if not safe_name or "." not in safe_name:
        return None
    extension = safe_name.rsplit(".", 1)[-1].lower()
    if extension not in allowed_extensions or not valid_upload_signature(upload, extension):
        return None
    stored_name = f"{secrets.token_hex(12)}_{safe_name}"
    category = "payment-proofs" if folder == UPLOAD_FOLDER else "messages"
    return save_upload(upload, category, folder, stored_name)

def db():
    if "db" not in g:
        database_url = os.environ.get("AREEJ_DATABASE_URL", "").strip()
        if database_url:
            g.db = PostgresCompatConnection.connect(database_url)
        else:
            g.db = sqlite3.connect(DB_PATH)
            g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error=None):
    conn = g.pop("db", None)
    if conn: conn.close()

def init_db():
    database_url = os.environ.get("AREEJ_DATABASE_URL", "").strip()
    if database_url:
        if not os.environ.get("AREEJ_SECRET_KEY"):
            raise RuntimeError("AREEJ_SECRET_KEY must be set when PostgreSQL is enabled.")
        conn = PostgresCompatConnection.connect(database_url)
        try:
            schema = conn.execute("SELECT to_regnamespace('areej_app') AS schema_name").fetchone()
            if not schema or schema["schema_name"] is None:
                raise RuntimeError("Supabase schema areej_app is missing. Apply the reviewed migrations first.")
            throttle = conn.execute("SELECT to_regclass('areej_app.login_attempts') AS table_name").fetchone()
            if not throttle or throttle["table_name"] is None:
                raise RuntimeError("Supabase table areej_app.login_attempts is missing. Apply migration 002_areej_login_attempts first.")
            active_column = conn.execute("""SELECT 1 FROM information_schema.columns
                WHERE table_schema='areej_app' AND table_name='users' AND column_name='is_active'""").fetchone()
            if not active_column:
                raise RuntimeError("Supabase users.is_active is missing. Apply migration 004_areej_account_management.sql before deploying this version.")
        finally:
            conn.close()
        return

    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS login_attempts (
      attempt_key TEXT PRIMARY KEY, window_started_at REAL NOT NULL,
      failed_attempts INTEGER NOT NULL DEFAULT 0, blocked_until REAL
    );
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
    user_columns = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
    if "is_active" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
    message_columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)")}
    for column, definition in {
        "is_read": "INTEGER DEFAULT 0", "attachment_name": "TEXT DEFAULT ''",
        "attachment_path": "TEXT DEFAULT ''", "attachment_type": "TEXT DEFAULT ''"
    }.items():
        if column not in message_columns:
            conn.execute(f"ALTER TABLE messages ADD COLUMN {column} {definition}")
    # Never create predictable demo accounts automatically.
    # Create the first administrator only when the deployment owner
    # explicitly supplies a private environment variable.
    initial_admin_password = os.environ.get("AREEJ_INITIAL_ADMIN_PASSWORD", "")

    if initial_admin_password:
        if len(initial_admin_password) < 8:
            raise RuntimeError(
                "AREEJ_INITIAL_ADMIN_PASSWORD must contain at least 8 characters."
            )

        existing_admin = conn.execute(
            "SELECT id FROM users WHERE role=? LIMIT 1",
            ("admin",)
        ).fetchone()

        if not existing_admin:
            existing_username = conn.execute(
                "SELECT id FROM users WHERE username=?",
                ("admin",)
            ).fetchone()

            if existing_username:
                raise RuntimeError(
                    "The username 'admin' already exists but is not an administrator. "
                    "Resolve this account before creating the initial administrator."
                )

            conn.execute(
                """
                INSERT INTO users
                (username, password_hash, role, display_name)
                VALUES (?, ?, ?, ?)
                """,
                (
                    "admin",
                    generate_password_hash(initial_admin_password),
                    "admin",
                    "Academy Administrator"
                )
            )

    conn.commit()
    conn.close()

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
            active_user = db().execute("SELECT is_active FROM users WHERE id=?", (session["user_id"],)).fetchone()
            if not active_user or not active_user["is_active"]:
                session.clear()
                flash("Your account is inactive. Please contact the academy administrator.", "error")
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapped
    return deco

@app.route("/")
def index():
    return render_template("home.html", year=datetime.datetime.now().year)

@app.route("/privacy")
def privacy_policy():
    return render_template("privacy.html", year=datetime.datetime.now().year)

@app.route("/health")
def health():
    try:
        db().execute("SELECT 1 FROM users LIMIT 1").fetchone()
    except Exception:
        app.logger.exception("Application health check failed")
        return {"status": "unhealthy", "service": "Areej Virtual Islamic Academy"}, 503
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
    if os.environ.get("AREEJ_DATABASE_URL"):
        return {"error": "Database backups are handled by the encrypted backup workflow, not this SQLite download route."}, 503
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
    age = request.form.get("age", "").strip()
    programme = request.form.get("programme", "").strip()
    phone = request.form.get("phone", "").strip()
    email = request.form.get("email", "").strip()
    contact = phone or request.form.get("contact", "").strip()
    if email:
        contact = f"{contact} / {email}" if contact else email

    if not student_name or not age or not programme or not contact:
        flash("Please complete the required student name, age, programme and contact fields.", "error")
        return redirect(url_for("index", _anchor="admissions"))
    try:
        student_age = int(age)
    except ValueError:
        flash("Please enter a valid student age between 3 and 100.", "error")
        return redirect(url_for("index", _anchor="admissions"))
    if not 3 <= student_age <= 100:
        flash("Student age must be between 3 and 100.", "error")
        return redirect(url_for("index", _anchor="admissions"))

    proof = request.files.get("payment_proof")
    proof_name = ""
    if proof and proof.filename:
        proof_name = save_validated_upload(proof, UPLOAD_FOLDER, {"jpg", "jpeg", "png", "pdf"})
        if not proof_name:
            flash("Payment proof must be a valid JPG, PNG or PDF file.", "error")
            return redirect(url_for("index", _anchor="admissions"))

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
        now = datetime.datetime.now(datetime.UTC).timestamp()
        client_ip = request.remote_addr or "unknown"
        attempt_key = hashlib.sha256(
            f"{username.casefold()}\0{client_ip}".encode("utf-8")
        ).hexdigest()
        conn = db()
        attempt = conn.execute(
            "SELECT * FROM login_attempts WHERE attempt_key=?", (attempt_key,)
        ).fetchone()

        if attempt and attempt["blocked_until"] and attempt["blocked_until"] > now:
            flash("Too many unsuccessful sign-in attempts. Please wait and try again.", "error")
            return render_template("login.html"), 429

        if attempt and now - attempt["window_started_at"] >= 900:
            conn.execute("DELETE FROM login_attempts WHERE attempt_key=?", (attempt_key,))
            conn.commit()
            attempt = None

        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if user and user["is_active"] and check_password_hash(user["password_hash"], password):
            conn.execute("DELETE FROM login_attempts WHERE attempt_key=?", (attempt_key,))
            conn.commit()
            session.clear()
            session.update(
                user_id=user["id"],
                username=user["username"],
                display_name=user["display_name"],
                role=user["role"],
                csrf_token=secrets.token_hex(32),
            )
            return redirect(url_for("portal_home"))

        if attempt:
            failures = attempt["failed_attempts"] + 1
            blocked_until = now + 600 if failures >= 8 else None
            conn.execute(
                "UPDATE login_attempts SET failed_attempts=?, blocked_until=? WHERE attempt_key=?",
                (failures, blocked_until, attempt_key),
            )
        else:
            conn.execute(
                "INSERT INTO login_attempts(attempt_key,window_started_at,failed_attempts,blocked_until) VALUES(?,?,1,NULL)",
                (attempt_key, now),
            )
        conn.execute(
            "DELETE FROM login_attempts WHERE window_started_at < ?", (now - 86400,)
        )
        conn.commit()
        flash("The username or password is incorrect.", "error")
    return render_template("login.html")

@app.route("/portal")
@roles("admin","staff","student","parent")
def portal_home():
    endpoints = {"admin":"admin_dashboard","staff":"staff_dashboard",
                 "student":"student_dashboard","parent":"parent_dashboard"}
    return redirect(url_for(endpoints[session["role"]]))

def portal_contacts(conn, role):
    # Staff may contact academy administrators, colleagues and students
    # enrolled in classes assigned to them, but not unrelated learners.
    if role == "staff":
        return conn.execute(
            """SELECT DISTINCT u.id, u.display_name, u.role
               FROM users u
               WHERE u.id != ? AND (
                   u.role IN ('admin', 'staff')
                   OR (
                       u.role = 'student'
                       AND EXISTS (
                           SELECT 1
                           FROM enrollments_academic ea
                           JOIN classes cl ON cl.id = ea.class_id
                           WHERE ea.student_id = u.id
                             AND cl.teacher_id = ?
                       )
                   )
               )
               ORDER BY u.role, u.display_name""",
            (session["user_id"], session["user_id"]),
        ).fetchall()

    return conn.execute(
        "SELECT id, display_name, role FROM users WHERE id != ? ORDER BY role, display_name",
        (session["user_id"],),
    ).fetchall()

@app.route("/messages/open", methods=["POST"])
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
    if upload and upload.filename:
        allowed_extensions = {"jpg", "jpeg", "png", "webp", "pdf", "txt", "doc", "docx", "webm", "ogg", "mp3", "wav"}
        attachment_path = save_validated_upload(upload, MESSAGE_FOLDER, allowed_extensions) or ""
        if not attachment_path:
            flash("That attachment is not a supported file or its contents do not match its extension.", "error")
            return redirect(request.referrer or url_for("portal"))
        attachment_name = secure_filename(upload.filename) or "attachment"
        attachment_type = upload.content_type or "application/octet-stream"
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
    message = db().execute("SELECT attachment_name FROM messages WHERE attachment_path=? AND (sender_id=? OR recipient_id=?)",
                            (filename, session["user_id"], session["user_id"])).fetchone()
    try:
        content = read_upload(filename, MESSAGE_FOLDER)
    except (FileNotFoundError, ValueError):
        abort(404)
    return send_file(io.BytesIO(content), as_attachment=True,
                     download_name=(message["attachment_name"] or "attachment"),
                     mimetype="application/octet-stream")

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
    students = conn.execute(
        """SELECT DISTINCT u.id, u.display_name
           FROM users u
           JOIN enrollments_academic ea ON ea.student_id=u.id
           JOIN classes cl ON cl.id=ea.class_id
           WHERE u.role='student' AND cl.teacher_id=?
           ORDER BY u.display_name""",
        (session["user_id"],),
    ).fetchall()
    assignments = conn.execute("SELECT a.*, cl.name AS class_name FROM assignments a JOIN classes cl ON cl.id=a.class_id WHERE cl.teacher_id=? ORDER BY a.created_at DESC", (session["user_id"],)).fetchall()
    attendance_summary = conn.execute(
        """SELECT COUNT(*) AS total,
                  COALESCE(SUM(CASE WHEN a.status='present' THEN 1 ELSE 0 END), 0) AS present
           FROM attendance a
           JOIN classes cl ON cl.id=a.class_id
           WHERE cl.teacher_id=?""",
        (session["user_id"],),
    ).fetchone()
    attendance_rate = round(100 * attendance_summary["present"] / attendance_summary["total"]) if attendance_summary["total"] else 0
    return render_template(
        "staff.html", classes=classes, courses=courses, students=students,
        assignments=assignments, portal_messages=messages,
        class_count=len(classes), student_count=len(students),
        attendance_rate=attendance_rate, assignment_count=len(assignments),
        recipients=portal_contacts(conn, "staff")
    )

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
            elif len(password) < 8:
                flash("The password must contain at least 8 characters.", "error")
            elif conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone():
                flash("That username is already in use. Please choose another one.", "error")
            else:
                conn.execute("INSERT INTO users(username,password_hash,role,display_name,is_active) VALUES(?,?,?,?,TRUE)",
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
    students = conn.execute("SELECT id, username, display_name FROM users WHERE role='student' AND is_active=TRUE ORDER BY display_name").fetchall()
    staff_accounts = conn.execute("SELECT id, username, display_name FROM users WHERE role='staff' AND is_active=TRUE ORDER BY display_name").fetchall()
    parent_accounts = conn.execute("SELECT id, username, display_name FROM users WHERE role='parent' AND is_active=TRUE ORDER BY display_name").fetchall()
    accounts = conn.execute("SELECT id, username, display_name, role, is_active FROM users ORDER BY role, display_name").fetchall()
    admin_assignments = conn.execute("SELECT a.*, cl.name AS class_name, u.display_name AS teacher_name FROM assignments a JOIN classes cl ON cl.id=a.class_id LEFT JOIN users u ON u.id=cl.teacher_id ORDER BY a.created_at DESC").fetchall()
    portal_messages = conn.execute("SELECT m.*, u.display_name AS sender_name, u.role AS sender_role, r.display_name AS recipient_name FROM messages m JOIN users u ON u.id=m.sender_id JOIN users r ON r.id=m.recipient_id WHERE m.recipient_id=? OR m.sender_id=? ORDER BY m.created_at ASC LIMIT 50", (session["user_id"], session["user_id"])).fetchall()
    classes = conn.execute("SELECT cl.*, u.display_name AS teacher_name FROM classes cl LEFT JOIN users u ON u.id=cl.teacher_id ORDER BY cl.id DESC").fetchall()
    return render_template("admin.html", courses=courses, course_count=course_count,
                           enrollment_count=enrollment_count, pending_enrollments=pending_enrollments,
                           enrollments=enrollments, user_counts=user_counts, students=students,
                           staff_accounts=staff_accounts, parent_accounts=parent_accounts, classes=classes,
                           accounts=accounts, admin_assignments=admin_assignments,
                           portal_messages=portal_messages, recipients=portal_contacts(conn, "admin"))

@app.route("/admin/accounts/<int:user_id>/update", methods=["POST"])
@roles("admin")
def admin_update_account(user_id):
    conn = db()
    account = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not account:
        abort(404)
    display_name = request.form.get("display_name", "").strip()
    username = request.form.get("username", "").strip().lower()
    new_password = request.form.get("new_password", "")
    if not display_name or not username:
        flash("Name and username are required.", "error")
    elif new_password and len(new_password) < 8:
        flash("A new password must contain at least 8 characters.", "error")
    elif conn.execute("SELECT id FROM users WHERE username=? AND id<>?", (username, user_id)).fetchone():
        flash("That username is already in use.", "error")
    else:
        if new_password:
            conn.execute("UPDATE users SET display_name=?, username=?, password_hash=? WHERE id=?",
                         (display_name, username, generate_password_hash(new_password), user_id))
        else:
            conn.execute("UPDATE users SET display_name=?, username=? WHERE id=?",
                         (display_name, username, user_id))
        conn.commit()
        flash("Account details updated successfully.", "success")
        if user_id == session.get("user_id"):
            session["display_name"] = display_name
            session["username"] = username
    return redirect(url_for("admin_dashboard", _anchor="accounts"))

@app.route("/admin/accounts/<int:user_id>/toggle", methods=["POST"])
@roles("admin")
def admin_toggle_account(user_id):
    conn = db()
    account = conn.execute("SELECT id, role, is_active FROM users WHERE id=?", (user_id,)).fetchone()
    if not account:
        abort(404)
    if user_id == session.get("user_id"):
        flash("You cannot deactivate your own administrator account.", "error")
    elif account["role"] == "admin" and account["is_active"]:
        active_admins = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role='admin' AND is_active=TRUE").fetchone()["n"]
        if active_admins <= 1:
            flash("The last active administrator account cannot be deactivated.", "error")
        else:
            conn.execute("UPDATE users SET is_active=FALSE WHERE id=?", (user_id,))
            conn.commit()
            flash("Administrator account deactivated. Its records have been preserved.", "success")
    else:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (not bool(account["is_active"]), user_id))
        conn.commit()
        flash("Account status updated. Existing records have been preserved.", "success")
    return redirect(url_for("admin_dashboard", _anchor="accounts"))

@app.route("/admin/courses/<int:course_id>/update", methods=["POST"])
@roles("admin")
def admin_update_course(course_id):
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    if not name:
        flash("Course name is required.", "error")
    else:
        result = db().execute("UPDATE courses SET name=?, description=? WHERE id=?", (name, description, course_id))
        db().commit()
        flash("Course updated successfully." if result.rowcount else "Course was not found.", "success" if result.rowcount else "error")
    return redirect(url_for("admin_dashboard", _anchor="courses"))

@app.route("/admin/courses/<int:course_id>/delete", methods=["POST"])
@roles("admin")
def delete_course(course_id):
    conn = db()
    linked = conn.execute("SELECT COUNT(*) AS n FROM classes WHERE course_id=?", (course_id,)).fetchone()["n"]
    if linked:
        flash("This course is used by one or more classes. Reassign those classes before deleting the course.", "error")
    else:
        result = conn.execute("DELETE FROM courses WHERE id=?", (course_id,))
        conn.commit()
        flash("Course deleted." if result.rowcount else "Course was not found.", "success" if result.rowcount else "error")
    return redirect(url_for("admin_dashboard", _anchor="courses"))

@app.route("/admin/classes/<int:class_id>/update", methods=["POST"])
@roles("admin")
def admin_update_class(class_id):
    name = request.form.get("name", "").strip()
    if not name:
        flash("Class name is required.", "error")
    else:
        result = db().execute("UPDATE classes SET name=?, schedule=?, meeting_url=?, channel=?, description=? WHERE id=?",
            (name, request.form.get("schedule", "").strip(), request.form.get("meeting_url", "").strip(),
             request.form.get("channel", "General").strip(), request.form.get("description", "").strip(), class_id))
        db().commit()
        flash("Class updated successfully." if result.rowcount else "Class was not found.", "success" if result.rowcount else "error")
    return redirect(url_for("admin_dashboard", _anchor="manage-classes"))

@app.route("/admin/classes/<int:class_id>/delete", methods=["POST"])
@roles("admin")
def admin_delete_class(class_id):
    conn = db()
    dependencies = conn.execute("SELECT (SELECT COUNT(*) FROM enrollments_academic WHERE class_id=?)+(SELECT COUNT(*) FROM attendance WHERE class_id=?)+(SELECT COUNT(*) FROM assignments WHERE class_id=?)+(SELECT COUNT(*) FROM results WHERE class_id=?)+(SELECT COUNT(*) FROM learning_materials WHERE class_id=?) AS n", (class_id, class_id, class_id, class_id, class_id)).fetchone()["n"]
    if dependencies:
        flash("This class has linked enrolments, attendance or assignments. Remove or reassign those records before deleting it.", "error")
    else:
        conn.execute("DELETE FROM classes WHERE id=?", (class_id,)); conn.commit()
        flash("Class deleted.", "success")
    return redirect(url_for("admin_dashboard", _anchor="manage-classes"))

@app.route("/admin/assignments/<int:assignment_id>/update", methods=["POST"])
@roles("admin")
def admin_update_assignment(assignment_id):
    title = request.form.get("title", "").strip()
    if not title:
        flash("Assignment title is required.", "error")
    else:
        result = db().execute("UPDATE assignments SET title=?, instructions=?, due_date=? WHERE id=?",
            (title, request.form.get("instructions", "").strip(), request.form.get("due_date", "").strip(), assignment_id))
        db().commit()
        flash("Assignment updated successfully." if result.rowcount else "Assignment was not found.", "success" if result.rowcount else "error")
    return redirect(url_for("admin_dashboard", _anchor="manage-assignments"))

@app.route("/admin/assignments/<int:assignment_id>/delete", methods=["POST"])
@roles("admin")
def admin_delete_assignment(assignment_id):
    conn = db()
    submitted = conn.execute("SELECT COUNT(*) AS n FROM assignment_submissions WHERE assignment_id=?", (assignment_id,)).fetchone()["n"]
    if submitted:
        flash("This assignment has student submissions. Keep the record or review submissions before deleting it.", "error")
    else:
        conn.execute("DELETE FROM assignments WHERE id=?", (assignment_id,)); conn.commit()
        flash("Assignment deleted.", "success")
    return redirect(url_for("admin_dashboard", _anchor="manage-assignments"))

@app.route("/staff/work", methods=["POST"])
@roles("staff")
def staff_work():
    conn = db()
    action = request.form.get("action")
    teacher_id = session["user_id"]

    if action == "create_class":
        name = request.form.get("name", "").strip()
        course_id = request.form.get("course_id") or None
        if not name or (course_id and not conn.execute("SELECT id FROM courses WHERE id=?", (course_id,)).fetchone()):
            flash("Choose a valid course and enter a class name.", "error")
        else:
            conn.execute("INSERT INTO classes(course_id,teacher_id,name,description,schedule,meeting_url,channel) VALUES(?,?,?,?,?,?,?)",
                         (course_id, teacher_id, name, request.form.get("description","").strip(),
                          request.form.get("schedule","").strip(), request.form.get("meeting_url","").strip(),
                          request.form.get("channel","General")))
            conn.commit()
            flash("Class and channel created.", "success")

    elif action == "create_assignment":
        class_id = request.form.get("class_id")
        title = request.form.get("title", "").strip()
        owned_class = conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?", (class_id, teacher_id)).fetchone()
        if not owned_class or not title:
            abort(403)
        conn.execute("INSERT INTO assignments(class_id,title,instructions,due_date) VALUES(?,?,?,?)",
                     (class_id, title, request.form.get("instructions","").strip(), request.form.get("due_date","")))
        conn.commit()
        flash("Assignment published.", "success")

    elif action == "update_class":
        class_id = request.form.get("class_id")
        name = request.form.get("name", "").strip()
        owned = conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?", (class_id, teacher_id)).fetchone()
        if not owned:
            abort(403)
        if not name:
            flash("Class name is required.", "error")
        else:
            conn.execute("UPDATE classes SET name=?, schedule=?, meeting_url=?, channel=?, description=? WHERE id=? AND teacher_id=?",
                (name, request.form.get("schedule", "").strip(), request.form.get("meeting_url", "").strip(),
                 request.form.get("channel", "General").strip(), request.form.get("description", "").strip(), class_id, teacher_id))
            conn.commit(); flash("Class updated.", "success")

    elif action == "delete_class":
        class_id = request.form.get("class_id")
        owned = conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?", (class_id, teacher_id)).fetchone()
        if not owned:
            abort(403)
        dependencies = conn.execute("SELECT (SELECT COUNT(*) FROM enrollments_academic WHERE class_id=?)+(SELECT COUNT(*) FROM attendance WHERE class_id=?)+(SELECT COUNT(*) FROM assignments WHERE class_id=?)+(SELECT COUNT(*) FROM results WHERE class_id=?)+(SELECT COUNT(*) FROM learning_materials WHERE class_id=?) AS n", (class_id, class_id, class_id, class_id, class_id)).fetchone()["n"]
        if dependencies:
            flash("This class has linked student or academic records, so it cannot be deleted yet.", "error")
        else:
            conn.execute("DELETE FROM classes WHERE id=? AND teacher_id=?", (class_id, teacher_id))
            conn.commit(); flash("Class deleted.", "success")

    elif action == "update_assignment":
        assignment_id = request.form.get("assignment_id")
        title = request.form.get("title", "").strip()
        owned = conn.execute("SELECT a.id FROM assignments a JOIN classes cl ON cl.id=a.class_id WHERE a.id=? AND cl.teacher_id=?", (assignment_id, teacher_id)).fetchone()
        if not owned:
            abort(403)
        if not title:
            flash("Assignment title is required.", "error")
        else:
            conn.execute("UPDATE assignments SET title=?, instructions=?, due_date=? WHERE id=?",
                (title, request.form.get("instructions", "").strip(), request.form.get("due_date", "").strip(), assignment_id))
            conn.commit(); flash("Assignment updated.", "success")

    elif action == "delete_assignment":
        assignment_id = request.form.get("assignment_id")
        owned = conn.execute("SELECT a.id FROM assignments a JOIN classes cl ON cl.id=a.class_id WHERE a.id=? AND cl.teacher_id=?", (assignment_id, teacher_id)).fetchone()
        if not owned:
            abort(403)
        submitted = conn.execute("SELECT COUNT(*) AS n FROM assignment_submissions WHERE assignment_id=?", (assignment_id,)).fetchone()["n"]
        if submitted:
            flash("This assignment already has student submissions and cannot be deleted.", "error")
        else:
            conn.execute("DELETE FROM assignments WHERE id=?", (assignment_id,))
            conn.commit(); flash("Assignment deleted.", "success")

    elif action == "record_attendance":
        class_id, student_id = request.form.get("class_id"), request.form.get("student_id")
        owned_enrolment = conn.execute(
            """SELECT ea.id FROM enrollments_academic ea
               JOIN classes cl ON cl.id=ea.class_id
               WHERE ea.class_id=? AND ea.student_id=? AND cl.teacher_id=?""",
            (class_id, student_id, teacher_id)
        ).fetchone()
        status = request.form.get("status", "present")
        if not owned_enrolment or status not in {"present", "absent", "late", "excused"}:
            abort(403)
        conn.execute("INSERT OR REPLACE INTO attendance(class_id,student_id,lesson_date,status,recorded_by) VALUES(?,?,?,?,?)",
                     (class_id, student_id, request.form.get("lesson_date") or datetime.date.today().isoformat(),
                      status, teacher_id))
        conn.commit()
        flash("Attendance recorded.", "success")

    elif action == "record_result":
        class_id, student_id = request.form.get("class_id"), request.form.get("student_id")
        owned_enrolment = conn.execute(
            """SELECT ea.id FROM enrollments_academic ea
               JOIN classes cl ON cl.id=ea.class_id
               WHERE ea.class_id=? AND ea.student_id=? AND cl.teacher_id=?""",
            (class_id, student_id, teacher_id)
        ).fetchone()
        try:
            score = float(request.form.get("score", "0"))
            maximum_score = float(request.form.get("maximum_score", "100"))
        except ValueError:
            flash("Enter valid numeric assessment scores.", "error")
            return redirect(url_for("staff_dashboard", _anchor="classes"))
        assessment = request.form.get("assessment", "").strip()
        if (not owned_enrolment or not assessment
                or not math.isfinite(score) or not math.isfinite(maximum_score)
                or maximum_score <= 0 or score < 0 or score > maximum_score):
            abort(403)
        conn.execute("INSERT INTO results(class_id,student_id,assessment,score,maximum_score,feedback) VALUES(?,?,?,?,?,?)",
                     (class_id, student_id, assessment, score, maximum_score, request.form.get("feedback","").strip()))
        conn.commit()
        flash("Result saved.", "success")

    return redirect(url_for("staff_dashboard", _anchor="classes"))

@app.route("/student/submit", methods=["POST"])
@roles("student")
def submit_assignment():
    assignment_id = request.form.get("assignment_id")
    student_id = session["user_id"]
    content = request.form.get("content", "").strip()
    assignment = db().execute(
        """SELECT a.id FROM assignments a
           JOIN enrollments_academic ea ON ea.class_id=a.class_id
           WHERE a.id=? AND ea.student_id=?""",
        (assignment_id, student_id)
    ).fetchone()
    if not assignment:
        abort(403)
    upload = request.files.get("submission_file")
    file_name = file_path = ""
    if upload and upload.filename:
        file_path = save_validated_upload(
            upload, MESSAGE_FOLDER, {"jpg", "jpeg", "png", "webp", "pdf", "txt", "doc", "docx"}
        ) or ""
        if not file_path:
            flash("Please upload a supported document or image file.", "error")
            return redirect(url_for("student_dashboard", _anchor="assignments"))
        file_name = secure_filename(upload.filename) or "submission"
    if not content and not file_path:
        flash("Add a response or attach a file before submitting.", "error")
        return redirect(url_for("student_dashboard", _anchor="assignments"))
    db().execute("INSERT OR REPLACE INTO assignment_submissions(assignment_id,student_id,content,file_name,file_path) VALUES(?,?,?,?,?)",
                 (assignment_id, student_id, content, file_name, file_path))
    db().commit()
    flash("Assignment submitted successfully.", "success")
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

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

@app.errorhandler(403)
def forbidden(error): return render_template("error.html", code=403, message="You do not have permission to view this page."), 403
@app.errorhandler(404)
def missing(error): return render_template("error.html", code=404, message="This page could not be found."), 404

@app.errorhandler(429)
def too_many_requests(error):
    return render_template(
        "error.html", code=429,
        message="Too many requests. Please wait a few minutes and try again."
    ), 429

# Initialize the selected database when imported by a WSGI server such as Gunicorn.
# SQLite setup is idempotent; PostgreSQL mode only validates the pre-provisioned
# areej_app schema and the required login-throttling migration.
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=False)
