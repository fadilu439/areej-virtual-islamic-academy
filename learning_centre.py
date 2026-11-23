"""Student learning centre and parent child-progress routes."""
from flask import abort, render_template, session


def register_learning_routes(app, db, roles):
    @app.route("/student/learning")
    @roles("student")
    def student_learning_centre():
        conn = db()
        student_id = session["user_id"]
        classes = conn.execute("""SELECT c.* FROM classes c
            JOIN enrollments_academic e ON e.class_id=c.id
            WHERE e.student_id=? ORDER BY c.schedule,c.name""", (student_id,)).fetchall()
        courses = conn.execute("""SELECT DISTINCT co.* FROM courses co
            JOIN classes c ON c.course_id=co.id
            JOIN enrollments_academic e ON e.class_id=c.id
            WHERE e.student_id=? ORDER BY co.name""", (student_id,)).fetchall()
        assignments = conn.execute("""SELECT a.*,c.name AS class_name,s.status AS submission_status,
            s.score,s.feedback,s.submitted_at FROM assignments a
            JOIN classes c ON c.id=a.class_id
            JOIN enrollments_academic e ON e.class_id=c.id
            LEFT JOIN assignment_submissions s ON s.assignment_id=a.id AND s.student_id=?
            WHERE e.student_id=? ORDER BY a.due_date,a.created_at DESC""", (student_id,student_id)).fetchall()
        attendance = conn.execute("""SELECT a.*,c.name AS class_name FROM attendance a
            JOIN classes c ON c.id=a.class_id
            JOIN enrollments_academic e ON e.class_id=c.id
            WHERE a.student_id=? AND e.student_id=? ORDER BY a.lesson_date DESC LIMIT 120""", (student_id,student_id)).fetchall()
        results = conn.execute("""SELECT r.*,c.name AS class_name FROM results r
            JOIN classes c ON c.id=r.class_id
            WHERE r.student_id=? ORDER BY r.created_at DESC LIMIT 120""", (student_id,)).fetchall()
        materials = conn.execute("""SELECT m.*,c.name AS class_name FROM learning_materials m
            JOIN classes c ON c.id=m.class_id
            JOIN enrollments_academic e ON e.class_id=c.id
            WHERE e.student_id=? ORDER BY m.created_at DESC LIMIT 100""", (student_id,)).fetchall()
        reports = conn.execute("""SELECT r.*,c.name AS class_name FROM academic_reports r
            JOIN classes c ON c.id=r.class_id
            WHERE r.student_id=? AND r.report_type='student_progress' AND r.status='approved'
            ORDER BY r.report_date DESC LIMIT 50""", (student_id,)).fetchall()
        return render_template("student_learning.html", classes=classes, courses=courses,
            assignments=assignments, attendance=attendance, results=results,
            materials=materials, reports=reports)

    @app.route("/parent/children/<int:student_id>/progress")
    @roles("parent")
    def parent_child_progress(student_id):
        conn = db()
        linked = conn.execute("""SELECT u.id,u.display_name,u.username FROM users u
            JOIN parent_links p ON p.student_id=u.id
            WHERE p.parent_id=? AND p.student_id=? AND u.role='student'""",
            (session["user_id"],student_id)).fetchone()
        if not linked:
            abort(404)
        attendance = conn.execute("""SELECT a.*,c.name AS class_name FROM attendance a
            JOIN classes c ON c.id=a.class_id
            WHERE a.student_id=? ORDER BY a.lesson_date DESC LIMIT 120""", (student_id,)).fetchall()
        results = conn.execute("""SELECT r.*,c.name AS class_name FROM results r
            JOIN classes c ON c.id=r.class_id
            WHERE r.student_id=? ORDER BY r.created_at DESC LIMIT 120""", (student_id,)).fetchall()
        reports = conn.execute("""SELECT r.*,c.name AS class_name FROM academic_reports r
            JOIN classes c ON c.id=r.class_id
            WHERE r.student_id=? AND r.report_type='student_progress' AND r.status='approved'
            ORDER BY r.report_date DESC LIMIT 50""", (student_id,)).fetchall()
        attendance_summary = conn.execute("""SELECT COUNT(*) AS total,
            SUM(CASE WHEN status='present' THEN 1 ELSE 0 END) AS present
            FROM attendance WHERE student_id=?""", (student_id,)).fetchone()
        return render_template("parent_child_progress.html", child=linked,
            attendance=attendance, results=results, reports=reports,
            attendance_summary=attendance_summary)
