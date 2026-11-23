"""Academic reporting and assignment review routes for AREEJ.

Routes are registered by app.py after the database helpers and role decorator exist.
"""
import datetime
import math
from flask import abort, flash, redirect, render_template, request, session, url_for


def register_academic_routes(app, db, roles):
    @app.route("/staff/reports", methods=["GET"])
    @roles("staff")
    def staff_reports():
        conn = db()
        classes = conn.execute("SELECT id,name FROM classes WHERE teacher_id=? ORDER BY name", (session["user_id"],)).fetchall()
        reports = conn.execute("""SELECT r.*, c.name AS class_name, u.display_name AS student_name
            FROM academic_reports r JOIN classes c ON c.id=r.class_id
            LEFT JOIN users u ON u.id=r.student_id
            WHERE r.staff_id=? ORDER BY r.created_at DESC LIMIT 100""", (session["user_id"],)).fetchall()
        submissions = conn.execute("""SELECT s.*, a.title AS assignment_title, c.name AS class_name,
            u.display_name AS student_name FROM assignment_submissions s
            JOIN assignments a ON a.id=s.assignment_id JOIN classes c ON c.id=a.class_id
            JOIN users u ON u.id=s.student_id WHERE c.teacher_id=?
            ORDER BY s.submitted_at DESC LIMIT 100""", (session["user_id"],)).fetchall()
        students = conn.execute("""SELECT DISTINCT u.id,u.display_name FROM users u
            JOIN enrollments_academic ea ON ea.student_id=u.id JOIN classes c ON c.id=ea.class_id
            WHERE c.teacher_id=? AND u.role='student' ORDER BY u.display_name""", (session["user_id"],)).fetchall()
        plans = conn.execute("""SELECT * FROM lesson_plans WHERE staff_id=?
            ORDER BY lesson_date DESC,created_at DESC LIMIT 100""",(session["user_id"],)).fetchall()
        materials = conn.execute("""SELECT m.*,c.name AS class_name FROM learning_materials m
            JOIN classes c ON c.id=m.class_id WHERE c.teacher_id=? ORDER BY m.created_at DESC LIMIT 100""",
            (session["user_id"],)).fetchall()
        return render_template("reports.html", mode="staff", classes=classes, reports=reports,
                               submissions=submissions, students=students, plans=plans, materials=materials)

    @app.route("/admin/reports", methods=["GET"])
    @roles("admin")
    def admin_reports():
        conn = db()
        status = request.args.get("status", "").strip()
        if status not in {"", "draft", "submitted", "approved", "rejected"}:
            abort(400)
        query = """SELECT r.*, c.name AS class_name, s.display_name AS staff_name,
                   u.display_name AS student_name FROM academic_reports r
                   JOIN classes c ON c.id=r.class_id JOIN users s ON s.id=r.staff_id
                   LEFT JOIN users u ON u.id=r.student_id"""
        params = []
        if status:
            query += " WHERE r.status=?"
            params.append(status)
        query += " ORDER BY CASE WHEN r.status='submitted' THEN 0 ELSE 1 END, r.created_at DESC LIMIT 250"
        reports = conn.execute(query, params).fetchall()
        return render_template("reports.html", mode="admin", reports=reports, status=status)

    @app.route("/staff/lesson-plans/create", methods=["POST"])
    @roles("staff")
    def create_lesson_plan():
        conn=db()
        class_id=request.form.get("class_id","")
        owned=conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?",(class_id,session["user_id"])).fetchone()
        topic=request.form.get("topic","").strip()[:200]
        lesson_date=request.form.get("lesson_date","").strip()
        try:
            datetime.date.fromisoformat(lesson_date)
        except ValueError:
            abort(400)
        if not owned:
            abort(403)
        if not topic:
            abort(400)
        conn.execute("""INSERT INTO lesson_plans(class_id,staff_id,lesson_date,topic,objectives,materials,planned_activity)
            VALUES(?,?,?,?,?,?,?)""",(class_id,session["user_id"],lesson_date,topic,
            request.form.get("objectives","").strip()[:3000],request.form.get("materials","").strip()[:2000],
            request.form.get("planned_activity","").strip()[:3000]))
        conn.commit()
        flash("Lesson plan saved.", "success")
        return redirect(url_for("staff_reports"))

    @app.route("/staff/materials/create", methods=["POST"])
    @roles("staff")
    def create_learning_material():
        conn=db()
        class_id=request.form.get("class_id","")
        owned=conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?",(class_id,session["user_id"])).fetchone()
        title=request.form.get("title","").strip()[:160]
        resource_url=request.form.get("url","").strip()
        if not owned:
            abort(403)
        if not title or not resource_url.startswith(("https://","http://")) or len(resource_url)>1000:
            abort(400)
        conn.execute("INSERT INTO learning_materials(class_id,title,url) VALUES(?,?,?)",(class_id,title,resource_url))
        conn.commit()
        flash("Learning resource shared with enrolled students.", "success")
        return redirect(url_for("staff_reports"))

    @app.route("/staff/reports/create", methods=["POST"])
    @roles("staff")
    def create_academic_report():
        conn = db()
        report_type = request.form.get("report_type", "")
        class_id = request.form.get("class_id", "")
        owned = conn.execute("SELECT id FROM classes WHERE id=? AND teacher_id=?", (class_id, session["user_id"])).fetchone()
        report_date = request.form.get("report_date", "") or datetime.date.today().isoformat()
        try:
            parsed_date = datetime.date.fromisoformat(report_date)
            duration = int(request.form.get("duration_minutes", "0") or 0)
            attendance_count = int(request.form.get("attendance_count", "0") or 0)
            score_raw = request.form.get("score", "").strip()
            maximum_raw = request.form.get("maximum_score", "").strip()
            score = float(score_raw) if score_raw else None
            maximum = float(maximum_raw) if maximum_raw else None
        except (ValueError, TypeError):
            flash("Enter valid dates and numeric report values.", "error")
            return redirect(url_for("staff_reports"))
        student_id = request.form.get("student_id") or None
        if report_type == "student_progress":
            enrolled = conn.execute("""SELECT 1 FROM enrollments_academic
                WHERE class_id=? AND student_id=?""", (class_id, student_id)).fetchone() if student_id else None
            if not enrolled:
                abort(403)
        elif report_type not in {"daily", "weekly"}:
            abort(400)
        if not owned:
            abort(403)
        if (duration < 0 or duration > 240 or attendance_count < 0
                or (score is None) != (maximum is None)
                or (score is not None and (not math.isfinite(score) or not math.isfinite(maximum)
                    or maximum <= 0 or score < 0 or score > maximum))):
            abort(400)
        week_start = request.form.get("week_start", "").strip()
        week_end = request.form.get("week_end", "").strip()
        if report_type == "weekly":
            try:
                if not week_start or not week_end or datetime.date.fromisoformat(week_end) < datetime.date.fromisoformat(week_start):
                    raise ValueError
            except ValueError:
                flash("A valid weekly start and end date are required.", "error")
                return redirect(url_for("staff_reports"))
        conn.execute("""INSERT INTO academic_reports
            (report_type,class_id,staff_id,student_id,report_date,week_start,week_end,topic,
             duration_minutes,attendance_count,progress_notes,challenges,next_steps,score,
             maximum_score,teacher_comments,recommendations,status)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (report_type,class_id,session["user_id"],student_id,parsed_date.isoformat(),week_start,week_end,
             request.form.get("topic","").strip()[:200],duration,attendance_count,
             request.form.get("progress_notes","").strip()[:4000],request.form.get("challenges","").strip()[:2000],
             request.form.get("next_steps","").strip()[:2000],score,maximum,
             request.form.get("teacher_comments","").strip()[:3000],
             request.form.get("recommendations","").strip()[:2000],
             "submitted" if request.form.get("submit_action") == "submit" else "draft"))
        conn.commit()
        flash("Academic report saved and sent for review." if request.form.get("submit_action") == "submit" else "Report saved as draft.", "success")
        return redirect(url_for("staff_reports"))

    @app.route("/admin/reports/<int:report_id>/review", methods=["POST"])
    @roles("admin")
    def review_academic_report(report_id):
        decision = request.form.get("decision", "")
        if decision not in {"approved", "rejected"}:
            abort(400)
        conn = db()
        report = conn.execute("SELECT id,status FROM academic_reports WHERE id=?", (report_id,)).fetchone()
        if not report:
            abort(404)
        if report["status"] not in {"submitted", "rejected"}:
            flash("Only submitted or previously rejected reports can be reviewed.", "error")
            return redirect(url_for("admin_reports"))
        conn.execute("""UPDATE academic_reports SET status=?, reviewer_id=?, reviewed_at=CURRENT_TIMESTAMP,
            review_note=? WHERE id=?""",
            (decision,session["user_id"],request.form.get("review_note","").strip()[:2000],report_id))
        conn.commit()
        flash("Report " + decision + ".", "success")
        return redirect(url_for("admin_reports"))

    @app.route("/staff/submissions/<int:submission_id>/grade", methods=["POST"])
    @roles("staff")
    def grade_assignment_submission(submission_id):
        conn = db()
        submission = conn.execute("""SELECT s.id,a.class_id FROM assignment_submissions s
            JOIN assignments a ON a.id=s.assignment_id JOIN classes c ON c.id=a.class_id
            WHERE s.id=? AND c.teacher_id=?""", (submission_id,session["user_id"])).fetchone()
        if not submission:
            abort(403)
        try:
            score = float(request.form.get("score", ""))
            maximum = float(request.form.get("maximum_score", "100"))
        except (ValueError, TypeError):
            abort(400)
        if not math.isfinite(score) or not math.isfinite(maximum) or maximum <= 0 or score < 0 or score > maximum:
            abort(400)
        conn.execute("""UPDATE assignment_submissions SET score=?,feedback=?,status='graded',
            reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?""",
            (score,request.form.get("feedback","").strip()[:3000],session["user_id"],submission_id))
        conn.commit()
        flash("Submission marked and feedback saved.", "success")
        return redirect(url_for("staff_reports"))
