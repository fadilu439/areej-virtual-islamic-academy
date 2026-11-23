"""Private, optional manual-payment finance workflows for AREEJ."""
import datetime
import io
import math
import secrets
from flask import abort, flash, redirect, render_template, request, session, url_for, send_file


def register_finance_routes(app, db, roles, save_upload, read_upload, upload_folder):
    @app.route("/finance")
    @roles("admin", "student", "parent")
    def finance_portal():
        conn=db()
        settings=conn.execute("SELECT * FROM finance_settings WHERE id=1").fetchone()
        if session["role"]=="admin":
            invoices=conn.execute("""SELECT i.*,u.display_name AS student_name FROM invoices i
                JOIN users u ON u.id=i.student_id ORDER BY i.created_at DESC LIMIT 250""").fetchall()
            payments=conn.execute("""SELECT p.*,u.display_name AS student_name,i.title AS invoice_title
                FROM payments p JOIN users u ON u.id=p.student_id JOIN invoices i ON i.id=p.invoice_id
                ORDER BY p.created_at DESC LIMIT 250""").fetchall()
        elif session["role"]=="student":
            invoices=conn.execute("SELECT * FROM invoices WHERE student_id=? ORDER BY created_at DESC",(session["user_id"],)).fetchall()
            payments=conn.execute("SELECT p.*,i.title AS invoice_title FROM payments p JOIN invoices i ON i.id=p.invoice_id WHERE p.student_id=? ORDER BY p.created_at DESC",(session["user_id"],)).fetchall()
        else:
            children=conn.execute("SELECT student_id FROM parent_links WHERE parent_id=?",(session["user_id"],)).fetchall()
            ids=[row["student_id"] for row in children]
            if ids:
                marks=",".join("?" for _ in ids)
                invoices=conn.execute(f"SELECT i.*,u.display_name AS student_name FROM invoices i JOIN users u ON u.id=i.student_id WHERE i.student_id IN ({marks}) ORDER BY i.created_at DESC",ids).fetchall()
                payments=conn.execute(f"SELECT p.*,u.display_name AS student_name,i.title AS invoice_title FROM payments p JOIN users u ON u.id=p.student_id JOIN invoices i ON i.id=p.invoice_id WHERE p.student_id IN ({marks}) ORDER BY p.created_at DESC",ids).fetchall()
            else:
                invoices=[]; payments=[]
        students=conn.execute("SELECT id,display_name FROM users WHERE role='student' AND is_active=1 ORDER BY display_name").fetchall() if session["role"]=="admin" else []
        return render_template("finance.html",settings=settings,invoices=invoices,payments=payments,students=students,role=session["role"])

    @app.route("/admin/finance/settings", methods=["POST"])
    @roles("admin")
    def finance_settings_update():
        currency=request.form.get("currency","").strip().upper()
        enabled=request.form.get("fees_enabled")=="1"
        if len(currency)!=3 or not currency.isalpha():
            flash("Enter a valid three-letter currency code.", "error")
            return redirect(url_for("finance_portal"))
        conn=db()
        conn.execute("""INSERT INTO finance_settings(id,currency,fees_enabled,updated_by,updated_at)
            VALUES(1,?,?,?,CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET currency=excluded.currency,fees_enabled=excluded.fees_enabled,
            updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP""",
            (currency,1 if enabled else 0,session["user_id"]))
        conn.commit()
        flash("Private finance settings saved. No fee amount has been published.", "success")
        return redirect(url_for("finance_portal"))

    @app.route("/admin/finance/invoices/create", methods=["POST"])
    @roles("admin")
    def finance_create_invoice():
        conn=db()
        settings=conn.execute("SELECT * FROM finance_settings WHERE id=1").fetchone()
        if not settings or not settings["fees_enabled"]:
            flash("Enable private finance settings before issuing invoices. No public fee is displayed.", "error")
            return redirect(url_for("finance_portal"))
        student_id=request.form.get("student_id")
        student=conn.execute("SELECT id FROM users WHERE id=? AND role='student' AND is_active=1",(student_id,)).fetchone()
        title=request.form.get("title","").strip()[:160]
        description=request.form.get("description","").strip()[:2000]
        due_date=request.form.get("due_date","").strip()
        try:
            amount=round(float(request.form.get("amount","")),2)
            if due_date: datetime.date.fromisoformat(due_date)
        except (ValueError,TypeError):
            abort(400)
        if not student or not title or not math.isfinite(amount) or amount<=0:
            abort(400)
        conn.execute("""INSERT INTO invoices(student_id,title,description,amount,currency,due_date,status,created_by)
            VALUES(?,?,?,?,?,?,'unpaid',?)""",
            (student_id,title,description,amount,settings["currency"],due_date,session["user_id"]))
        conn.commit()
        flash("Private invoice created.", "success")
        return redirect(url_for("finance_portal"))

    @app.route("/finance/invoices/<int:invoice_id>/pay", methods=["POST"])
    @roles("student","parent")
    def finance_submit_payment(invoice_id):
        conn=db()
        invoice=conn.execute("SELECT * FROM invoices WHERE id=?",(invoice_id,)).fetchone()
        if not invoice:
            abort(404)
        if session["role"]=="student":
            allowed=invoice["student_id"]==session["user_id"]
        else:
            allowed=conn.execute("SELECT 1 FROM parent_links WHERE parent_id=? AND student_id=?",
                (session["user_id"],invoice["student_id"])).fetchone() is not None
        if not allowed:
            abort(404)
        paid=conn.execute("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE invoice_id=? AND status='confirmed'",(invoice_id,)).fetchone()["total"]
        balance=round(float(invoice["amount"])-float(paid or 0),2)
        try:
            amount=round(float(request.form.get("amount","")),2)
        except (ValueError,TypeError):
            abort(400)
        if not math.isfinite(amount) or amount<=0 or amount>balance:
            flash("Enter a payment amount that does not exceed the outstanding balance.", "error")
            return redirect(url_for("finance_portal"))
        upload=request.files.get("payment_proof")
        proof_path=save_upload(upload,upload_folder,{"jpg","jpeg","png","pdf"})
        if not proof_path:
            flash("Upload a valid JPG, PNG or PDF payment proof.", "error")
            return redirect(url_for("finance_portal"))
        proof_name=(upload.filename or "payment-proof")[:180]
        conn.execute("""INSERT INTO payments(invoice_id,student_id,amount,method,reference,proof_path,proof_name,status)
            VALUES(?,?,?,'manual_transfer',?,?,?,'pending')""",
            (invoice_id,invoice["student_id"],amount,request.form.get("reference","").strip()[:120],proof_path,proof_name))
        conn.commit()
        flash("Payment proof submitted. It will remain pending until the academy confirms it.", "success")
        return redirect(url_for("finance_portal"))

    @app.route("/admin/finance/payments/<int:payment_id>/review", methods=["POST"])
    @roles("admin")
    def finance_review_payment(payment_id):
        decision=request.form.get("decision","")
        if decision not in {"confirmed","rejected"}:
            abort(400)
        conn=db()
        payment=conn.execute("SELECT * FROM payments WHERE id=?",(payment_id,)).fetchone()
        if not payment:
            abort(404)
        if payment["status"]!="pending":
            flash("This payment has already been reviewed.", "error")
            return redirect(url_for("finance_portal"))
        receipt=("AREEJ-"+str(payment_id)+"-"+secrets.token_hex(3).upper()) if decision=="confirmed" else None
        conn.execute("""UPDATE payments SET status=?,reviewed_by=?,reviewed_at=CURRENT_TIMESTAMP,receipt_number=?
            WHERE id=? AND status='pending'""",(decision,session["user_id"],receipt,payment_id))
        if decision=="confirmed":
            totals=conn.execute("SELECT COALESCE(SUM(amount),0) AS total FROM payments WHERE invoice_id=? AND status='confirmed'",(payment["invoice_id"],)).fetchone()["total"]
            invoice=conn.execute("SELECT amount FROM invoices WHERE id=?",(payment["invoice_id"],)).fetchone()
            new_status="paid" if float(totals or 0)+float(payment["amount"])>=float(invoice["amount"]) else "partial"
            conn.execute("UPDATE invoices SET status=? WHERE id=?",(new_status,payment["invoice_id"]))
        conn.commit()
        flash("Payment "+decision+". "+("Official receipt generated." if receipt else "No receipt was issued."), "success")
        return redirect(url_for("finance_portal"))

    @app.route("/admin/finance/payments/<int:payment_id>/proof")
    @roles("admin")
    def finance_payment_proof(payment_id):
        payment=db().execute("SELECT proof_path,proof_name FROM payments WHERE id=?",(payment_id,)).fetchone()
        if not payment:
            abort(404)
        try:
            data=read_upload(payment["proof_path"],upload_folder)
        except (FileNotFoundError,ValueError):
            abort(404)
        return send_file(io.BytesIO(data),download_name=payment["proof_name"] or "payment-proof",
                         mimetype="application/octet-stream",as_attachment=True)
