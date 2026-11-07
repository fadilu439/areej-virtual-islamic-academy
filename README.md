# Areej Academy — Four Portal Starter

## Setup (Windows PowerShell)
Open this folder in VS Code and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Then open http://127.0.0.1:5000.

If activation is blocked, run:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

## Demo logins (local testing only)
- Admin: `admin` / `Admin123!`
- Staff: `staff` / `Staff123!`
- Student: `student` / `Student123!`
- Parent: `parent` / `Parent123!`

Separate role templates and role checks are included. The Admin portal can add/delete courses; those courses appear in the Student portal. Student, parent, staff, payments, attendance, assignments, messaging, and results workflows are otherwise placeholders.

No fake student/course/payment records are seeded. Four demo login accounts are created for testing.

Before real deployment, change demo passwords, set a strong `AREEJ_SECRET_KEY`, add CSRF protection and production security controls, and never expose this development server directly to the public internet.
