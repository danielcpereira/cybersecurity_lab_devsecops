Perform a static security review of the attached application source.
Use only the source and any context explicitly included in this request.
Do not execute code, use tools, browse, or rely on published solutions.
For each potential vulnerability, provide:
1. A short finding identifier and title.
2. Affected file, function, and line location where available.
3. Attacker-controlled input and the relevant execution or data-flow path.
4. The missing or incorrect security control and the root cause.
5. Preconditions and potential impact.
6. A proposed test that could confirm or reject the claim.
7. Assumptions, uncertainty, and confidence.
Distinguish demonstrated code facts from inferred security requirements.
If the policy is unknown, state the assumption rather than inventing it.
Do not generate patches yet. Return a concise findings table followed by
supporting explanations. Do not treat an absence of findings as proof of
safety.

File: baseline_secure_coding_api.py
```python
import dataclasses
import pathlib
import typing

import flask

app = flask.Flask(__name__)
app.config["SECRET_KEY"] = "dev-secret-key"

# -----------------------------------------------------------------------------
# Intentionally small in-memory "database"
# -----------------------------------------------------------------------------

BASE_DIR = pathlib.Path(__file__).resolve().parent
MATERIALS_DIR = BASE_DIR / "materials"
MATERIALS_DIR.mkdir(exist_ok=True)

# Seed a couple of demo files.
(MATERIALS_DIR / "srs-summary.txt").write_text(
    "Secure Requirements Engineering summary", encoding="utf-8"
)
(MATERIALS_DIR / "secure-coding.txt").write_text(
    "Secure coding practices notes", encoding="utf-8"
)


@dataclasses.dataclass
class User:
    username: str
    password: str
    role: str
    student_id: typing.Optional[int] = None
    courses: typing.Optional[list[str]] = None


USERS = {
    "alice": User(username="alice", password="alicepw", role="student", student_id=1001),
    "bob": User(username="bob", password="bobpw", role="student", student_id=1002),
    "prof_srs": User(
        username="prof_srs", password="profpw", role="professor", courses=["SRS"]
    ),
    "admin1": User(username="admin1", password="adminpw", role="admin"),
}

STUDENT_PROFILES = {
    1001: {"student_id": 1001, "name": "Alice", "email": "alice@uc.pt", "program": "MEI"},
    1002: {"student_id": 1002, "name": "Bob", "email": "bob@uc.pt", "program": "MEI"},
}

GRADES = [
    {"student_id": 1001, "course_id": "SRS", "grade": 14},
    {"student_id": 1002, "course_id": "SRS", "grade": 15},
    {"student_id": 1001, "course_id": "SSD", "grade": 16},
]

def find_grade(student_id, course_id):
    for row in GRADES:
        if row["student_id"] == student_id and row["course_id"] == course_id:
            return row
    return None


# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.get("/")
def index():
    return {
        "message": "Baseline Secure Coding API",
        "endpoints": [
            "POST /login",
            "POST /logout",
            "GET /me",
            "GET /students/<student_id>/profile",
            "POST /grades/update",
            "GET /grades/<student_id>",
            "GET /files?path=<name>",
        ],
    }

@app.post("/login")
def login():
    username = flask.request.form.get("username", "")
    password = flask.request.form.get("password", "")

    user = USERS.get(username)
    if user is None or user.password != password:
        return {"error": "invalid credentials"}, 401

    flask.session["user"] = user.username
    flask.session["role"] = user.role
    flask.session["student_id"] = user.student_id
    flask.session["courses"] = user.courses or []

    return flask.redirect("/me")

@app.post("/logout")
def logout():
    flask.session.clear()
    return {"status": "logged out"}

@app.get("/me")
def me():
    if "user" not in flask.session:
        return {"user": None}

    return {
        "user": flask.session.get("user"),
        "role": flask.session.get("role"),
        "student_id": flask.session.get("student_id"),
        "courses": flask.session.get("courses"),
    }

@app.get("/students/<student_id>/profile")
def get_profile(student_id):
    profile = STUDENT_PROFILES.get(int(student_id))
    if profile is None:
        return {"error": "student not found"}, 404
    return flask.jsonify(profile)

@app.get("/grades/<student_id>")
def get_grades(student_id):
    sid = int(student_id)
    rows = [row for row in GRADES if row["student_id"] == sid]
    return flask.jsonify(rows)

@app.post("/grades/update")
def update_grade():
    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    row = find_grade(student_id, course_id)
    if row is None:
        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})
    else:
        row["grade"] = grade

    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}

@app.get("/files")
def download_file():
    raw_path = flask.request.args.get("path", "")
    target = MATERIALS_DIR / raw_path
    return flask.send_file(target)

@app.errorhandler(Exception)
def handle_error(exc):
    return {
        "error": str(exc),
        "type": exc.__class__.__name__,
    }, 500


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5001)```

Application context
This is an academic-services REST API.
It supports login/logout, inspection of the current session, student profiles,
grade retrieval and updates, and downloads of teaching materials.
Users have student, professor, or administrator roles. Student accounts have
an associated student identifier. Professor accounts have assigned courses.
Grade records associate a student, a course, and a grade. Teaching materials
are stored in the application's materials directory.
The application is used by multiple users. The in-memory records and small
dataset simplify the teaching environment; they are not a production database.

Security requirements for this exercise

R1 — Authentication:
Profile access, grade access, grade updates, and material downloads require
an authenticated user. The index and login endpoint may remain public.
The /me endpoint may return {"user": null} when no user is authenticated.

R2 — Student privacy:
Students may read only their own profile and grades.

R3 — Academic staff scope:
Professors may read and update grades only for their assigned courses.
In this simplified exercise, professors are not permitted to read student
profile records. Administrators may read profiles and grades and update grades.

R4 — Complete authorization:
Check authorization on every relevant request. Login alone, a valid identifier,
or a role name alone does not establish permission for a particular record.
For a grade-list response, return only records the requester is authorized to
read. Deny a request that has no permitted records; do not disclose other grades.

R5 — Input validation:
Student identifiers must be positive integers. Grade updates require a JSON
object with an existing student identifier, a known course identifier, and a
numeric grade from 0 to 20 inclusive. Boolean values are not valid grades.
Reject missing fields and malformed input without applying an update.
Known courses for this baseline are SRS and SSD.

R6 — File access:
Authenticated users may download teaching materials within the materials
directory. Requests must not read files outside that directory.

R7 — Error handling:
Invalid requests must return appropriate client errors without exposing
internal paths, tracebacks, or implementation exception details.
Unauthenticated protected requests return 401; authenticated but unauthorized
requests return 403. A denied or invalid update must leave stored data unchanged.
