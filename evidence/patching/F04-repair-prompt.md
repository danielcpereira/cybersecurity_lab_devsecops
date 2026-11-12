We are now repairing a confirmed vulnerability in the supplied application.
This is repair assistance, not an independent discovery result.

Confirmed finding (F04): update_grade() (POST /grades/update) writes to GRADES
without checking authentication, role, or professor course assignment.
Any caller can modify or create grades. Reproduction: anonymous request -> 200;
student alice updates her own and Bob's grade -> 200; prof_srs (courses=["SRS"])
updates an SSD grade -> 200 and the stored value changes.

Required behavior:
R1: grade updates require an authenticated user; unauthenticated -> 401.
R3: professors may update grades only for their assigned courses.
    Administrators may update grades. Students may not update grades.
R4: check authorization on every request; login or role alone is not enough.
R7: authenticated but unauthorized -> 403. A denied update must leave stored data unchanged.
Legitimate use cases: prof_srs updates an SRS grade; admin1 updates any grade.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.


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

Security tests: tests_security/test_grade_authorization.py
```python
import baseline_secure_coding_api as api


def login(client, username, password):
    response = client.post(
        "/login",
        data={"username": username, "password": password},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert response.get_json()["user"] == username


def test_assigned_professor_can_update_grade(client):
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 18},
    )
    assert response.status_code == 200
    assert api.find_grade(1001, "SRS")["grade"] == 18


# ---------- F04: negative cases (must FAIL on the baseline) ----------

def test_unauthenticated_update_is_rejected(client):
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 401
    assert api.find_grade(1001, "SRS")["grade"] == 14  # unchanged


def test_student_cannot_update_own_grade(client):
    login(client, "alice", "alicepw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14  # unchanged


def test_student_cannot_update_other_student_grade(client):
    login(client, "alice", "alicepw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SRS", "grade": 0},
    )
    assert response.status_code == 403
    assert api.find_grade(1002, "SRS")["grade"] == 15  # unchanged


def test_professor_cannot_update_unassigned_course(client):
    # Variation: a role-only check ("is professor?") would wrongly allow this.
    login(client, "prof_srs", "profpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SSD", "grade": 0},
    )
    assert response.status_code == 403
    assert api.find_grade(1001, "SSD")["grade"] == 16  # unchanged


def test_admin_can_update_grade(client):
    # Permitted operation that must keep working after the fix.
    login(client, "admin1", "adminpw")
    response = client.post(
        "/grades/update",
        json={"student_id": 1002, "course_id": "SRS", "grade": 17},
    )
    assert response.status_code == 200
    assert api.find_grade(1002, "SRS")["grade"] == 17
```

CI failure output (before patch):
```
FAILED test_unauthenticated_update_is_rejected - assert 200 == 401
FAILED test_student_cannot_update_own_grade - assert 200 == 403
FAILED test_student_cannot_update_other_student_grade - assert 200 == 403
FAILED test_professor_cannot_update_unassigned_course - assert 200 == 403
PASSED test_assigned_professor_can_update_grade
PASSED test_admin_can_update_grade
```
