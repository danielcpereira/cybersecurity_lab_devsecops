We are now repairing a confirmed vulnerability in the supplied application.
This is repair assistance, not an independent discovery result.

Confirmed finding (F07): download_file() (GET /files?path=...) joins the
user-supplied path to MATERIALS_DIR and passes it to flask.send_file without
any containment check or authentication. Reproduction: ../secret.txt,
sub/../../secret.txt, an absolute path, and ../materials_private/leak.txt
(sibling directory with the same name prefix) all return 200 with the file
contents; an unauthenticated download also returns 200.

Required behavior:
R1: material downloads require an authenticated user; unauthenticated -> 401.
R6: authenticated users may download teaching materials within the materials
    directory. Requests must not read files outside that directory.
R7: invalid requests must return appropriate client errors (4xx) without
    exposing internal paths, tracebacks, or exception details.
Legitimate use case: an authenticated user downloads notes.txt from the
materials directory.
Note: tests replace api.MATERIALS_DIR at runtime (monkeypatch), so the
check must use the current value of MATERIALS_DIR on each request.

Propose a minimal, reviewable patch addressing the root cause.
Preserve the API's legitimate functionality and relevant response contracts.
Do not delete endpoints, disable features, weaken tests, or suppress scanner
rules to hide the issue. Identify all affected paths that need the same
control.
Return a unified diff, explain the control being implemented, and identify
remaining assumptions or limitations. Suggest additional regression tests.


File: baseline_secure_coding_api.py (F04 already patched)
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


def require_grade_update_permission():
    """Check authentication and basic role authorization."""
    username = flask.session.get("user")

    if not username:
        return {"error": "authentication required"}, 401

    # Resolve identity and permissions from the server-side user registry.
    user = USERS.get(username)

    if user is None:
        return {"error": "authentication required"}, 401

    if user.role in ("admin", "professor"):
        return None

    return {"error": "forbidden"}, 403


def require_professor_course_assignment(user, course_id):
    """Check whether a professor is assigned to the requested course."""
    if user.role == "admin":
        return None

    if course_id in (user.courses or []):
        return None

    return {"error": "forbidden"}, 403


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
    # Authenticate and reject students before parsing the request body.
    permission_error = require_grade_update_permission()
    if permission_error is not None:
        return permission_error

    user = USERS[flask.session["user"]]

    data = flask.request.get_json()

    student_id = data["student_id"]
    course_id = data["course_id"]
    grade = data["grade"]

    # Professors must be assigned to the requested course.
    permission_error = require_professor_course_assignment(user, course_id)
    if permission_error is not None:
        return permission_error

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

Security tests: tests_security/test_file_access.py
```python
import baseline_secure_coding_api as api
import pytest

SECRET = "TOP-SECRET-OUTSIDE"
SIBLING = "SIBLING-SECRET"


def login(client, username, password):
    r = client.post("/login", data={"username": username, "password": password},
                    follow_redirects=True)
    assert r.status_code == 200


@pytest.fixture
def materials(tmp_path, monkeypatch):
    mdir = tmp_path / "materials"
    mdir.mkdir()
    (mdir / "sub").mkdir()
    (mdir / "notes.txt").write_text("allowed content", encoding="utf-8")
    secret = tmp_path / "secret.txt"
    secret.write_text(SECRET, encoding="utf-8")
    sib = tmp_path / "materials_private"   # same prefix as "materials"
    sib.mkdir()
    (sib / "leak.txt").write_text(SIBLING, encoding="utf-8")
    monkeypatch.setattr(api, "MATERIALS_DIR", mdir)
    return {"secret": secret}


def assert_denied(r, marker):
    assert 400 <= r.status_code < 500
    assert marker not in r.get_data(as_text=True)


# Permitted operation (must PASS before and after the fix)
def test_authenticated_user_can_download_material(client, materials):
    login(client, "alice", "alicepw")
    r = client.get("/files?path=notes.txt")
    assert r.status_code == 200
    assert r.get_data(as_text=True) == "allowed content"


# Negative cases (must FAIL on the baseline)
def test_unauthenticated_download_is_rejected(client, materials):
    r = client.get("/files?path=notes.txt")
    assert r.status_code == 401


def test_parent_traversal_is_denied(client, materials):
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files?path=../secret.txt"), SECRET)


def test_nested_traversal_is_denied(client, materials):
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files?path=sub/../../secret.txt"), SECRET)


def test_absolute_path_is_denied(client, materials):
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files", query_string={"path": str(materials["secret"])}), SECRET)


def test_sibling_prefix_directory_is_denied(client, materials):
    # Defeats a naive check like str(path).startswith(str(MATERIALS_DIR))
    login(client, "alice", "alicepw")
    assert_denied(client.get("/files?path=../materials_private/leak.txt"), SIBLING)
```

CI failure output (before patch):
```
FAILED test_unauthenticated_download_is_rejected - assert 200 == 401
FAILED test_parent_traversal_is_denied - assert 400 <= 200
FAILED test_nested_traversal_is_denied - assert 400 <= 200
FAILED test_absolute_path_is_denied - assert 400 <= 200
FAILED test_sibling_prefix_directory_is_denied - assert 400 <= 200
PASSED test_authenticated_user_can_download_material
```
