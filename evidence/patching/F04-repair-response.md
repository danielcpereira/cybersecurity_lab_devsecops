The vulnerability is isolated to update_grade(). The minimal fix is to enforce authentication and resource-specific authorization before reading or modifying GRADES.

I would keep the existing endpoint, request format, successful response body, and HTTP 200 behavior unchanged.
1. Proposed unified diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@
 def find_grade(student_id, course_id):
     for row in GRADES:
         if row["student_id"] == student_id and row["course_id"] == course_id:
             return row
     return None


+def require_grade_update_permission(course_id):
+    """Enforce authentication and authorization for grade updates."""
+    username = flask.session.get("user")
+
+    if not username:
+        return {"error": "authentication required"}, 401
+
+    # Resolve the user from the server-side user registry rather than
+    # trusting role or course information supplied by the request.
+    user = USERS.get(username)
+
+    if user is None:
+        return {"error": "authentication required"}, 401
+
+    if user.role == "admin":
+        return None
+
+    if user.role == "professor" and course_id in (user.courses or []):
+        return None
+
+    return {"error": "forbidden"}, 403
+
+
 # -----------------------------------------------------------------------------
 # REST API Endpoints
 # -----------------------------------------------------------------------------
@@
 @app.post("/grades/update")
 def update_grade():
     data = flask.request.get_json()

     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]

+    # Authorization must happen on every request and before any mutation.
+    permission_error = require_grade_update_permission(course_id)
+    if permission_error is not None:
+        return permission_error
+
     row = find_grade(student_id, course_id)
     if row is None:
         GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})


The remainder of update_grade() stays unchanged.
2. Security control implemented
The patch introduces a centralized authorization function with three decisions:
Unauthenticated caller
401 Unauthorized

No authenticated session identity is available. The request is rejected.
Administrator
200 Allowed

Administrators can update grades in any course.
Professor
200 Allowed

Only when the requested course belongs to their assigned courses.
Student or unauthorized professor
403 Forbidden

The operation is rejected without changing stored data.
Why this addresses the root cause
1. Authentication is mandatory (R1).

The endpoint checks for an authenticated session before allowing an update.

2. Authorization is role- and resource-specific (R3).

A professor role alone is insufficient. The requested course_id must also belong to that professor.

3. Authorization is evaluated on every request (R4).

The permission check runs inside update_grade(), rather than relying on a previous login check or a client-side restriction.

4. Unauthorized requests cannot mutate data (R7).

The permission check occurs before find_grade() and, importantly, before either GRADES.append() or modifying an existing row.
3. Affected paths
The primary affected path is:
HTTP method	Endpoint	Required control
POST	/grades/update	Authentication + role + course assignment

Other paths in the supplied application:
Endpoint	Assessment
POST /login	Establishes the session; no grade mutation
POST /logout	Clears the session
GET /me	Returns session information
GET /students/<student_id>/profile	Read-only
GET /grades/<student_id>	Read-only, but currently lacks access control
GET /files	File access; separate security concern

Important: The GET endpoints do not require the same grade-update permission because they do not modify grades. However, /grades/<student_id> exposes student grades without authentication or ownership checks. That deserves a separate authorization review.

If other endpoints, background jobs, or administrative interfaces can modify GRADES, they must enforce equivalent authorization. The supplied file contains no other grade-writing endpoint.
4. Additional regression tests
The supplied tests cover the essential authorization cases. I would add the following.
Test	Expected result
Professor assigned to SRS creates a new SRS grade	200
Professor assigned to SRS cannot create an SSD grade	403
Professor cannot modify an existing SSD grade	403, unchanged
Admin updates a grade in an unassigned course	200
Student attempts to create a new grade	403
Session contains a forged professor role but username is Alice	403
Session contains a forged course assignment but username is prof_srs	403
Session has a deleted/unknown username	401
Logout followed by grade update	401

The forged-session tests are particularly useful because they verify that authorization uses the server-side USERS registry rather than trusting role and course information stored in the session.

Example:
def test_session_role_is_not_trusted(client):    with client.session_transaction() as sess:        sess["user"] = "alice"        sess["role"] = "admin"    response = client.post(        "/grades/update",        json={"student_id": 1001, "course_id": "SRS", "grade": 20},    )    assert response.status_code == 403    assert api.find_grade(1001, "SRS")["grade"] == 14def test_session_course_assignment_is_not_trusted(client):    with client.session_transaction() as sess:        sess["user"] = "prof_srs"        sess["role"] = "professor"        sess["courses"] = ["SRS", "SSD"]    response = client.post(        "/grades/update",        json={"student_id": 1001, "course_id": "SSD", "grade": 0},    )    assert response.status_code == 403    assert api.find_grade(1001, "SSD")["grade"] == 16def test_professor_cannot_create_grade_in_unassigned_course(client):    login(client, "prof_srs", "profpw")    response = client.post(        "/grades/update",        json={"student_id": 1002, "course_id": "SSD", "grade": 18},    )    assert response.status_code == 403    assert api.find_grade(1002, "SSD") is None



5. Remaining assumptions and limitations
There are a few points worth documenting in the security review.
1. Session integrity: Flask's default session is cookie-based and signed. The SECRET_KEY in this example is a development placeholder. Production must use a strong, randomly generated secret stored outside the source code.
2. User registry: The patch assumes USERS is the authoritative source of user roles and course assignments. In a production application, these should come from a trusted database or identity/authorization service.
3. Course assignment changes: Permissions are checked against the current server-side user record on every request. This avoids trusting potentially stale client-provided role or course data.
4. CSRF: Authentication and authorization do not prevent cross-site request forgery. If cookie-based sessions are used in production, protect state-changing endpoints with CSRF tokens and appropriate cookie settings.
5. Input validation: The patch intentionally does not change grade validation, request parsing, or data types. These should be addressed separately without expanding the scope of this vulnerability fix.
6. Concurrency: The in-memory implementation is not transactional or thread-safe. A production database should perform authorization and the grade update within an appropriately controlled transaction.
6. Expected verification
After applying the patch, the supplied test suite should produce:
Test	Expected
Assigned professor updates SRS	PASS
Anonymous update	PASS
Student updates own grade	PASS
Student updates another student's grade	PASS
Professor updates unassigned SSD	PASS
Administrator updates any grade	PASS

Run:
pytest -q tests_security/test_grade_authorization.py


Final assessment: This is a minimal, reviewable, root-cause fix for F04. It implements server-side, per-request authorization without removing functionality or changing the legitimate API response contract. The additional session-tampering tests are important to demonstrate that the authorization decision cannot be bypassed by manipulating client-held session fields.