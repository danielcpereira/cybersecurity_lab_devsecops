The fix is to split authorization into two stages:
1. Before parsing the body: authenticate the user and reject students.
2. After parsing the body: verify that a professor is assigned to the requested course. Administrators are allowed.
This ensures malformed or empty requests cannot trigger a 500 before authentication is enforced.
Revised unified diff
--- a/baseline_secure_coding_api.py
+++ b/baseline_secure_coding_api.py
@@
-def require_grade_update_permission(course_id):
-    """Enforce authentication and authorization for grade updates."""
+def require_grade_update_permission():
+    """Check authentication and basic role authorization."""
     username = flask.session.get("user")

     if not username:
         return {"error": "authentication required"}, 401

-    # Resolve the user from the server-side user registry rather than
-    # trusting role or course information supplied by the request.
+    # Resolve identity and permissions from the server-side user registry.
     user = USERS.get(username)

     if user is None:
         return {"error": "authentication required"}, 401

-    if user.role == "admin":
+    if user.role in ("admin", "professor"):
         return None

-    if user.role == "professor" and course_id in (user.courses or []):
-        return None
-
     return {"error": "forbidden"}, 403


+def require_professor_course_assignment(user, course_id):
+    """Check whether a professor is assigned to the requested course."""
+    if user.role == "admin":
+        return None
+
+    if course_id in (user.courses or []):
+        return None
+
+    return {"error": "forbidden"}, 403
+
+
@@
 @app.post("/grades/update")
 def update_grade():
+    # Authenticate and reject students before parsing the request body.
+    permission_error = require_grade_update_permission()
+    if permission_error is not None:
+        return permission_error
+
+    user = USERS[flask.session["user"]]
+
     data = flask.request.get_json()

     student_id = data["student_id"]
     course_id = data["course_id"]
     grade = data["grade"]

-    # Authorization must happen on every request and before any mutation.
-    permission_error = require_grade_update_permission(course_id)
+    # Professors must be assigned to the requested course.
+    permission_error = require_professor_course_assignment(user, course_id)
     if permission_error is not None:
         return permission_error

     row = find_grade(student_id, course_id)


Resulting authorization sequence
POST /grades/update


1. Authenticate using server-side identity

No valid user → 401


2. Check role

Student or other role → 403


3. Parse request body

Read student_id, course_id and grade


4. Check professor course assignment

Unassigned course → 403

Admin → allowed


5. Perform grade update
200 OK


Additional regression tests
I recommend adding these three tests to prevent this specific regression:
def test_unauthenticated_empty_json_returns_401(client):    response = client.post("/grades/update", json={})    assert response.status_code == 401def test_unauthenticated_non_json_returns_401(client):    response = client.post(        "/grades/update",        data="not json",        content_type="text/plain",    )    assert response.status_code == 401def test_student_empty_json_returns_403(client):    login(client, "alice", "alicepw")    response = client.post("/grades/update", json={})    assert response.status_code == 403



Remaining limitation: An authenticated professor sending malformed JSON can still receive a 500 under the existing global exception handler. That is a separate input-validation/error-handling issue and should be addressed independently rather than broadening this authorization patch.

The revised sequence satisfies R1, R3, R4 and R7 while preserving the successful API response contract.