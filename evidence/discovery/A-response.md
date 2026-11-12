# Static security review

Target: `baseline_secure_coding_api.py`\
Review type: Source-only static analysis\
Scope: The 159-line Python Flask application supplied in the request.

The review identifies 7 potential security findings. The most significant concerns are missing authorization checks, unrestricted grade modification, arbitrary file access, and disclosure of internal exception details.

No code was executed, no external sources were consulted, and no patches have been generated.

## 1. Findings summary

| ID     | Finding                                                      | Location      | Severity | Confidence |
| ------ | ------------------------------------------------------------ | ------------- | -------- | ---------- |
| SEC-01 | Hardcoded Flask session secret                               | Line 8        | High     | High       |
| SEC-02 | Missing authentication and authorization on student profiles | Lines 115–120 | High     | High       |
| SEC-03 | Missing authorization on grade retrieval                     | Lines 122–126 | High     | High       |
| SEC-04 | Unrestricted grade modification                              | Lines 128–142 | Critical | High       |
| SEC-05 | Path traversal in file download endpoint                     | Lines 144–148 | High     | High       |
| SEC-06 | Sensitive exception information disclosure                   | Lines 150–155 | Medium   | High       |
| SEC-07 | Debug mode enabled on externally bound server                | Lines 158–159 | High     | High       |

Severity represents potential risk, not confirmed exploitability in an unknown deployment environment.

## 2. Supporting explanations

### SEC-01 — Hardcoded Flask session secret



High

High confidence



Location: Line 8

```
app = flask.Flask(__name__)app.config["SECRET_KEY"] = "dev-secret-key"
```

Demonstrated code facts

The Flask application uses a statically defined secret key. The value is embedded directly in the application source.

Flask uses this secret to sign session cookies.

Attacker-controlled input and data flow

An attacker who obtains the application source or otherwise discovers the secret can potentially construct or modify valid Flask session cookies.

The session contains security-relevant values:

- `user`
- `role`
- `student_id`
- `courses`

These are assigned during login at lines 91–94.

Missing security control and root cause

There is no evidence of:

- Environment-specific secret configuration.
- Secret rotation.
- Secure secret provisioning.
- Separation between development and production secrets.

The root cause is using a predictable, hardcoded development credential for session signing.

Preconditions and potential impact

An attacker must know or obtain the secret and be able to submit a forged session cookie.

Potential consequences include session impersonation and manipulation of session attributes.

The impact depends on whether downstream endpoints trust those attributes.

Proposed test

1. Start the application in a controlled test environment.
2. Authenticate as a low-privilege user.
3. Inspect the session cookie.
4. Using the configured secret, attempt to construct a valid cookie with modified session values.
5. Request `/me` and compare the returned values.

Assumptions and uncertainty

Assumption: The application uses Flask's default cookie-based session implementation.

The secret is demonstrably hardcoded. Successful privilege escalation through cookie manipulation depends on downstream authorization behavior.

### SEC-02 — Missing authentication and authorization on student profiles



High

High confidence



Location: Lines 115–120\
Function: `get_profile(student_id)`

```
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))    if profile is None:        return {"error": "student not found"}, 404    return flask.jsonify(profile)
```

Demonstrated code facts

The endpoint:

- Accepts a student ID through the URL.
- Converts it to an integer.
- Retrieves the corresponding profile.
- Returns the profile without checking the authenticated session.

The profile contains student names, email addresses, and program information.

Attacker-controlled input and data flow

An attacker controls the `student_id` URL parameter.

Example:

```
GET /students/1001/profile
```

The supplied identifier is directly used to retrieve a profile.

Missing security control and root cause

There is no authentication check or ownership/role-based authorization check.

The implementation assumes that knowing or supplying a student ID is sufficient to access the corresponding profile.

Preconditions and potential impact

The endpoint must be reachable by the attacker.

Potential consequences:

- Unauthorized disclosure of student information.
- Enumeration of student profiles.
- Privacy violations.

Proposed test

1. Access the endpoint without logging in.
2. Request another student's profile while authenticated as a different student.
3. Compare the returned information with the expected access policy.

Assumptions and uncertainty

Assumption: Student profiles are intended to be restricted to their owners or authorized university personnel.

If profiles are intentionally public, this may not constitute a vulnerability. The intended access policy is not supplied.

### SEC-03 — Missing authorization on grade retrieval



High

High confidence



Location: Lines 122–126\
Function: `get_grades(student_id)`

```
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)
```

Demonstrated code facts

The endpoint retrieves all grade records belonging to a supplied student ID.

It does not inspect:

- The authenticated user.
- The user's role.
- The user's student ID.
- The user's course permissions.

Attacker-controlled input and data flow

The attacker controls the URL parameter.

For example:

```
GET /grades/1002
```

The supplied identifier determines which student's grades are returned.

Missing security control and root cause

No access-control mechanism enforces ownership or authorized academic access.

The root cause is relying on a caller-supplied student identifier without verifying the caller's permissions.

Preconditions and potential impact

The attacker needs network access to the endpoint.

Potential consequences:

- Disclosure of individual student grades.
- Enumeration of grades across multiple students.
- Exposure of academic performance information.

Proposed test

1. Request grades without authentication.
2. Authenticate as student 1001.
3. Request `/grades/1002`.
4. Authenticate as the professor and test access to both SRS and SSD records.

Compare results against the intended academic access policy.

Assumptions and uncertainty

Assumption: Grades are confidential and students should only access their own records.

Whether professors can access grades across courses is unknown. The `courses` session attribute suggests course-based permissions may be intended, but no enforcement is present in this endpoint.

### SEC-04 — Unrestricted grade modification



Critical

High confidence



Location: Lines 128–142\
Function: `update_grade()`

```
@app.post("/grades/update")def update_grade():    data = flask.request.get_json()    student_id = data["student_id"]    course_id = data["course_id"]    grade = data["grade"]    row = find_grade(student_id, course_id)    if row is None:        GRADES.append({            "student_id": student_id,            "course_id": course_id,            "grade": grade        })    else:        row["grade"] = grade    return {        "status": "ok",        "student_id": student_id,        "course_id": course_id,        "grade": grade    }
```

Demonstrated code facts

The endpoint:

- Does not verify authentication.
- Does not verify the caller's role.
- Does not verify course ownership.
- Does not validate the grade's permitted range or type.
- Allows insertion of new grade records.
- Allows modification of existing grade records.

The application defines students, professors, and administrators, but this endpoint does not distinguish between them.

Attacker-controlled input and data flow

All three relevant values originate from the request body:

```
{
  "student_id": 1001,
  "course_id": "SRS",
  "grade": 20
}
```

The values flow directly into `find_grade()` and subsequently into the in-memory grade database.

An unauthenticated caller can potentially submit the same request.

Missing security control and root cause

The endpoint lacks:

- Authentication enforcement.
- Role-based authorization.
- Course-level authorization.
- Student ownership restrictions.
- Input validation and business-rule enforcement.

The root cause is treating a grade modification request as trusted without establishing the caller's authority or validating the requested change.

Preconditions and potential impact

The endpoint must be reachable.

Potential consequences:

- Unauthorized grade modification.
- Fabrication of academic records.
- Modification of another student's results.
- Creation of records for arbitrary student/course combinations.
- Corruption of grade data.

This is the highest-priority finding because it directly affects the integrity of academic records.

Proposed test

Run the following cases in an isolated test environment:

| Test | Request condition                         | Expected secure behavior |
| ---- | ----------------------------------------- | ------------------------ |
| T1   | No authentication                         | Reject                   |
| T2   | Student attempts grade modification       | Reject                   |
| T3   | Professor modifies an unauthorized course | Reject                   |
| T4   | Professor modifies an authorized course   | Allow if policy permits  |
| T5   | Grade exceeds permitted range             | Reject                   |
| T6   | Unknown student ID                        | Reject                   |
| T7   | Unknown course ID                         | Reject                   |

Verify that rejected requests leave `GRADES` unchanged.

Assumptions and uncertainty

Assumption: Grade modification is a privileged operation restricted to authorized academic personnel.

The exact grading scale, professor permissions, and administrative override rules are not provided.

The absence of authorization checks is a demonstrated code fact; the precise authorization policy is an inferred requirement.

### SEC-05 — Path traversal in file download endpoint



High

High confidence



Location: Lines 144–148\
Function: `download_file()`

```
@app.get("/files")def download_file():    raw_path = flask.request.args.get("path", "")    target = MATERIALS_DIR / raw_path    return flask.send_file(target)
```

Demonstrated code facts

The endpoint accepts a filename/path from the request query string.

It joins that value to `MATERIALS_DIR` and passes the resulting path to `flask.send_file()`.

There is no visible validation or containment check.

Attacker-controlled input and data flow

The attacker controls the `path` parameter.

Example:

```
GET /files?path=../../some-file.txt
```

The path is combined with the materials directory.

Python's path joining does not, by itself, guarantee that the resulting path remains inside the intended directory.

Missing security control and root cause

The application does not:

- Reject path traversal components.
- Resolve and verify the final path.
- Enforce that the resolved path remains inside `MATERIALS_DIR`.
- Restrict access to an explicit list of permitted files.

The root cause is treating an untrusted path as a trusted filesystem location.

Preconditions and potential impact

The attacker needs access to the endpoint and the application process must have filesystem read permissions on the targeted file.

Potential consequences:

- Unauthorized access to files outside the materials directory.
- Disclosure of application configuration.
- Exposure of other readable files.

The actual impact depends on the operating system, filesystem permissions, and Flask/Werkzeug behavior.

Proposed test

1\. Request a legitimate file:

```
GET /files?path=srs-summary.txt
```

2\. Attempt traversal:

```
GET /files?path=../../some-file.txt
```

3\. Verify whether files outside `MATERIALS_DIR` can be returned.

Use a harmless test file outside the directory rather than sensitive system files.

Assumptions and uncertainty

Assumption: The intended policy is to permit downloads only from `MATERIALS_DIR`.

The vulnerability is supported by the missing path-containment check. Actual exploitation depends on filesystem permissions and deployment configuration.

### SEC-06 — Sensitive exception information disclosure



Medium

High confidence



Location: Lines 150–155\
Function: `handle_error(exc)`

```
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500
```

Demonstrated code facts

The application registers a global exception handler that returns:

- The exception message.
- The exception class name.

These details are sent to the client with an HTTP 500 response.

Attacker-controlled input and data flow

Malformed or unexpected requests may trigger exceptions.

Examples include:

- Invalid student IDs.
- Missing JSON properties.
- Invalid JSON request bodies.
- Unexpected file paths.

The resulting exception is passed directly to the response serializer.

Missing security control and root cause

There is no separation between internal diagnostic information and client-facing error messages.

The root cause is exposing raw exception information to external callers.

Preconditions and potential impact

An attacker must be able to trigger an exception through an accessible endpoint.

Potential consequences:

- Disclosure of internal implementation details.
- Identification of expected request fields.
- Disclosure of filesystem paths or other exception-related details.
- Assistance in constructing further attacks.

Proposed test

Submit malformed requests, such as:

```
GET /students/not-a-number/profile
```

And:

```
POST /grades/update
Content-Type: application/json

{}
```

Inspect the HTTP responses for exception messages and internal details.

Assumptions and uncertainty

The exact information disclosed depends on the exception raised.

The code demonstrably returns raw exception details. Whether those details contain sensitive information depends on runtime conditions.

### SEC-07 — Debug mode enabled on externally bound server



High

High confidence



Location: Lines 158–159

```
if __name__ == "__main__":    app.run(debug=True, host="0.0.0.0", port=5001)
```

Demonstrated code facts

The application:

- Starts Flask with `debug=True`.
- Binds to `0.0.0.0`.
- Listens on port 5001.

Binding to `0.0.0.0` makes the server listen on all available network interfaces.

Attacker-controlled input and data flow

An attacker with network access may send requests that cause application exceptions.

Those exceptions may be presented through Flask's development debugger.

Missing security control and root cause

The development configuration is enabled in the application startup code.

There is no visible distinction between development and production startup configurations.

Preconditions and potential impact

The application must be deployed using this startup path, and the listening interface must be reachable by the attacker.

Potential consequences include:

- Exposure of debugging information.
- Disclosure of application internals.
- Potential interactive debugger exploitation if the debugger is accessible and its protections can be bypassed.

The impact can be severe depending on the deployed Flask/Werkzeug version and debugger exposure.

Proposed test

1. Start the application using the supplied entry point in an isolated environment.
2. Trigger an exception through an HTTP request.
3. Inspect the response for development debugger behavior.
4. Verify whether the debugger interface is externally reachable.

Do not attempt debugger console interaction against a production environment.

Assumptions and uncertainty

The source explicitly enables debug mode.

It does not establish whether this startup path is used in production or whether an external reverse proxy or network restriction prevents access.

Therefore, production exploitability remains deployment-dependent.

## 3. Cross-cutting observations

The following are additional observations that deserve attention but are not classified as separate confirmed vulnerabilities.

| Area             | Code observation                                                              | Security relevance                                                                                     |
| ---------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Authentication   | Login checks credentials against an in-memory user dictionary (lines 82–96).  | No rate limiting or brute-force protection is visible.                                                 |
| Password storage | Passwords are stored as plaintext in `USERS` (lines 36–43).                   | A source or memory disclosure exposes all configured credentials.                                      |
| Session handling | Session values include role and student permissions (lines 91–94).            | Their trustworthiness depends on secret protection and proper authorization enforcement.               |
| CSRF             | State-changing operations use POST requests (lines 98–101 and 128–142).       | No explicit CSRF protection is visible. Exploitability depends on cookie settings and client behavior. |
| Input validation | Student IDs are converted with `int()`, while grade fields are not validated. | Unexpected values can cause exceptions or invalid records.                                             |
| Data persistence | User and grade data are stored in memory.                                     | Restarting the application loses modifications; this is primarily a reliability concern.               |

### Important distinction: CSRF

The source does not demonstrate whether the application is exposed to cross-site request forgery.

Flask's default session mechanism uses cookies, but cookie attributes, browser behavior, and any additional middleware are not fully established by this source.

If browser-based cookie authentication is used, CSRF protection should be evaluated for state-changing endpoints, especially `/grades/update`.

## 4. Prioritization

| Priority | Finding | Reason                                                     |
| -------- | ------- | ---------------------------------------------------------- |
| 1        | SEC-04  | Unauthorized modification of academic records              |
| 2        | SEC-05  | Potential filesystem access outside the intended directory |
| 3        | SEC-02  | Potential disclosure of personal student information       |
| 4        | SEC-03  | Potential disclosure of confidential academic records      |
| 5        | SEC-01  | Potential session forgery if the secret is obtained        |
| 6        | SEC-07  | Development debugger exposure                              |
| 7        | SEC-06  | Internal exception information disclosure                  |

## 5. Review limitations and conclusion

This review is based exclusively on the supplied Python source.

The following were not available for examination:

- Deployment configuration.
- Reverse proxy and network restrictions.
- Flask and Werkzeug versions.
- Browser/client behavior.
- Intended authorization policies.
- Institutional data-classification requirements.
- External authentication or middleware components.

Consequently, findings involving missing controls are reported as code-level observations, while their security implications are qualified by explicit assumptions.

Overall assessment: The application has significant security weaknesses, particularly in authorization and data integrity. The grade modification endpoint is the most serious issue because it permits modification and creation of academic records without checking the caller's identity or permissions.

The absence of a visible security control in this source does not prove that no external control exists. Equally, external controls should not be assumed without evidence.

No patches or code modifications have been made.