# Static security review

Target: `baseline_secure_coding_api(1).py` · Review type: source-only static analysis · No code execution or external research

## 1. Findings summary

Overall assessment: The source contains several significant security weaknesses, particularly missing authorization checks, unrestricted grade modification, arbitrary file access, and insecure session configuration.

I identified 7 potential vulnerabilities. The findings below distinguish directly observable implementation defects from risks whose exploitability depends on deployment configuration or intended authorization policy.

| ID     | Finding                                        | Location                      | Severity | Confidence |
| ------ | ---------------------------------------------- | ----------------------------- | -------- | ---------- |
| SEC-01 | Unauthenticated access to student profiles     | `get_profile()`, L115–120     | High     | High       |
| SEC-02 | Unauthenticated access to student grades       | `get_grades()`, L122–126      | High     | High       |
| SEC-03 | Missing authorization on grade updates         | `update_grade()`, L128–142    | Critical | High       |
| SEC-04 | Path traversal in file downloads               | `download_file()`, L144–148   | High     | High       |
| SEC-05 | Hardcoded Flask secret key                     | App configuration, L7–8       | High     | High       |
| SEC-06 | Debug mode enabled on network interface        | Application startup, L158–159 | High     | High       |
| SEC-07 | Sensitive exception details exposed to clients | `handle_error()`, L150–155    | Medium   | High       |

Severity assumes the API is reachable by users who should not automatically have all privileges. Actual severity depends on deployment exposure and the intended access-control policy.

## 2. Supporting explanations

### SEC-01 — Unauthenticated access to student profiles



High

High confidence



Affected location

- File: `baseline_secure_coding_api(1).py`
- Function: `get_profile(student_id)`
- Lines: 115–120

Code facts

The endpoint retrieves a student profile using the supplied student identifier:

```
@app.get("/students/<student_id>/profile")def get_profile(student_id):    profile = STUDENT_PROFILES.get(int(student_id))    if profile is None:        return {"error": "student not found"}, 404    return flask.jsonify(profile)
```

There is no authentication or authorization check.

Attacker-controlled input and data flow

1. An attacker supplies a student identifier in the URL.
2. The identifier is converted to an integer.
3. The application looks up the corresponding profile.
4. The profile is returned without checking the session or the caller's role.

Missing security control / root cause

The endpoint does not enforce authentication or ownership-based authorization.

Preconditions and potential impact

The endpoint must be reachable by the attacker.

Potential consequences include:

- Unauthorized disclosure of student names.
- Exposure of student email addresses.
- Disclosure of academic program information.
- Enumeration of student records.

Proposed test

Send a request without an authenticated session:

```
GET /students/1001/profile
```

Expected secure behavior, assuming profiles are restricted: return `401 Unauthorized` or an appropriate authorization error.

Repeat using another student's identifier while authenticated as a student.

Assumptions and uncertainty

The supplied context identifies student profiles as academic records but does not explicitly define their visibility policy.

The finding is based on the absence of access control. Whether public profile access is intentionally permitted remains unknown.

### SEC-02 — Unauthenticated access to student grades



High

High confidence



Affected location

- Function: `get_grades(student_id)`
- Lines: 122–126

Code facts

```
@app.get("/grades/<student_id>")def get_grades(student_id):    sid = int(student_id)    rows = [row for row in GRADES if row["student_id"] == sid]    return flask.jsonify(rows)
```

The endpoint returns every grade associated with the requested student identifier.

Attacker-controlled input and data flow

The attacker controls `student_id` in the URL.

That identifier directly determines which records are retrieved from `GRADES`.

No session or role information is checked.

Missing security control / root cause

There is no authentication requirement and no object-level authorization.

In particular, the endpoint does not establish that:

- A student is requesting their own grades.
- A professor is requesting grades for an assigned course.
- An administrator has the necessary privileges.

Preconditions and potential impact

An attacker must be able to reach the endpoint.

Potential impact:

- Disclosure of individual academic performance.
- Unauthorized access to other students' grades.
- Enumeration of student academic records.

Proposed test

Without logging in:

```
GET /grades/1002
```

Then authenticate as Alice and request Bob's grades:

```
GET /grades/1002
```

Expected secure behavior, assuming grades are private: deny unauthenticated access and prevent students from retrieving other students' grades.

Assumptions and uncertainty

The application context does not explicitly state whether professors can view grades for all courses or only their assigned courses. That policy needs clarification.

The missing authorization checks are demonstrated code facts.

### SEC-03 — Missing authorization on grade updates



Critical

High confidence



Affected location

- Function: `update_grade()`
- Lines: 128–142

Code facts

```
@app.post("/grades/update")def update_grade():    data = flask.request.get_json()    student_id = data["student_id"]    course_id = data["course_id"]    grade = data["grade"]    row = find_grade(student_id, course_id)    if row is None:        GRADES.append({"student_id": student_id, "course_id": course_id, "grade": grade})    else:        row["grade"] = grade    return {"status": "ok", "student_id": student_id, "course_id": course_id, "grade": grade}
```

The endpoint accepts the student identifier, course identifier, and grade from the request body.

It then modifies the grade records directly.

Attacker-controlled input and data flow

An attacker controls all three relevant values:

- `student_id`
- `course_id`
- `grade`

These values flow directly into the grade lookup and modification operations.

There is no check of the authenticated user's identity or role.

Missing security control / root cause

The endpoint lacks:

- Authentication enforcement.
- Role-based authorization.
- Professor-to-course authorization.
- Validation of grade values.
- Restrictions on which student/course combinations can be modified.

The most significant problem is the absence of authorization before modifying academic records.

Preconditions and potential impact

The endpoint must be accessible to the attacker.

Potential consequences include:

- Students changing their own grades.
- Students changing other students' grades.
- Unauthorized creation of grade records.
- Professors modifying grades for courses they do not teach.
- Unauthorized manipulation of academic records.

Proposed test

First, authenticate as a student. Then submit:

```
POST /grades/update
Content-Type: application/json

{
  "student_id": 1002,
  "course_id": "SRS",
  "grade": 20
}
```

Check whether the grade changes.

Repeat without authentication and as a professor assigned to a different course.

Expected secure behavior:

- Unauthenticated requests should be rejected.
- Students should not be permitted to update grades.
- Professors should only update grades for their assigned courses.
- Administrators should follow an explicitly defined administrative policy.

Assumptions and uncertainty

The application context establishes three roles and professor course assignments.

It does not explicitly specify the exact administrative grade-management policy or valid grade range. These should be defined before implementation.

The missing authorization is a demonstrated code fact, not merely an inferred concern.

### SEC-04 — Path traversal in file downloads



High

High confidence



Affected location

- Function: `download_file()`
- Lines: 144–148

Code facts

```
@app.get("/files")def download_file():    raw_path = flask.request.args.get("path", "")    target = MATERIALS_DIR / raw_path    return flask.send_file(target)
```

The application joins a user-controlled path with the materials directory and passes the resulting path to `flask.send_file()`.

Attacker-controlled input and data flow

The attacker controls the `path` query parameter.

The input flows directly into filesystem path construction.

There is no validation that the resulting path remains inside `MATERIALS_DIR`.

Missing security control / root cause

The application does not enforce filesystem containment.

Path traversal sequences may allow a caller to reference files outside the intended materials directory.

There is also no visible authorization check protecting downloaded materials.

Preconditions and potential impact

The attacker needs access to the endpoint.

The filesystem must contain accessible files outside the materials directory.

Potential consequences:

- Unauthorized disclosure of application files.
- Exposure of configuration or source files.
- Disclosure of other locally accessible sensitive data.

The actual extent depends on operating-system permissions and deployment layout.

Proposed test

Request an ordinary file:

```
GET /files?path=secure-coding.txt
```

Then test a traversal attempt:

```
GET /files?path=../../baseline_secure_coding_api(1).py
```

Expected secure behavior: reject paths that resolve outside the materials directory.

Also test absolute paths, encoded traversal sequences, and symbolic-link cases.

Assumptions and uncertainty

The context says teaching materials are stored in the materials directory.

It does not explicitly establish whether all materials are public. The absence of a containment check is demonstrable; successful access to an arbitrary external file depends on filesystem conditions.

### SEC-05 — Hardcoded Flask secret key



High

High confidence



Affected location

- Application configuration
- Lines: 7–8

Code facts

```
app = flask.Flask(__name__)app.config["SECRET_KEY"] = "dev-secret-key"
```

The Flask secret key is hardcoded to a predictable development-oriented value.

Attacker-controlled input and data flow

The attacker does not directly supply the secret key.

Instead, the concern is that an attacker who obtains the source code or knows the deployed configuration can know the key.

Flask uses this key to protect its client-side session cookies.

Missing security control / root cause

There is no visible secure secret-management mechanism or environment-specific secret configuration.

The root cause is the use of a fixed, predictable secret.

Preconditions and potential impact

If the application is deployed with this exact key, an attacker who knows it may be able to forge Flask session cookies.

Potential impact includes:

- Session impersonation.
- Modification of session attributes.
- Potential privilege escalation by altering role-related session data.

The last consequence is particularly relevant because authorization decisions should not rely on untrusted session values.

Proposed test

In an isolated test environment:

1. Inspect the configured secret key.
2. Establish an authenticated session.
3. Assess whether a client capable of signing Flask session cookies with the known key can construct a modified session.
4. Submit that session and observe whether the application accepts it.

Expected secure behavior: use a sufficiently random secret supplied through protected deployment configuration, not a publicly known development constant.

Assumptions and uncertainty

This finding assumes the shown configuration is used in deployment.

The source does not establish whether an external deployment mechanism overrides the key.

The risk is therefore conditional on the actual runtime configuration.

### SEC-06 — Debug mode enabled on a network interface



High

High confidence



Affected location

- Application startup
- Lines: 158–159

Code facts

```
if __name__ == "__main__":    app.run(debug=True, host="0.0.0.0", port=5001)
```

The application is configured to:

- Enable Flask debug mode.
- Listen on all network interfaces.

Attacker-controlled input and execution path

An attacker with network access may send requests that trigger application exceptions.

These exceptions may activate debug-related behavior.

Missing security control / root cause

Debug mode is enabled in the application startup configuration.

The application also binds to `0.0.0.0`, making it reachable through network interfaces when network controls permit.

Preconditions and potential impact

The application must be launched through this startup block and be reachable by an attacker.

Potential consequences include:

- Exposure of debugging information.
- Increased attack surface through development tooling.
- Potential interactive debugger exposure, depending on Flask/Werkzeug version and deployment behavior.

Proposed test

Start the application in an isolated environment and inspect its debug behavior.

Trigger an exception through an invalid request and determine:

- Whether debug responses are exposed remotely.
- Whether an interactive debugger is available.
- Whether external clients can reach the service.

Expected secure behavior: production deployments should disable debug mode and use an appropriately configured production server.

Assumptions and uncertainty

The source demonstrates the development server configuration but does not establish how the application is actually deployed.

The impact depends on the runtime environment, network accessibility, and framework version.

### SEC-07 — Sensitive exception details exposed to clients



Medium

High confidence



Affected location

- Function: `handle_error(exc)`
- Lines: 150–155

Code facts

```
@app.errorhandler(Exception)def handle_error(exc):    return {        "error": str(exc),        "type": exc.__class__.__name__,    }, 500
```

The application returns exception messages and exception class names directly to the caller.

Attacker-controlled input and data flow

An attacker can submit malformed or unexpected inputs to endpoints.

For example:

- Invalid student identifiers.
- Missing JSON properties.
- Unexpected JSON types.
- Invalid file paths.

These inputs may trigger exceptions handled by `handle_error()`.

Missing security control / root cause

The global exception handler does not distinguish between internal diagnostic information and information appropriate for external clients.

There is no visible generic error response or separate protected logging mechanism.

Preconditions and potential impact

An attacker must be able to trigger an exception.

Potential impact:

- Disclosure of internal implementation details.
- Exposure of filesystem paths.
- Identification of internal exception types.
- Assistance in developing further attacks.

Proposed test

Submit malformed JSON to `/grades/update`:

```
POST /grades/update
Content-Type: application/json

{}
```

Inspect the response for internal exception details.

Expected secure behavior: return a generic error message to clients while retaining detailed diagnostics in appropriately protected server logs.

Assumptions and uncertainty

The exact information disclosed depends on the exception raised and the runtime environment.

The direct exposure of exception messages is demonstrated by the source.

## 3. Additional observations (not classified as confirmed vulnerabilities)

These observations deserve attention but are not included as independent vulnerability findings because the source alone does not establish a sufficiently specific security impact.

| Area               | Observation                                                                         | Security relevance                                                                                 |
| ------------------ | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Authentication     | Passwords are stored in plaintext in `USERS` (L27–42).                              | Credential exposure if application memory or source data is compromised.                           |
| Login              | No visible login rate limiting (L82–96).                                            | Potential brute-force attacks.                                                                     |
| Session management | Login does not explicitly regenerate the session identifier (L91–94).               | Session fixation risk depends on session lifecycle and client behavior.                            |
| Input validation   | Grade updates accept unvalidated values (L132–142).                                 | Invalid or unexpected academic data may be stored.                                                 |
| HTTP methods       | No visible CSRF protection on state-changing endpoints.                             | Relevant if cookie-based authentication is used with browser clients.                              |
| Data storage       | Records are held in process memory.                                                 | Data persistence, concurrency, and integrity limitations; not inherently a security vulnerability. |
| Error handling     | The global exception handler returns HTTP 500 for all caught exceptions (L150–155). | Incorrect error classification and potentially excessive disclosure.                               |

## 4. Recommended testing priorities

Based on potential impact and the demonstrated code paths:

| Priority | Finding | Primary security property to test |
| -------- | ------- | --------------------------------- |
| 1        | SEC-03  | Grade modification authorization  |
| 2        | SEC-04  | Filesystem containment            |
| 3        | SEC-02  | Grade confidentiality             |
| 4        | SEC-01  | Profile confidentiality           |
| 5        | SEC-05  | Session integrity                 |
| 6        | SEC-06  | Debugger exposure                 |
| 7        | SEC-07  | Error information disclosure      |

## 5. Overall conclusion

The most serious issue is the absence of authorization enforcement on the academic data endpoints.

In particular, `update_grade()` allows request-supplied values to modify academic records without checking the caller's identity, role, or course permissions. This creates a direct risk to grade integrity.

The file-download endpoint also lacks a visible filesystem containment control, creating a potential path traversal vulnerability.

The profile and grade retrieval endpoints similarly lack authentication and object-level authorization.

Finally, the hardcoded secret key, debug configuration, and exception disclosure weaken session security and information confidentiality.

Review limitations: This is a static review of one Python source file. No execution, dependency inspection, deployment inspection, network testing, or external research was performed. The findings identify weaknesses visible in the supplied implementation; they do not establish that every exploit will succeed in every deployment.

The absence of additional findings should not be interpreted as evidence that the application is secure.