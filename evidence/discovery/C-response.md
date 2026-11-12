Static security review — Academic Services REST API
Scope: Source code and security requirements R1–R7 supplied in the request only.

Method: Manual static analysis. No code execution, tools, external sources, or published solutions were used.

Overall assessment: 
High security risk
 The application has several demonstrated authorization and input-validation failures. The most significant are unauthenticated access to protected resources, missing record-level authorization, unrestricted grade modification, and directory traversal in file downloads.
1. Findings summary
The following table prioritizes findings by their potential security impact.
ID	Finding	Affected location	Severity	Confidence
SEC-01	Missing authentication and authorization on protected endpoints	get_profile, get_grades, update_grade, download_file	Critical	High
SEC-02	Student profile IDOR / unauthorized profile disclosure	get_profile	High	High
SEC-03	Unauthorized grade disclosure / IDOR	get_grades	High	High
SEC-04	Missing authorization on grade updates	update_grade	Critical	High
SEC-05	Missing grade-update input validation	update_grade	High	High
SEC-06	Directory traversal in material downloads	download_file	High	High
SEC-07	Weak credential and session security	USERS, login	High	High
SEC-08	Excessive exception information disclosure	handle_error	Medium	High
SEC-09	Debug mode enabled	Application startup	High	High
SEC-10	Missing validation of student identifiers	get_profile, get_grades	Medium	High

Severity reflects the potential impact under the supplied requirements, not an independently verified deployment assessment.

2. Supporting explanations
SEC-01 — Missing authentication and authorization on protected endpoints

Critical
 High confidence

Affected locations:
- get_profile(student_id)
- get_grades(student_id)
- update_grade()
- download_file()
Attacker-controlled input and data flow

An unauthenticated attacker can directly invoke the protected endpoints:
- GET /students/1001/profile
- GET /grades/1001
- POST /grades/update
- GET /files?path=srs-summary.txt
These functions do not check whether "user" exists in flask.session.

Missing security control

Authentication checks are absent from all four endpoints.

The application establishes session information during login, but does not enforce authentication when accessing protected functionality.

Preconditions and impact

No authentication is required to exploit these endpoints.

Potential consequences include:
- Disclosure of student profiles.
- Disclosure of academic grades.
- Unauthorized modification of grades.
- Access to teaching materials.
This directly violates R1.

Proposed test

Without logging in, issue requests to each of the four endpoints.

Expected result under R1: HTTP 401 for all protected requests.

Assumptions and uncertainty

The supplied requirements explicitly classify all four endpoints as protected.

The absence of authentication checks is directly demonstrated by the source.

SEC-02 — Student profile IDOR / unauthorized profile disclosure

High
 High confidence

Affected location: get_profile(student_id)

Attacker-controlled input and data flow

The attacker controls the URL parameter:
GET /students/<student_id>/profile


The parameter is converted into an integer and used directly to retrieve a profile:
profile = STUDENT_PROFILES.get(int(student_id))



The endpoint returns the profile without checking the authenticated user's identity or role.

Missing security control

There is no object-level authorization.

The implementation does not verify that:
- A student is requesting their own profile.
- A professor is prohibited from reading profiles.
- An administrator is authorized to access the requested profile.
Preconditions and impact

Under the supplied requirements, an attacker must be authenticated to reach the endpoint legitimately, but authentication alone does not grant access to arbitrary student records.

A student authenticated as Alice could request Bob's profile by changing the identifier to 1002.

Potential impact:
- Exposure of student names.
- Exposure of email addresses.
- Exposure of academic program information.
This violates R2, R3 and R4.

Proposed test
1. Log in as Alice.
2. Request /students/1001/profile.
3. Request /students/1002/profile.
Expected:
- First request: HTTP 200.
- Second request: HTTP 403.
Also test access as a professor and administrator.

Assumptions and uncertainty

The expected permissions are explicitly established by R2 and R3.

The vulnerability is directly demonstrated by the absence of authorization checks.

SEC-03 — Unauthorized grade disclosure / IDOR

High
 High confidence

Affected location: get_grades(student_id)

Attacker-controlled input and data flow

The attacker controls the student identifier in:
GET /grades/<student_id>


The endpoint retrieves all grade records matching that identifier:
sid = int(student_id)rows = [row for row in GRADES if row["student_id"] == sid]



It returns the resulting records without considering the authenticated user's role, student identifier, or assigned courses.

Missing security control

The endpoint does not implement record-level authorization or filtering.

Examples of missing restrictions:
- Students must only see their own grades.
- Professors must only see grades belonging to their assigned courses.
- Administrators may access all grades.
There is also no check that the requester is entitled to see at least one record.

Preconditions and impact

An authenticated student can change the URL parameter to retrieve another student's grades.

A professor can retrieve grades for courses outside their assigned scope.

Potential impact:
- Disclosure of confidential academic records.
- Exposure of grades across courses.
- Violation of student privacy.
This violates R2, R3 and R4.

Proposed test
1. Log in as Alice.
2. Request /grades/1001.
3. Request /grades/1002.
Expected:
- Alice's grades are returned.
- Bob's grades are denied with HTTP 403.
Additional tests:
- Professor assigned to SRS requests grades for a student with SRS and SSD records.
- Professor requests a student with no SRS records.
The response must contain only authorized records. Requests with no permitted records must return 403.

Assumptions and uncertainty

The expected course-level authorization is explicitly established by R3 and R4.

The current implementation returns all records for the requested student, which is directly demonstrated.

SEC-04 — Missing authorization on grade updates

Critical
 High confidence

Affected location: update_grade()

Attacker-controlled input and data flow

The attacker controls the JSON request body:
{
  "student_id": 1001,
  "course_id": "SRS",
  "grade": 20
}


The endpoint retrieves or creates a grade record:
row = find_grade(student_id, course_id)if row is None:    GRADES.append(...)else:    row["grade"] = grade



No authorization decision occurs before the modification.

Missing security control

There is no verification of:
- Authentication.
- User role.
- Professor course assignments.
- Administrator privileges.
- Whether a student is attempting to modify academic records.
The application also does not enforce that the student identifier belongs to an authorized target.

Preconditions and impact

An unauthenticated attacker can potentially modify any grade.

An authenticated student can modify their own or another student's grades.

A professor can modify grades for courses outside their assigned scope.

Potential consequences:
- Academic fraud.
- Unauthorized grade changes.
- Creation of unauthorized grade records.
- Compromise of academic record integrity.
This violates R1, R3 and R4.

Proposed test

Submit grade updates under these identities:
Identity	Attempt	Expected
Unauthenticated	Update Alice's SRS grade	401
Alice	Update her own grade	403
Alice	Update Bob's grade	403
Professor SRS	Update Alice's SRS grade	Allowed
Professor SRS	Update Alice's SSD grade	403
Administrator	Update any valid grade	Allowed

After every denied request, verify that the stored grade remains unchanged.

Assumptions and uncertainty

The permitted update operations are explicitly defined by R3.

The missing authorization checks are directly demonstrated.

SEC-05 — Missing grade-update input validation

High
 High confidence

Affected location: update_grade()

Attacker-controlled input and data flow

The endpoint reads three values directly from JSON:
data = flask.request.get_json()student_id = data["student_id"]course_id = data["course_id"]grade = data["grade"]



It then passes these values to find_grade() and potentially stores them in GRADES.

Missing security control

The endpoint does not validate the input against R5.

Missing checks include:
1. The request body must be a JSON object.
2. All required fields must exist.
3. student_id must be a positive integer.
4. The student identifier must exist.
5. course_id must be either SRS or SSD.
6. grade must be numeric.
7. The grade must be between 0 and 20 inclusive.
8. Boolean values must not be accepted as grades.
Python's type system introduces an important edge case: bool is a subclass of int.

Consequently, a simple numeric-type check using isinstance(grade, (int, float)) would accept True and False.

Preconditions and impact

An attacker able to reach the endpoint can supply malformed or unexpected values.

Potential consequences:
- Invalid academic records.
- Grades outside the permitted range.
- Records associated with nonexistent students.
- Records associated with unknown courses.
- Unexpected application exceptions.
Proposed test

Submit the following cases:
Test input	Expected result
Missing student_id	400
Missing course_id	400
Missing grade	400
Student ID -1	400
Student ID 0	400
Unknown student ID	400
Unknown course	400
Grade -1	400
Grade 21	400
Grade true	400
Grade "15"	400
Grade 15	Accepted if otherwise valid
Grade 15.5	Accepted if otherwise valid

Verify that every rejected request leaves GRADES unchanged.

Assumptions and uncertainty

The validation rules are explicitly established by R5.

Whether grades should be restricted to integers or may contain decimals is not specified. The proposed tests assume numeric values include integers and floating-point numbers.

SEC-06 — Directory traversal in material downloads

High
 High confidence

Affected location: download_file()

Attacker-controlled input and data flow

The attacker controls the path query parameter:
raw_path = flask.request.args.get("path", "")target = MATERIALS_DIR / raw_pathreturn flask.send_file(target)



The application joins the attacker-controlled path to the materials directory without checking whether the resolved target remains inside that directory.

For example:
GET /files?path=../app.py


The path can resolve to a file outside the intended materials directory.

Missing security control

There is no path containment validation.

The application does not:
- Reject parent-directory traversal.
- Resolve and verify the final path.
- Enforce that the requested file is contained within MATERIALS_DIR.
Preconditions and impact

An attacker must be able to reach the endpoint.

Under the current implementation, authentication is also missing, so the endpoint is exposed to unauthenticated requests.

Potential impact includes:
- Disclosure of application source code.
- Disclosure of configuration files.
- Access to other readable files on the server.
The exact accessible files depend on the deployment filesystem and process permissions.

This violates R1 and R6.

Proposed test

Create or identify a readable test file outside the materials directory.

Attempt:
GET /files?path=../test-secret.txt


Expected:
- Requests for files inside the materials directory may succeed for authenticated users.
- Requests resolving outside that directory must be denied.
Also test:
- ../ traversal.
- Nested traversal.
- Absolute paths.
- Symlink paths, if symlinks are possible in the deployment.
Assumptions and uncertainty

The intended directory restriction is explicitly established by R6.

The exact behavior of absolute paths and symlinks depends on the operating system and filesystem. The lack of path containment validation is directly demonstrated.

SEC-07 — Weak credential and session security

High
 High confidence

Affected locations:
- User dataclass
- USERS
- login()
- Application initialization
Attacker-controlled input and data flow

Login accepts usernames and passwords through form fields:
username = flask.request.form.get("username", "")password = flask.request.form.get("password", "")



Credentials are checked against plaintext values stored in the USERS dictionary:
if user is None or user.password != password:    return {"error": "invalid credentials"}, 401



The application also configures:
app.config["SECRET_KEY"] = "dev-secret-key"



Missing security control

There are two distinct security concerns.
1. Plaintext credentials: Passwords are stored directly in application memory rather than as password hashes.
2. Predictable session signing secret: The application uses a hardcoded development secret.
Flask's default session mechanism uses signed client-side session cookies. A predictable signing secret can undermine session integrity.

An attacker who knows the secret may be able to construct or modify session contents, subject to the application's cookie configuration and serialization behavior.

Preconditions and impact

Plaintext credentials become particularly problematic if application memory, source code, or configuration is exposed.

The hardcoded session secret is directly available to anyone with access to the supplied source.

Potential consequences include:
- Credential disclosure.
- Session forgery.
- Impersonation of users.
- Potential privilege escalation by manipulating session role information.
Proposed test
1. Inspect the source and confirm the secret is fixed.
2. Verify whether a session cookie can be generated or modified using the known secret.
3. Test whether modifying session fields can impersonate an administrator.
4. Inspect credential storage and confirm that passwords are stored in plaintext.
Assumptions and uncertainty

The source demonstrates the hardcoded secret and plaintext credentials.

Successful session forgery depends on the deployed session configuration and the ability to use the signing secret. The security impact is therefore conditional, although the underlying weakness is confirmed.

The requirements do not explicitly specify password-hashing or session-secret management rules. This finding is based on standard security expectations rather than a separately numbered requirement.

SEC-08 — Excessive exception information disclosure

Medium
 High confidence

Affected location: handle_error(exc)

Attacker-controlled input and data flow

The error handler returns:
return {    "error": str(exc),    "type": exc.__class__.__name__,}, 500



Malformed requests and unexpected application errors can cause exceptions to reach this handler.

The response includes the exception message and class name.

Missing security control

The handler exposes internal implementation details instead of returning a generic error message.

Exception messages can contain:
- Internal file paths.
- Filesystem information.
- Details about failed operations.
- Information about internal data structures.
Preconditions and impact

An attacker must be able to trigger an exception.

Potential impact:
- Information disclosure.
- Improved reconnaissance.
- Assistance in identifying further vulnerabilities.
This violates R7.

Proposed test

Send malformed requests that trigger exceptions, such as:
- Missing JSON fields.
- Invalid student identifiers.
- Invalid JSON bodies.
- Requests for nonexistent files.
Inspect the HTTP responses.

Expected: appropriate client errors without internal exception messages, paths, or implementation details.

Assumptions and uncertainty

The disclosure of exception text is directly demonstrated.

Whether a particular exception exposes sensitive information depends on its message.

SEC-09 — Debug mode enabled

High
 High confidence

Affected location: Application startup
app.run(debug=True, host="0.0.0.0", port=5001)



Attacker-controlled input and data flow

The application starts with debugging enabled and binds to all network interfaces.

An attacker who can reach the application may trigger errors through malformed requests or unexpected input.

Missing security control

Debug mode is enabled in the application startup configuration.

Debugging facilities can expose detailed exception information and development functionality.

The network binding makes the application potentially accessible beyond the local machine.

Preconditions and impact

Impact depends on whether this startup path is used in the deployed environment and whether the service is reachable by untrusted users.

Potential consequences include:
- Exposure of detailed debugging information.
- Increased attack surface.
- Potential access to interactive debugging facilities if the debugger is exposed and its protections are bypassed.
Proposed test
1. Start the application using its supplied startup path in an isolated environment.
2. Trigger an unhandled exception.
3. Inspect the response and determine whether the interactive debugger is exposed.
4. Confirm whether the service is reachable from an untrusted network.
Expected for a secure deployment: debug mode disabled and no publicly accessible interactive debugger.

Assumptions and uncertainty

The source explicitly enables debug mode and binds to 0.0.0.0.

Actual network exposure and debugger exploitability cannot be established from the source alone.

SEC-10 — Missing validation of student identifiers

Medium
 High confidence

Affected locations:
- get_profile(student_id)
- get_grades(student_id)
Attacker-controlled input and data flow

Both endpoints accept a student identifier through a URL parameter.

The value is converted directly:
int(student_id)



No explicit validation checks that the identifier is positive.

Missing security control

The application does not implement the identifier validation required by R5.

In particular, negative integers and zero are not explicitly rejected.

The application also allows conversion errors to propagate to the global error handler.

Preconditions and impact

An attacker must be able to reach the endpoints.

Potential consequences:
- Invalid requests being processed as ordinary record lookups.
- Inconsistent client error behavior.
- Internal exception details being exposed for malformed identifiers.
This violates R5 and R7.

Proposed test

Try:
GET /students/0/profile
GET /students/-1/profile
GET /grades/0
GET /grades/-1
GET /students/abc/profile


Expected:
- Invalid or nonpositive identifiers return HTTP 400.
- No internal exception details are disclosed.
- No data is returned.
Assumptions and uncertainty

Positive integer identifiers are explicitly required by R5.

The current implementation does not enforce this requirement.

3. Additional observations and limitations
The following observations are relevant but should not automatically be classified as independent vulnerabilities.
Observation	Assessment
courses is stored in the session	Course assignments are available for authorization, but the application does not use them in grade authorization.
find_grade() performs exact matching	The lookup itself is straightforward; the main issue is the absence of authorization and validation before modification.
GRADES is an in-memory list	Persistence and concurrency are not guaranteed, but this is explicitly described as a teaching simplification.
MATERIALS_DIR.mkdir() creates the directory	Directory creation is not inherently a vulnerability.
/logout clears the session	No obvious authorization bypass is demonstrated by this endpoint.
/me returns session information	Its unauthenticated behavior is explicitly permitted by R1.

4. Requirements compliance matrix
This matrix summarizes the demonstrated gaps against the supplied requirements.
Requirement	Status	Explanation
R1 — Authentication	Fail	Four protected endpoints lack authentication checks.
R2 — Student privacy	Fail	Students can request other students' profiles and grades.
R3 — Academic staff scope	Fail	Professor course assignments are not enforced; profile access is unrestricted.
R4 — Complete authorization	Fail	No record-level authorization or authorized grade filtering exists.
R5 — Input validation	Fail	Grade fields, student IDs, course IDs, and numeric ranges are not validated.
R6 — File access	Fail	File paths are not restricted to the materials directory.
R7 — Error handling	Fail	Exceptions expose implementation details and invalid inputs are not consistently handled.

5. Review conclusion
The most important issues to address, in order, are:
1. SEC-01 and SEC-04: Enforce authentication and authorization before allowing access to protected resources or modifying academic records.
2. SEC-02 and SEC-03: Implement record-level authorization for student profiles and grades.
3. SEC-06: Restrict file downloads to paths contained within the materials directory.
4. SEC-05 and SEC-10: Validate all user-controlled identifiers and grade-update fields.
5. SEC-07, SEC-08 and SEC-09: Improve credential handling, session security, exception handling, and debug configuration.
Final assessment: The source demonstrates multiple violations of the explicitly supplied security requirements. In particular, the missing authorization controls make student records and grade modifications accessible without the required permission checks.

This is a static review, not a penetration test. The findings identify source-level defects; runtime exploitability, deployment configuration, and filesystem behavior have not been independently verified. No patches or code modifications have been proposed.