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


def test_unauthenticated_malformed_update_is_rejected(client):
    # Variation: authentication must be checked before parsing the body.
    response = client.post("/grades/update", json={})
    assert response.status_code == 401


def test_forged_session_role_is_not_trusted(client):
    # Suggested by the LLM repair: role must come from USERS, not the session.
    with client.session_transaction() as sess:
        sess["user"] = "alice"
        sess["role"] = "admin"
    response = client.post(
        "/grades/update",
        json={"student_id": 1001, "course_id": "SRS", "grade": 20},
    )
    assert response.status_code == 403
    assert api.find_grade(1001, "SRS")["grade"] == 14
