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
