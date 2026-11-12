# Consolidated findings table (Section 7)

Target: `baseline_secure_coding_api.py` (unmodified baseline, 159 lines).
Sources compared: Bandit and Semgrep reports from the baseline CI run (`evidence/baseline-sast/`), and LLM responses A, B, C (`evidence/discovery/`).
Executable reproduction: `evidence/validation/repro_baseline.py` (Flask test client, no code changes).

**Legend for A / B / C columns**

- **Yes**: the response names the affected operation and the missing or incorrect check (counts as detection).
- **Partial**: mentioned only inside another finding, or only for some of the affected operations.
- **Obs**: listed only as a side "observation", not as a finding.
- **No**: not mentioned.

The LLM IDs in brackets refer to that response's own numbering (A and B both use SEC-01…07, but the IDs map to different issues).

| ID | Root cause and affected operation | Bandit rule | Semgrep rule | A | B | C | Validation status | Evidence |
|---|---|---|---|---|---|---|---|---|
| F01 | **Missing authentication** on protected endpoints: `get_profile` (L115–120), `get_grades` (L122–126), `update_grade` (L128–142), `download_file` (L144–148). None checks `"user" in flask.session`. R1 | — | — | Partial (in SEC-02/03/04; not for `/files`) | Partial (SEC-01/02/03; `/files` only in SEC-04 text) | Yes (SEC-01, all four) | Confirmed | Without login: profile, grades and file return 200; anonymous `POST /grades/update` changes 1001/SRS from 14 to 20. |
| F02 | **Profile object-level authorization missing**: `get_profile` returns any profile by URL ID, with no owner or role check. R2, R3, R4 | — | — | Yes (SEC-02) | Yes (SEC-01) | Yes (SEC-02) | Confirmed | alice → `/students/1002/profile` returns 200 with Bob's data. prof_srs → `/students/1001/profile` returns 200. The professor rule is policy-dependent and only C states it. |
| F03 | **Grade-read authorization and filtering missing**: `get_grades` returns all rows for the URL ID, ignoring role, own student ID and assigned courses. R2, R3, R4 | — | — | Yes (SEC-03; notes unused `courses`) | Yes (SEC-02) | Yes (SEC-03; incl. filtering and deny-if-none) | Confirmed | alice → `/grades/1002` returns 200 with Bob's grade. prof_srs → `/grades/1001` also returns the **SSD** row (not assigned). |
| F04 | **Grade-update authorization missing**: `update_grade` writes to `GRADES` without checking role or professor course scope. R3, R4 | — | — | Yes (SEC-04) | Yes (SEC-03) | Yes (SEC-04) | Confirmed | alice sets her own SRS to 20 and Bob's SRS to 0 (both 200). prof_srs sets Alice's **SSD** to 0 (200; stored value changed). |
| F05 | **Grade-update input validation missing; the update is actually an upsert**: there are no type, range, existence or known-course checks, and unknown keys create new rows (L130–140). R5, R7 | — | — | Partial (in SEC-04, tests T5–T7) | Partial (SEC-03 bullet and observation) | Yes (SEC-05; incl. `bool` edge case) | Confirmed | Accepted with 200: grade 999, `true`, `"A+"`. Unknown course `XYZ`, unknown student 9999, and `"1001"` as a string each **append a new row**. A missing field or a JSON list returns 500. |
| F06 | **Path traversal in file download**: `MATERIALS_DIR / raw_path` passed to `send_file` with no containment check. `pathlib` also lets an **absolute** path replace the base directory (L144–148). R6 | — | — | Yes (SEC-05; `../` only) | Yes (SEC-04; absolute paths as a test) | Yes (SEC-06; absolute paths and symlinks) | Confirmed | `?path=../baseline_secure_coding_api.py` returns the source code, including `SECRET_KEY`. `?path=/etc/hosts` returns the host file. |
| F07 | **Student-ID validation missing** on URL IDs: `int()` without a positive check or a clean error (`get_profile`, `get_grades`). R5, R7 | — | — | Obs | Obs (as an error trigger in SEC-07) | Yes (SEC-10) | Confirmed | `/students/abc/profile` returns 500 `ValueError`. `/grades/-1` and `/grades/0` return 200 `[]` instead of 400. |
| F08 | **Error handler leaks internals and uses wrong status codes**: `@app.errorhandler(Exception)` returns `str(exc)` and the class name with 500, including for `HTTPException`s (L150–155). R7 | — | — | Yes (SEC-06) | Yes (SEC-07; observation that all errors become 500) | Yes (SEC-08) | Confirmed | A missing file returns 500 and leaks the absolute server path. An unknown route returns **500** instead of 404. A non-JSON update returns 500 instead of 415/400. |
| F09 | **Hard-coded Flask `SECRET_KEY`**: anyone with the source can sign session cookies, and the session holds `role` (L8) | B105 | — | Yes (SEC-01) | Yes (SEC-05) | Yes (part of SEC-07) | Confirmed | A cookie forged with `dev-secret-key` as `{"user":"admin1","role":"admin"}` is accepted by `/me` without a password. Fixing this alone does not count as a repair (Section 8). |
| F10 | **Hard-coded plaintext passwords** in `USERS` (L36–43) | B106 ×4 | — | Obs | Obs | Yes (part of SEC-07) | Confirmed (code fact); not required by R1–R7 | These are teaching-fixture credentials. Hashing is not part of the supplied requirements. |
| F11 | **Flask debug mode enabled** in `app.run(debug=True)` (L159) | B201 | debug-enabled | Yes (SEC-07) | Yes (SEC-06) | Yes (SEC-09) | Confirmed (config); runtime impact **unverified** | All three LLMs say exceptions may expose the Werkzeug debugger. But the global `errorhandler(Exception)` catches request exceptions first (see F08), so that part of the claim is overstated. Exposure in the container depends on the Dockerfile `CMD`. |
| F12 | **Binding to all interfaces** with `host="0.0.0.0"` (L159) | B104 | avoid_app_run_with_bad_host | Partial (in SEC-07) | Partial (in SEC-06) | Partial (in SEC-09) | Policy-dependent | This is required inside a container. The lab publishes the port only on `127.0.0.1:5001`. |
| F13 | **No CSRF protection** on state-changing POSTs (`/grades/update`, `/logout`) | — | — | Obs | Obs | No | Policy-dependent / Unverified | Not covered by R1–R7. Exploitability depends on cookie `SameSite` and browser clients. |
| F14 | **No login rate limiting** (`login`, L82–96) | — | — | Obs | Obs | No | Policy-dependent | Not covered by R1–R7. |
| F15 | **"Session fixation"**: B claims the login does not regenerate the session identifier | — | — | No | Obs | No | False positive | Flask uses signed client-side cookies, with no server-side session ID to fix in advance. Login issues a new signed cookie; reproduced: a planted cookie does not give the attacker the victim's session. |

## Summary per source

| Source | Fully detected (Yes) | Partial or Obs | Missed | Incorrect or overstated |
|---|---|---|---|---|
| Bandit | F09, F10, F11, F12 | — | F01–F08 | — |
| Semgrep | F11, F12 | — | F01–F10 | — |
| LLM A (source only) | F02, F03, F04, F06, F08, F09, F11 | F01, F05, F07, F10, F12, F13, F14 | — | F11 debugger claim overstated |
| LLM B (+ context) | F02, F03, F04, F06, F08, F09, F11 | F01, F05, F07, F10, F12, F13, F14 | — | F11 overstated; F15 false positive |
| LLM C (+ requirements) | F01–F11 | F12 | F13, F14 (out of R1–R7 scope) | F11 overstated |

## Observations for the Section 14 discussion (to verify in your own words)

- **SAST vs LLM:** Bandit and Semgrep only flagged configuration patterns (F09–F12). Neither detected any of the eight application-logic issues (F01–F08), which are the ones that matter for the repair selection.
- **A to B:** The application description changed very little. B reported the same seven root causes as A, in a different order. It added absolute paths as a test variation for F06.
- **B to C:** The requirements produced the biggest change:
  - F01 was separated from authorization and applied to all four endpoints, including `/files`.
  - Professor profile denial (F02) and grade-list filtering (F03, R4) appeared.
  - Full R5 validation appeared, including the `bool` subclass edge case (F05), plus student-ID validation (F07).
  - A requirement compliance matrix was added.
- **Did C just repeat the requirements?** Mostly not. Each finding is located in a specific function with a concrete request. The compliance matrix in section 4 is the part that restates requirements.
- **What every condition missed or under-stated:**
  - The `pathlib` absolute-path override in F06 only appeared as a test idea, never as a root cause.
  - That F05 is an **upsert**: a type mismatch such as `"1001"` silently creates a new record.
  - That the global error handler turns 404/415 into 500 (only B hinted at this).

## Candidate selection for Section 8 (suggested)

1. **Authorization:** F04, grade-update authorization (role and course scope). It matches the supplied worked-example fixtures. F03 is an alternative.
2. **File access or input validation:** F06, path traversal. The guide gives the `tmp_path` and `monkeypatch` testing approach. F05 is an alternative.
