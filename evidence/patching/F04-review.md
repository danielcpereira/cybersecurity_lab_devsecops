# F04 patch review

Initial LLM patch (F04-repair-response.md):
+ Uses server-side USERS for role/courses (forged session role -> 403).
+ Check runs before any mutation of GRADES; no endpoints or tests removed.
- Incomplete: permission check runs AFTER data["student_id"] is read.
  Anonymous request with {} or a non-JSON body -> 500 with exception details,
  instead of 401 (violates R1/R7). Supplied tests did not catch it.
Action: added test_unauthenticated_malformed_update_is_rejected and the
LLM-suggested test_forged_session_role_is_not_trusted; asked the LLM to
move authentication and the student-role check before body parsing
(F04-repair-response-2.md).
