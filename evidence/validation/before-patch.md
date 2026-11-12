# Security tests BEFORE patching

CI run (security-regression failed, build skipped): https://github.com/danielcpereira/cybersecurity_lab_devsecops/actions/runs/43199061518

Result: 9 failed, 3 passed

## F04 - grade update authorization (test_grade_authorization.py)
- test_unauthenticated_update_is_rejected: assert 200 == 401 (anonymous update accepted)
- test_student_cannot_update_own_grade: assert 200 == 403 (alice changed her own grade)
- test_student_cannot_update_other_student_grade: assert 200 == 403 (alice changed Bob's grade)
- test_professor_cannot_update_unassigned_course: assert 200 == 403 (prof_srs changed an SSD grade)
- Permitted operations passed: assigned professor, admin

## F07 - path traversal (test_file_access.py)
- test_unauthenticated_download_is_rejected: assert 200 == 401
- test_parent_traversal_is_denied: assert 400 <= 200 (../secret.txt returned)
- test_nested_traversal_is_denied: assert 400 <= 200 (sub/../../secret.txt returned)
- test_absolute_path_is_denied: assert 400 <= 200 (absolute path returned)
- test_sibling_prefix_directory_is_denied: assert 400 <= 200 (../materials_private/leak.txt returned)
- Permitted operation passed: authenticated download of notes.txt
