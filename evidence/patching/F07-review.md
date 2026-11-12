# F07 patch review

LLM patch (F07-repair-response.md):
+ Authentication checked before path processing (401).
+ resolve() + relative_to() containment: blocks ../, nested, absolute,
  sibling-prefix directory and symlink escapes; uses current MATERIALS_DIR.
+ Non-files -> 404 without leaking paths.
- Out of scope: also rewrote the global handle_error (affects every
  endpoint). Not needed for F07 (all tests pass without it).
Decision: accepted the download_file change; REJECTED the handle_error
change to keep the patch minimal. Error handling (F08) left for a
separate fix.
