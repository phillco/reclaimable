# Runbook

## Safety and verification

1. **[2026-11-02] Keep safety comparisons separate from I/O names.**
   Do instead: canonicalise aliases and fold Unicode for protection checks; retain
   exact filesystem names for content inventories and hash verification.
2. **[2026-11-02] Exercise removal only on disposable fixtures.**
   Do instead: use the isolated test environment and fail closed on incomplete
   directory walks or deny-glob expansion.
