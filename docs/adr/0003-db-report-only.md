# ADR 0003 — Database: report-only, SQL export for remediation

**Date**: 2026-10-01  
**Status**: Accepted

## Context

A DB Scan can find injected JS, spam links, unauthorised admin users and hidden cron jobs in the WordPress database. The tool reads credentials from `wp-config.php` automatically.

Automatically cleaning the database during `--fix` is dangerous: a false positive or a mis-targeted DELETE/UPDATE could destroy production content with no easy rollback.

## Decision

The DB Scan is **always read-only**. When DB Findings are detected, the tool generates a `.sql` file containing the remediation queries (DELETE, UPDATE) that the operator must **review and run manually**. The `--fix` flag does not touch the database.

## Consequences

- **+** Zero risk of accidental data loss from the tool itself.
- **+** Operator has a complete audit trail of what needs to change and why.
- **−** Remediation requires a manual step. Accepted: database changes are high-stakes and benefit from human review regardless.
