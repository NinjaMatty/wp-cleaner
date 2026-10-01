# ADR 0001 — Single-file PHP architecture

**Date**: 2026-10-01  
**Status**: Accepted

## Context

WP-Cleaner is a security emergency tool deployed onto a compromised WordPress server. The operator may have only FTP or a file manager to upload files, and may be under time pressure. The tool must be drop-in: upload one file, run one command.

## Decision

WP-Cleaner is delivered as a single PHP file (`wp-cleaner.php`). All logic — integrity checking, heuristic scanning, DB scan, reporting — lives in one file. No Composer, no autoloader, no external dependencies at deploy time.

## Consequences

- **+** Zero-friction deployment: one file upload, one `php wp-cleaner.php` command.
- **+** No dependency resolution on a potentially broken server.
- **−** The file will grow large (~800–1 500 LOC). Mitigated by clear section comments and a logical top-to-bottom structure.
- **−** Unit-testing individual components requires refactoring the file into classes/functions that can be included without executing the CLI entrypoint. Accepted for v1; a multi-file structure is a v2 option if the codebase grows further.
