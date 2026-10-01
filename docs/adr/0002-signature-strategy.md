# ADR 0002 — Malware signature strategy: hardcoded + optional remote update

**Date**: 2026-10-01  
**Status**: Accepted

## Context

WP-Cleaner needs a set of malware Signatures (PCRE regex + literal strings) to run a Heuristic Scan. The tool must work on servers without internet access. Signatures must also be updatable as new threats emerge.

Several external sources are available (see research: `scr34m/php-malware-scanner` GPL-3, AMWScan GPL-3, YARA rulesets). A live remote feed at runtime is not viable because the compromised server may have no outbound internet.

## Decision

1. A curated baseline set of Signatures is **hardcoded** in `wp-cleaner.php` as a structured PHP array, derived from the community knowledge of `scr34m/php-malware-scanner` and AMWScan (GPL-3 compatible).
2. Running `php wp-cleaner.php --update-signatures` fetches the latest pattern files from the `scr34m/php-malware-scanner` GitHub raw URLs, merges them with the hardcoded set, and **rewrites the Signature array constant inside `wp-cleaner.php`** itself. The tool is its own update target.
3. The tool is licensed **GPL-3** to be compatible with the GPL-3 signature sources.

## Alternatives considered

- **Runtime fetch on every scan**: rejected — server may be offline; adds latency to every scan.
- **External JSON pattern file**: rejected — breaks the single-file constraint (ADR 0001).
- **YARA rules**: rejected — requires a YARA binary or PHP extension not available on a vanilla shared host.

## Consequences

- **+** Tool works fully offline with the hardcoded baseline.
- **+** Operator can refresh signatures with a single command when internet is available.
- **+** No external files or binaries required.
- **−** `--update-signatures` does an in-place self-modification of the PHP file. This is unusual but safe: it rewrites only the delimited signature block between two marker comments.
- **−** GPL-3 licence means derivatives must also be GPL-3.
