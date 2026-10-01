# WP-Cleaner — Domain Glossary

## Core concepts

**Scan**
Read-only analysis of a WordPress installation. Default mode (`--scan`). No file is written or deleted. Produces a Report.

**Fix**
Restoration of Modified Files and removal (or quarantine) of Extra Files, using the official WordPress release as the reference. Activated with `--fix`. Always preceded by a Backup.

**Backup**
A timestamped copy of every file that would be overwritten or removed during a Fix. Stored in `./wp-cleaner-backup/YYYY-MM-DD_HH-MM/` inside the WP root, compressed into a `.zip` at the end of the Fix run.

**Report**
The output of a Scan or Fix: a list of findings (Modified Files, Extra Files, Heuristic Hits, DB Findings, CVE Findings). Available as stdout, a plain-text log file, or an HTML file (standalone, CSS inline).

## File integrity

**Core Files**
PHP and other files that are part of the official WordPress release zip downloaded from wordpress.org. The reference for integrity checking.

**Modified File**
A Core File whose content differs from the corresponding file in the official WordPress release for the same version.

**Extra File**
A file present inside a Core WordPress directory (e.g., `wp-includes/`, `wp-admin/`) that does not exist in the official release. A common infection vector.

**Plugin Integrity**
Comparison of an installed plugin's files against the version downloaded from wordpress.org/plugins. Only possible for free plugins with a known version in their plugin header.

**Unverifiable Plugin**
A plugin not available on wordpress.org (e.g., premium plugins such as ACF Pro, Elementor Pro). Cannot be integrity-checked. Flagged as "unverifiable" in the Report and subjected to a Heuristic Scan only.

**Whitelist**
A list of paths and glob patterns excluded from Extra File detection. Default entries cover `wp-content/uploads/`, `wp-content/cache/`, `wp-content/upgrade/`. Customisable via a `.wp-cleaner-ignore` file in the WP root.

## Heuristic scanning

**Heuristic Scan**
Pattern-based analysis of PHP files (plugins, themes, wp-config.php, .htaccess, wp-content/uploads) looking for known malicious code signatures. Runs on files that cannot be integrity-checked.

**Signature**
A PCRE regex or literal string pattern identifying a known malicious code construct (e.g., `eval(base64_decode(...))`, webshell keywords, `shell_exec`). Embedded in the tool source as a structured PHP array.

**Signature Feed**
The remote source (`scr34m/php-malware-scanner` on GitHub) from which updated Signatures can be fetched via `--update-signatures`.

**Heuristic Hit**
A file that matched one or more Signatures during a Heuristic Scan.

## Database

**DB Scan**
Read-only analysis of the WordPress database. Credentials are read automatically from `wp-config.php`. Checks for: injected JS/iframes in `wp_posts`, spam links in `wp_options`, unauthorised admin users, hidden cron jobs in `wp_cron`. Never modifies the database.

**DB Finding**
A suspicious entry found during a DB Scan. Exported as a set of SQL queries the operator can review and run manually to remediate.

## Vulnerability checking

**CVE Check**
Optional query (activated with `--check-vulns`) to the WPVulnerability.com public JSON API. Reports known CVEs for the installed WordPress version, plugins, and themes. Requires internet access on the server.

**CVE Finding**
A known CVE returned by the CVE Check for an installed component.

## Configuration

**Config File**
`.wp-cleaner.json` in the WP root. Stores persistent preferences (backup directory, verbosity, whitelist additions). CLI flags always override Config File values.

**Ignore File**
`.wp-cleaner-ignore` in the WP root. A `.gitignore`-style file listing paths and glob patterns excluded from Extra File detection.

## Versioning

**WP Version**
The WordPress version string read automatically from `wp-includes/version.php` (`$wp_version`). Used to download the correct release zip. Can be overridden with `--wp-version`.

**Release Zip**
The official WordPress `.zip` archive for a specific WP Version, downloaded from `https://wordpress.org/wordpress-X.X.X.zip` and cached locally.

**Zip Cache**
A local directory (`./wp-cleaner-cache/`) storing downloaded Release Zips. A cached zip is reused if its SHA1 matches the expected value; otherwise it is re-downloaded.
