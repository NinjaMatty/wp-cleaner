# WP-Cleaner

**WordPress Malware Scanner & Sanitizer** — single-file PHP emergency tool.

[![License: GPL-3.0](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PHP: 7.4+](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](https://www.php.net)

---

## What it does

WP-Cleaner scans a hacked WordPress installation and helps you clean it up:

| Check | What it finds |
|---|---|
| **Core integrity** | Files modified vs. the official WordPress release (MD5 comparison) |
| **Extra files** | PHP files injected into `wp-admin/`, `wp-includes/`, and the root |
| **Heuristic scan** | Known malware patterns in plugins, themes, `wp-config.php`, `.htaccess`, and uploads |
| **Plugin integrity** | Files in free wp.org plugins that differ from the published version |
| **DB scan** | Injected JS/iframes in posts, suspicious options, fake admin users, hidden cron jobs |
| **CVE check** | Known vulnerabilities in installed WP version and plugins via WPVulnerability.com |

---

## Requirements

- PHP 7.4 or higher
- `php-zip` extension (`apt install php-zip` / `yum install php-zip`)
- Internet access (for downloading the official WordPress zip on first run)
- **CLI execution only** — must be run from the terminal

---

## Installation

Upload a single file to your WordPress root:

```bash
# On the server, from the WordPress root directory:
wget https://raw.githubusercontent.com/your-org/wp-cleaner/main/wp-cleaner.php
```

---

## Usage

```bash
# Scan only (dry-run, no changes) — always start here
php wp-cleaner.php

# Full scan + HTML report
php wp-cleaner.php --html

# Scan including database and CVE checks
php wp-cleaner.php --db --check-vulns

# Fix mode: restore modified core files and remove injected extra files
# (creates a timestamped backup before making any change)
php wp-cleaner.php --fix

# Full scan + fix + HTML report + log
php wp-cleaner.php --fix --db --check-vulns --html --log /tmp/wpcleaner.log

# Run against a different WordPress root
php wp-cleaner.php --wp-root /var/www/html

# Update malware signature database
php wp-cleaner.php --update-signatures
```

### All options

| Flag | Description |
|---|---|
| `--scan` | Scan only (default) |
| `--fix` | Restore modified core files + remove extra files (backup first) |
| `--db` | Include database scan |
| `--check-vulns` | Query WPVulnerability.com for known CVEs |
| `--html` | Write standalone HTML report to WP root |
| `--update-signatures` | Fetch latest signatures from scr34m/php-malware-scanner |
| `--wp-version <ver>` | Override auto-detected WP version |
| `--wp-root <path>` | WP root directory (default: current directory) |
| `--backup-dir <path>` | Override backup directory |
| `--log <file>` | Write log to file |
| `--verbose` | Show detailed output |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings |
| `1` | Findings detected |
| `2` | Runtime error |

---

## How `--fix` works

1. **Backup first**: copies every file that will be touched into `./wp-cleaner-backup/<timestamp>/` and zips it.
2. **Restore core files**: overwrites modified core files with the original from the official WordPress zip.
3. **Remove extra files**: deletes injected PHP files from `wp-admin/`, `wp-includes/`, and the root.
4. **Plugin/theme files**: cannot be auto-restored (they are not in the core zip). WP-Cleaner flags them and asks you to reinstall the affected plugin/theme manually.

**The database is never modified automatically.** The `--db` scan produces a `.sql` file with remediation queries for you to review and run manually.

---

## Whitelist (`.wp-cleaner-ignore`)

Create a `.wp-cleaner-ignore` file in the WordPress root to exclude paths from the extra-file scan. Syntax is like `.gitignore`:

```
# Custom uploads subfolder with PHP scripts (legacy application)
wp-content/uploads/legacy-app/

# A custom root-level PHP file that is not a plugin
my-custom-api.php
```

Default whitelist entries (always excluded):
- `wp-content/uploads`
- `wp-content/cache`
- `wp-content/upgrade`
- `wp-cleaner-backup`
- `wp-cleaner-cache`
- `.git`, `.svn`, `node_modules`

---

## Persistent config (`.wp-cleaner.json`)

Store default settings in `.wp-cleaner.json` in the WordPress root. CLI flags always override config file values.

```json
{
  "backup_dir": "/mnt/backup/wp-cleaner",
  "log": "/var/log/wp-cleaner.log",
  "verbose": false
}
```

> **Note**: `.wp-cleaner.json` support will be implemented in v1.1. For now, use CLI flags.

---

## Malware signatures

Signatures are embedded directly in `wp-cleaner.php` between two marker comments. Update them at any time:

```bash
php wp-cleaner.php --update-signatures
```

This fetches the latest patterns from [scr34m/php-malware-scanner](https://github.com/scr34m/php-malware-scanner) and patches the signature block in the file itself. No external files needed.

---

## Security notes

- **Run as CLI only.** Never expose `wp-cleaner.php` to the web — add it to `.gitignore` and your server's deny rules, or delete it after use.
- The tool is **read-only by default** (`--scan`). Only `--fix` makes filesystem changes.
- The database is **never modified** automatically.
- Always review the report before running `--fix` on a production site.

---

## Architecture decisions

See [`docs/adr/`](docs/adr/) for the key decisions:

- [ADR 0001](docs/adr/0001-single-file-php.md) — Single PHP file
- [ADR 0002](docs/adr/0002-signature-strategy.md) — Signature strategy
- [ADR 0003](docs/adr/0003-db-report-only.md) — DB: report-only

## License

GPL-3.0-or-later — see [LICENSE](LICENSE)
