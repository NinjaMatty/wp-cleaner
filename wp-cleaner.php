<?php
declare(strict_types=1);

/**
 * WP-Cleaner v1.0.0 — WordPress Malware Scanner & Sanitizer
 * License : GPL-3.0-or-later
 * Requires: PHP 7.4+, php-zip extension
 *
 * Usage:
 *   php wp-cleaner.php [options]
 *
 * Options:
 *   --scan                Scan only, no changes (default)
 *   --fix                 Restore modified/extra core files after backup
 *   --db                  Include database scan (reads wp-config.php)
 *   --check-vulns         Query WPVulnerability.com for known CVEs
 *   --html                Write standalone HTML report to WP root
 *   --update-signatures   Fetch latest signatures from remote and patch this file
 *   --wp-version <ver>    Override auto-detected WP version
 *   --wp-root <path>      WP root directory (default: current directory)
 *   --backup-dir <path>   Override backup directory
 *   --log <file>          Also write log to file
 *   --verbose             Show detailed output
 *   --version             Print tool version and exit
 *   --help                Print this help and exit
 *
 * Exit codes:
 *   0 = no findings   1 = findings detected   2 = runtime error
 */

// ════════════════════════════════════════════════════════════════════════════
//  PHP 7.4 POLYFILLS
// ════════════════════════════════════════════════════════════════════════════
if (!function_exists('str_starts_with')) {
    function str_starts_with(string $haystack, string $needle): bool
    {
        return strncmp($haystack, $needle, strlen($needle)) === 0;
    }
}
if (!function_exists('str_ends_with')) {
    function str_ends_with(string $haystack, string $needle): bool
    {
        $len = strlen($needle);
        return $len === 0 || substr($haystack, -$len) === $needle;
    }
}
if (!function_exists('str_contains')) {
    function str_contains(string $haystack, string $needle): bool
    {
        return strpos($haystack, $needle) !== false;
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  SIGNATURES  —  managed block, update with: php wp-cleaner.php --update-signatures
//  Do not edit manually between the markers below.
// ════════════════════════════════════════════════════════════════════════════
// <WP_CLEANER_SIGNATURES_START>
const WPC_SIG_REGEX = [
    'eval_base64'     => '/eval\s*\(\s*base64_decode\s*\(/i',
    'eval_gzinflate'  => '/eval\s*\(\s*gzinflate\s*\(/i',
    'eval_gzuncompress'=> '/eval\s*\(\s*gzuncompress\s*\(/i',
    'eval_str_rot13'  => '/eval\s*\(\s*str_rot13\s*\(/i',
    'eval_rawurl'     => '/eval\s*\(\s*rawurldecode\s*\(/i',
    'eval_hex2bin'    => '/eval\s*\(\s*hex2bin\s*\(/i',
    'shell_exec_req'  => '/\bshell_exec\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'passthru_req'    => '/\bpassthru\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'system_req'      => '/\bsystem\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'assert_req'      => '/\bassert\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'preg_replace_e'  => '/preg_replace\s*\(\s*["\'].+\/e["\']/i',
    'remote_include'  => '/(?:include|require)(?:_once)?\s*\(\s*["\']https?:\/\//i',
    'callback_req'    => '/\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'injected_iframe' => '/<iframe[^>]+src=["\']https?:\/\/[^"\']+["\']/i',
    'wp_vcd'          => '/wp_vcd/i',
    'obfuscated_chr'  => '/(?:chr\s*\(\s*\d+\s*\)\s*\.){4,}/i',
    'long_base64'     => '/[a-zA-Z0-9+\/]{500,}={0,2}/',
    'create_function' => '/create_function\s*\(\s*["\'][^"\']*["\']\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/i',
    'usort_callback'  => '/usort\s*\(\s*\$\w+\s*,\s*\$_(GET|POST|REQUEST|COOKIE)/i',
];

const WPC_SIG_LITERAL = [
    'c99shell', 'r57shell', 'wso shell', 'b374k',
    'phpspy', 'FilesMan', 'Backdoor', 'wp_vcd',
];

const WPC_SIG_HTACCESS = [
    'auto_prepend'  => '/php_value\s+auto_prepend_file/i',
    'auto_append'   => '/php_value\s+auto_append_file/i',
    'add_handler'   => '/AddHandler\s+application\/x-httpd-php\s+\.\w+/i',
    'rewrite_ext'   => '/RewriteRule\s+.+\s+https?:\/\//i',
];
// <WP_CLEANER_SIGNATURES_END>

// ════════════════════════════════════════════════════════════════════════════
//  CONSTANTS
// ════════════════════════════════════════════════════════════════════════════
const WPC_TOOL_VERSION  = '1.0.0';
const WPC_EXIT_OK       = 0;
const WPC_EXIT_FINDINGS = 1;
const WPC_EXIT_ERROR    = 2;

const WPC_ZIP_URL       = 'https://wordpress.org/wordpress-%s.zip';
const WPC_MD5_URL       = 'https://wordpress.org/wordpress-%s.zip.md5';
const WPC_CVE_CORE_URL  = 'https://api.wpvulnerability.com/core/%s';
const WPC_CVE_PLUGIN_URL= 'https://api.wpvulnerability.com/plugin/%s/%s';
const WPC_SIG_REGEX_URL = 'https://raw.githubusercontent.com/scr34m/php-malware-scanner/master/patterns_re.txt';
const WPC_SIG_RAW_URL   = 'https://raw.githubusercontent.com/scr34m/php-malware-scanner/master/patterns_raw.txt';
const WPC_PLUGIN_DL_URL = 'https://downloads.wordpress.org/plugin/%s.%s.zip';
const WPC_THEME_DL_URL  = 'https://downloads.wordpress.org/theme/%s.%s.zip';

const WPC_DEFAULT_WHITELIST = [
    'wp-content/uploads',
    'wp-content/cache',
    'wp-content/upgrade',
    'wp-content/wflogs',
    'wp-content/ai1wm-backups',
    'wp-content/updraft',
    'wp-content/backups',
    '.git',
    '.svn',
    'node_modules',
    'wp-cleaner-backup',
    'wp-cleaner-cache',
];

const WPC_PHP_EXTENSIONS    = ['php', 'php3', 'php4', 'php5', 'php7', 'phtml', 'phar'];
const WPC_UPLOAD_EXTENSIONS = ['php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'cgi', 'pl'];

// ════════════════════════════════════════════════════════════════════════════
//  DATA TYPES
// ════════════════════════════════════════════════════════════════════════════

class WpcConfig
{
    public string  $wpRoot;
    public ?string $wpVersion  = null;
    public string  $backupDir;
    public string  $cacheDir;
    public ?string $logFile    = null;
    public bool    $fixMode    = false;
    public bool    $genHtml    = false;
    public bool    $dbScan     = false;
    public bool    $checkVulns = false;
    public bool    $updateSigs = false;
    public bool    $verbose    = false;
    /** @var string[] */
    public array   $whitelist  = WPC_DEFAULT_WHITELIST;

    public function __construct(string $wpRoot)
    {
        $this->wpRoot    = rtrim($wpRoot, DIRECTORY_SEPARATOR);
        $this->backupDir = $this->wpRoot . DIRECTORY_SEPARATOR . 'wp-cleaner-backup';
        $this->cacheDir  = $this->wpRoot . DIRECTORY_SEPARATOR . 'wp-cleaner-cache';
    }
}

class WpcFinding
{
    /** @var string 'modified'|'extra'|'missing'|'heuristic'|'db'|'cve' */
    public string  $type;
    /** @var string 'critical'|'warning'|'info' */
    public string  $severity;
    public string  $path;
    public string  $detail;
    /** @var string[]|null */
    public ?array  $matches;
    public bool    $fixed = false;

    public function __construct(
        string $type,
        string $severity,
        string $path,
        string $detail,
        ?array $matches = null
    ) {
        $this->type     = $type;
        $this->severity = $severity;
        $this->path     = $path;
        $this->detail   = $detail;
        $this->matches  = $matches;
    }
}

class WpcReport
{
    public WpcConfig $config;
    public string    $wpVersion;
    public string    $timestamp;
    /** @var WpcFinding[] */
    public array     $findings  = [];
    /** @var string[] */
    public array     $fixed     = [];
    /** @var string[] */
    public array     $errors    = [];
    /** @var string[] */
    public array     $sqlFixes  = [];

    public function __construct(WpcConfig $config, string $wpVersion)
    {
        $this->config    = $config;
        $this->wpVersion = $wpVersion;
        $this->timestamp = date('Y-m-d H:i:s T');
    }

    public function hasFindings(): bool
    {
        return !empty($this->findings);
    }

    public function countByType(string $type): int
    {
        return count(array_filter($this->findings, fn($f) => $f->type === $type));
    }

    public function countBySeverity(string $sev): int
    {
        return count(array_filter($this->findings, fn($f) => $f->severity === $sev));
    }
}

// ════════════════════════════════════════════════════════════════════════════
//  I/O HELPERS
// ════════════════════════════════════════════════════════════════════════════

/** @var resource|null */
$wpc_log_handle = null;
/** @var WpcConfig|null */
$wpc_config = null;

function wpc_level_prefix(string $level): string
{
    switch ($level) {
        case 'ok':    return "\033[32m[OK  ]\033[0m";
        case 'warn':  return "\033[33m[WARN]\033[0m";
        case 'crit':  return "\033[31m[CRIT]\033[0m";
        case 'error': return "\033[31m[ERR ]\033[0m";
        case 'step':  return "\033[36m[ >> ]\033[0m";
        case 'fixed': return "\033[32m[FIX ]\033[0m";
        default:      return "      ";
    }
}

function wpc_out(string $msg, string $level = 'info'): void
{
    global $wpc_log_handle;
    $colored = wpc_level_prefix($level) . ' ' . $msg;
    $plain   = preg_replace('/\033\[\d+m/', '', $colored) ?? $colored;
    echo $colored . PHP_EOL;
    if ($wpc_log_handle !== null) {
        fwrite($wpc_log_handle, $plain . PHP_EOL);
    }
}

function wpc_verbose(string $msg): void
{
    global $wpc_config;
    if ($wpc_config !== null && $wpc_config->verbose) {
        wpc_out('  ' . $msg, 'info');
    }
}

function wpc_abort(string $msg, int $code = WPC_EXIT_ERROR): void
{
    wpc_out($msg, 'error');
    exit($code);
}

function wpc_http_get(string $url, int $timeoutSec = 30): ?string
{
    $ctx  = stream_context_create(['http' => [
        'timeout'    => $timeoutSec,
        'user_agent' => 'WP-Cleaner/' . WPC_TOOL_VERSION . ' (WordPress malware scanner)',
        'follow_location' => 1,
    ]]);
    $data = @file_get_contents($url, false, $ctx);
    return ($data !== false) ? $data : null;
}

function wpc_http_download(string $url, string $destPath, int $timeoutSec = 120): bool
{
    $tmp  = $destPath . '.tmp';
    $ctx  = stream_context_create(['http' => [
        'timeout'    => $timeoutSec,
        'user_agent' => 'WP-Cleaner/' . WPC_TOOL_VERSION,
        'follow_location' => 1,
    ]]);
    $data = @file_get_contents($url, false, $ctx);
    if ($data === false) {
        return false;
    }
    if (file_put_contents($tmp, $data) === false) {
        return false;
    }
    return rename($tmp, $destPath);
}

// ════════════════════════════════════════════════════════════════════════════
//  CLI PARSING
// ════════════════════════════════════════════════════════════════════════════

function wpc_help(): void
{
    echo <<<HELP
WP-Cleaner v1.0.0 — WordPress Malware Scanner & Sanitizer (GPL-3.0)

USAGE
  php wp-cleaner.php [options]

OPTIONS
  --scan                Scan only, no changes (default)
  --fix                 Restore modified core files, remove extra files (after backup)
  --db                  Include database scan (reads credentials from wp-config.php)
  --check-vulns         Check WPVulnerability.com API for known CVEs
  --html                Write standalone HTML report to WP root
  --update-signatures   Fetch latest malware signatures and patch this file
  --wp-version <ver>    Override auto-detected WP version (e.g. 6.7.1)
  --wp-root <path>      WP installation root (default: current directory)
  --backup-dir <path>   Override backup directory (default: <wp-root>/wp-cleaner-backup)
  --log <file>          Write log to file in addition to stdout
  --verbose             Show detailed output
  --version             Print tool version and exit
  --help                Print this help and exit

EXIT CODES
  0  No findings detected
  1  Findings detected
  2  Runtime error (version not found, download failed, etc.)

EXAMPLES
  php wp-cleaner.php
  php wp-cleaner.php --fix --html --log /tmp/scan.log
  php wp-cleaner.php --db --check-vulns --verbose
  php wp-cleaner.php --wp-root /var/www/html --fix

HELP;
}

function wpc_parse_cli(array $argv): WpcConfig
{
    $cwd    = getcwd();
    $config = new WpcConfig($cwd !== false ? $cwd : __DIR__);
    $i      = 1;
    $n      = count($argv);

    while ($i < $n) {
        $arg = $argv[$i];
        switch ($arg) {
            case '--scan':
                break; // default, no-op
            case '--fix':
                $config->fixMode = true;
                break;
            case '--db':
                $config->dbScan = true;
                break;
            case '--check-vulns':
                $config->checkVulns = true;
                break;
            case '--html':
                $config->genHtml = true;
                break;
            case '--update-signatures':
                $config->updateSigs = true;
                break;
            case '--verbose':
                $config->verbose = true;
                break;
            case '--version':
                echo 'WP-Cleaner v' . WPC_TOOL_VERSION . PHP_EOL;
                exit(WPC_EXIT_OK);
            case '--help':
                wpc_help();
                exit(WPC_EXIT_OK);
            case '--wp-version':
                $i++;
                $config->wpVersion = $argv[$i] ?? null;
                break;
            case '--wp-root':
                $i++;
                $rawRoot = $argv[$i] ?? null;
                if ($rawRoot !== null) {
                    $resolved = realpath($rawRoot);
                    $root = $resolved !== false ? $resolved : $rawRoot;
                    $config->wpRoot    = rtrim($root, DIRECTORY_SEPARATOR);
                    $config->backupDir = $config->wpRoot . DIRECTORY_SEPARATOR . 'wp-cleaner-backup';
                    $config->cacheDir  = $config->wpRoot . DIRECTORY_SEPARATOR . 'wp-cleaner-cache';
                }
                break;
            case '--backup-dir':
                $i++;
                $config->backupDir = $argv[$i] ?? $config->backupDir;
                break;
            case '--log':
                $i++;
                $config->logFile = $argv[$i] ?? null;
                break;
            default:
                if (str_starts_with($arg, '--')) {
                    fwrite(STDERR, "Unknown option: $arg\n");
                    fwrite(STDERR, "Run 'php wp-cleaner.php --help' for usage.\n");
                    exit(WPC_EXIT_ERROR);
                }
        }
        $i++;
    }

    return $config;
}

// ════════════════════════════════════════════════════════════════════════════
//  WORDPRESS DETECTION
// ════════════════════════════════════════════════════════════════════════════

function wpc_detect_version(string $wpRoot): ?string
{
    $vf = $wpRoot . DIRECTORY_SEPARATOR . 'wp-includes' . DIRECTORY_SEPARATOR . 'version.php';
    if (!is_file($vf)) {
        return null;
    }
    $content = file_get_contents($vf);
    if ($content === false) {
        return null;
    }
    if (preg_match('/\$wp_version\s*=\s*[\'"]([0-9][0-9.]+)[\'"]/', $content, $m)) {
        return $m[1];
    }
    return null;
}

function wpc_detect_db_config(string $wpRoot): array
{
    $cf = $wpRoot . DIRECTORY_SEPARATOR . 'wp-config.php';
    if (!is_file($cf)) {
        return [];
    }
    $content = file_get_contents($cf);
    if ($content === false) {
        return [];
    }

    $cfg = [];
    $map = ['DB_NAME' => 'db_name', 'DB_USER' => 'db_user', 'DB_PASSWORD' => 'db_password', 'DB_HOST' => 'db_host', 'DB_CHARSET' => 'db_charset'];
    foreach ($map as $constant => $key) {
        if (preg_match('/define\s*\(\s*[\'"]' . $constant . '[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]/', $content, $m)) {
            $cfg[$key] = $m[1];
        }
    }
    if (preg_match('/\$table_prefix\s*=\s*[\'"]([^\'"]+)[\'"]/', $content, $m)) {
        $cfg['table_prefix'] = $m[1];
    }

    $cfg['db_charset']    = $cfg['db_charset']    ?? 'utf8';
    $cfg['table_prefix']  = $cfg['table_prefix']  ?? 'wp_';
    return $cfg;
}

// ════════════════════════════════════════════════════════════════════════════
//  ZIP MANAGEMENT
// ════════════════════════════════════════════════════════════════════════════

function wpc_ensure_zip(string $version, string $cacheDir): string
{
    if (!is_dir($cacheDir)) {
        @mkdir($cacheDir, 0755, true);
    }

    $zipPath = $cacheDir . DIRECTORY_SEPARATOR . "wordpress-{$version}.zip";
    $md5File = $zipPath . '.md5';

    // Use cached zip if valid
    if (is_file($zipPath) && is_file($md5File)) {
        $expected = trim((string) file_get_contents($md5File));
        $actual   = (string) md5_file($zipPath);
        if ($expected !== '' && $expected === $actual) {
            wpc_verbose("Using cached zip: $zipPath");
            return $zipPath;
        }
        wpc_out("Cached zip MD5 mismatch — re-downloading.", 'warn');
        @unlink($zipPath);
    }

    // Fetch MD5 reference
    $md5Url = sprintf(WPC_MD5_URL, $version);
    wpc_out("Fetching MD5 checksum: $md5Url", 'step');
    $expectedMd5 = wpc_http_get($md5Url);
    if ($expectedMd5 === null) {
        wpc_abort("Cannot fetch MD5 for WordPress $version. Check internet connection.");
    }
    $expectedMd5 = trim($expectedMd5);
    file_put_contents($md5File, $expectedMd5);

    // Download zip
    $zipUrl = sprintf(WPC_ZIP_URL, $version);
    wpc_out("Downloading WordPress {$version} zip (this may take a moment)…", 'step');
    if (!wpc_http_download($zipUrl, $zipPath)) {
        wpc_abort("Failed to download: $zipUrl");
    }

    // Verify download
    $actualMd5 = (string) md5_file($zipPath);
    if ($actualMd5 !== $expectedMd5) {
        @unlink($zipPath);
        wpc_abort("Downloaded zip MD5 mismatch! Expected: $expectedMd5, Got: $actualMd5");
    }

    wpc_out("WordPress $version downloaded and verified (MD5 OK).", 'ok');
    return $zipPath;
}

/**
 * Returns ['relative/path.php' => 'md5hash', ...] — strips leading 'wordpress/' prefix.
 *
 * @return array<string,string>
 */
function wpc_list_zip_entries(string $zipPath): array
{
    if (!class_exists('ZipArchive')) {
        wpc_abort("php-zip extension not loaded. Install it with: apt install php-zip");
    }

    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        wpc_abort("Cannot open zip: $zipPath");
    }

    $entries = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        if ($name === false) {
            continue;
        }
        // Strip leading 'wordpress/' prefix
        $rel = (string) preg_replace('#^wordpress/#', '', $name);
        // Skip directories
        if ($rel === '' || str_ends_with($rel, '/')) {
            continue;
        }
        $content = $zip->getFromIndex($i);
        if ($content !== false) {
            $entries[$rel] = md5($content);
        }
    }
    $zip->close();
    return $entries;
}

/**
 * Extract a single file from the official WP zip by relative path.
 */
function wpc_get_zip_file(string $zipPath, string $relPath): ?string
{
    $zip = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        return null;
    }
    $content = $zip->getFromName('wordpress/' . $relPath);
    $zip->close();
    return ($content !== false) ? $content : null;
}

// ════════════════════════════════════════════════════════════════════════════
//  WHITELIST / IGNORE FILE
// ════════════════════════════════════════════════════════════════════════════

/**
 * @return string[]
 */
function wpc_load_whitelist(string $wpRoot): array
{
    $base       = WPC_DEFAULT_WHITELIST;
    $ignoreFile = $wpRoot . DIRECTORY_SEPARATOR . '.wp-cleaner-ignore';
    if (!is_file($ignoreFile)) {
        return $base;
    }
    $lines = file($ignoreFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines === false) {
        return $base;
    }
    $extra = array_map('trim', array_filter($lines, fn($l) => !str_starts_with(trim($l), '#')));
    return array_merge($base, $extra);
}

function wpc_is_whitelisted(string $relPath, array $whitelist): bool
{
    $relPath = ltrim(str_replace('\\', '/', $relPath), '/');
    foreach ($whitelist as $entry) {
        $entry = ltrim(str_replace('\\', '/', (string) $entry), '/');
        if ($relPath === $entry) {
            return true;
        }
        if (str_starts_with($relPath, $entry . '/')) {
            return true;
        }
        // Glob-style trailing wildcard
        if (str_ends_with($entry, '*')) {
            $prefix = rtrim(substr($entry, 0, -1), '/');
            if (str_starts_with($relPath, $prefix)) {
                return true;
            }
        }
    }
    return false;
}

// ════════════════════════════════════════════════════════════════════════════
//  CORE INTEGRITY SCAN
// ════════════════════════════════════════════════════════════════════════════

/**
 * Compare each core file on disk against the official zip MD5.
 *
 * @param  array<string,string> $zipEntries
 * @return WpcFinding[]
 */
function wpc_scan_core_integrity(string $wpRoot, array $zipEntries): array
{
    $findings = [];
    // Files that are intentionally absent in a normal install
    $skipFiles = ['wp-config-sample.php'];

    foreach ($zipEntries as $relPath => $expectedMd5) {
        if (in_array($relPath, $skipFiles, true)) {
            continue;
        }
        $diskPath = $wpRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);

        if (!is_file($diskPath)) {
            // Only flag truly critical missing files
            $critical = ['wp-login.php', 'wp-includes/functions.php', 'wp-includes/plugin.php', 'wp-settings.php'];
            if (in_array($relPath, $critical, true)) {
                $findings[] = new WpcFinding('missing', 'warning', $relPath, "Critical core file is missing");
            }
            continue;
        }

        $actualMd5 = (string) md5_file($diskPath);
        if ($actualMd5 !== $expectedMd5) {
            $findings[] = new WpcFinding(
                'modified',
                'critical',
                $relPath,
                "Core file modified — MD5 expected: $expectedMd5, actual: $actualMd5"
            );
        }
    }

    return $findings;
}

/**
 * Find files in core directories (wp-admin, wp-includes) and the root
 * that are NOT in the official release zip.
 *
 * @param  array<string,string> $zipEntries
 * @return WpcFinding[]
 */
function wpc_scan_extra_files(string $wpRoot, array $zipEntries, array $whitelist): array
{
    $findings  = [];
    $coreFiles = array_keys($zipEntries);

    // Walk core-only directories
    foreach (['wp-admin', 'wp-includes'] as $dir) {
        $fullDir = $wpRoot . DIRECTORY_SEPARATOR . $dir;
        if (!is_dir($fullDir)) {
            continue;
        }
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($fullDir, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $relPath = str_replace('\\', '/', substr($file->getPathname(), strlen($wpRoot) + 1));
            if (wpc_is_whitelisted($relPath, $whitelist)) {
                continue;
            }
            if (!in_array($relPath, $coreFiles, true)) {
                $ext      = strtolower(pathinfo($relPath, PATHINFO_EXTENSION));
                $severity = in_array($ext, WPC_PHP_EXTENSIONS, true) ? 'critical' : 'warning';
                $findings[] = new WpcFinding(
                    'extra',
                    $severity,
                    $relPath,
                    "File not in official WordPress release (possible injection)"
                );
            }
        }
    }

    // Walk root-level PHP files
    $rootPhpFiles = glob($wpRoot . DIRECTORY_SEPARATOR . '*.php');
    if ($rootPhpFiles !== false) {
        foreach ($rootPhpFiles as $absPath) {
            $relPath = basename($absPath);
            if (wpc_is_whitelisted($relPath, $whitelist)) {
                continue;
            }
            if (!in_array($relPath, $coreFiles, true)) {
                $findings[] = new WpcFinding(
                    'extra',
                    'warning',
                    $relPath,
                    "Extra PHP file in WordPress root (not in official release)"
                );
            }
        }
    }

    return $findings;
}

// ════════════════════════════════════════════════════════════════════════════
//  PLUGIN & THEME INTEGRITY + HEURISTIC
// ════════════════════════════════════════════════════════════════════════════

function wpc_read_plugin_header(string $content): array
{
    $sample = substr($content, 0, 8192);
    $result = [];
    if (preg_match('/^[ \t\/*#@]*Plugin Name\s*:\s*(.+)$/mi', $sample, $m)) {
        $result['name']     = trim($m[1]);
        $result['is_theme'] = false;
    }
    if (preg_match('/^[ \t\/*#@]*Theme Name\s*:\s*(.+)$/mi', $sample, $m)) {
        $result['name']     = trim($m[1]);
        $result['is_theme'] = true;
    }
    if (preg_match('/^[ \t\/*#@]*Version\s*:\s*([0-9][^\s\r\n*]+)/mi', $sample, $m)) {
        $result['version'] = trim($m[1]);
    }
    return $result;
}

function wpc_find_plugin_main_file(string $pluginDir, string $slug): ?string
{
    // Try slug-named file first (most common convention)
    $candidate = $pluginDir . DIRECTORY_SEPARATOR . $slug . '.php';
    if (is_file($candidate)) {
        return $candidate;
    }
    // Scan all PHP files in plugin root for "Plugin Name:" header
    $phpFiles = glob($pluginDir . DIRECTORY_SEPARATOR . '*.php');
    if ($phpFiles === false) {
        return null;
    }
    foreach ($phpFiles as $file) {
        $content = file_get_contents($file);
        if ($content !== false && stripos(substr($content, 0, 8192), 'Plugin Name:') !== false) {
            return $file;
        }
    }
    return null;
}

function wpc_ensure_plugin_zip(string $slug, string $version, string $cacheDir): ?string
{
    $zipPath = $cacheDir . DIRECTORY_SEPARATOR . "plugin-{$slug}-{$version}.zip";
    if (is_file($zipPath)) {
        return $zipPath;
    }
    $url = sprintf(WPC_PLUGIN_DL_URL, $slug, $version);
    wpc_verbose("Downloading plugin $slug $version from: $url");
    if (!wpc_http_download($url, $zipPath, 60)) {
        @unlink($zipPath);
        return null;
    }
    return $zipPath;
}

/**
 * @return WpcFinding[]
 */
function wpc_compare_against_zip(string $localDir, string $zipPath, string $displayPrefix): array
{
    $findings = [];
    $zip      = new ZipArchive();
    if ($zip->open($zipPath) !== true) {
        return $findings;
    }

    // Build map: relPath => md5 (strip first path component, i.e. slug/)
    $zipFiles = [];
    for ($i = 0; $i < $zip->numFiles; $i++) {
        $name = $zip->getNameIndex($i);
        if ($name === false || str_ends_with($name, '/')) {
            continue;
        }
        $rel     = (string) preg_replace('#^[^/]+/#', '', $name);
        $content = $zip->getFromIndex($i);
        if ($content !== false) {
            $zipFiles[$rel] = md5($content);
        }
    }
    $zip->close();

    // Walk local files
    $localLen = strlen(rtrim($localDir, DIRECTORY_SEPARATOR)) + 1;
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($localDir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $absPath = $file->getPathname();
        $relPath = str_replace('\\', '/', substr($absPath, $localLen));

        if (isset($zipFiles[$relPath])) {
            $actualMd5 = (string) md5_file($absPath);
            if ($actualMd5 !== $zipFiles[$relPath]) {
                $findings[] = new WpcFinding(
                    'modified', 'critical',
                    $displayPrefix . '/' . $relPath,
                    "File modified (integrity check failed)"
                );
            }
        } else {
            $ext = strtolower(pathinfo($relPath, PATHINFO_EXTENSION));
            if (in_array($ext, WPC_PHP_EXTENSIONS, true)) {
                $findings[] = new WpcFinding(
                    'extra', 'critical',
                    $displayPrefix . '/' . $relPath,
                    "Extra PHP file injected into $displayPrefix"
                );
            }
        }
    }

    return $findings;
}

/**
 * @return WpcFinding[]
 */
function wpc_scan_plugins(string $wpRoot, string $cacheDir, array $whitelist): array
{
    $findings   = [];
    $pluginsDir = $wpRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'plugins';
    if (!is_dir($pluginsDir)) {
        return $findings;
    }

    $entries = scandir($pluginsDir);
    if ($entries === false) {
        return $findings;
    }
    $slugs = array_filter($entries, fn($d) => $d !== '.' && $d !== '..' && is_dir("$pluginsDir/$d"));

    foreach ($slugs as $slug) {
        $pluginDir   = $pluginsDir . DIRECTORY_SEPARATOR . $slug;
        $displayPath = "wp-content/plugins/$slug";

        if (wpc_is_whitelisted("wp-content/plugins/$slug", $whitelist)) {
            wpc_verbose("Skipping whitelisted plugin: $slug");
            continue;
        }

        $mainFile = wpc_find_plugin_main_file($pluginDir, $slug);
        if ($mainFile === null) {
            wpc_verbose("No main file for plugin: $slug — heuristic only");
            $h = wpc_scan_heuristic_dir($pluginDir);
            foreach ($h as $f) {
                $findings[] = $f;
            }
            continue;
        }

        $content = (string) @file_get_contents($mainFile);
        $header  = wpc_read_plugin_header($content);

        if (empty($header['version'])) {
            // No version detected — heuristic only
            wpc_verbose("No version in plugin: $slug — heuristic only");
            $h = wpc_scan_heuristic_dir($pluginDir);
            foreach ($h as $f) {
                $findings[] = $f;
            }
            continue;
        }

        $version = $header['version'];
        $zipPath = wpc_ensure_plugin_zip($slug, $version, $cacheDir);

        if ($zipPath === null) {
            wpc_out("Plugin '$slug' v$version not found on wp.org — heuristic scan only (unverifiable).", 'warn');
            $h = wpc_scan_heuristic_dir($pluginDir);
            foreach ($h as $f) {
                $f->detail = "[Unverifiable plugin: $slug] " . $f->detail;
                $findings[] = $f;
            }
            continue;
        }

        wpc_verbose("Checking integrity: $slug $version");
        $integrity = wpc_compare_against_zip($pluginDir, $zipPath, $displayPath);
        $findings  = array_merge($findings, $integrity);
    }

    return $findings;
}

// ════════════════════════════════════════════════════════════════════════════
//  HEURISTIC SCAN
// ════════════════════════════════════════════════════════════════════════════

/**
 * @return WpcFinding[]
 */
function wpc_scan_heuristic_file(string $absPath, string $relPath): array
{
    $findings = [];
    $content  = @file_get_contents($absPath);
    if ($content === false) {
        return $findings;
    }

    $isHtaccess = (basename($absPath) === '.htaccess');
    $ext        = strtolower(pathinfo($absPath, PATHINFO_EXTENSION));

    // .htaccess: dedicated pattern set
    if ($isHtaccess) {
        foreach (WPC_SIG_HTACCESS as $name => $pattern) {
            if (preg_match($pattern, $content, $m)) {
                $findings[] = new WpcFinding(
                    'heuristic', 'critical', $relPath,
                    "Suspicious .htaccess directive ($name)",
                    [trim($m[0])]
                );
            }
        }
        return $findings;
    }

    // Only scan PHP/script extensions
    $scanExts = array_merge(WPC_PHP_EXTENSIONS, WPC_UPLOAD_EXTENSIONS);
    if (!in_array($ext, $scanExts, true)) {
        return $findings;
    }

    $matched = [];

    foreach (WPC_SIG_REGEX as $name => $pattern) {
        if (preg_match($pattern, $content, $m)) {
            $matched[] = $name . ': ' . substr(trim($m[0]), 0, 150);
        }
    }

    foreach (WPC_SIG_LITERAL as $literal) {
        if (stripos($content, $literal) !== false) {
            $matched[] = 'literal: ' . $literal;
        }
    }

    if (!empty($matched)) {
        $findings[] = new WpcFinding(
            'heuristic', 'critical', $relPath,
            count($matched) . ' suspicious pattern(s) detected',
            $matched
        );
    }

    return $findings;
}

/**
 * @return WpcFinding[]
 */
function wpc_scan_heuristic_dir(string $dir): array
{
    $findings = [];
    if (!is_dir($dir)) {
        return $findings;
    }
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($iterator as $file) {
        if (!$file->isFile()) {
            continue;
        }
        $absPath = $file->getPathname();
        $relPath = str_replace('\\', '/', $absPath);
        $more    = wpc_scan_heuristic_file($absPath, $relPath);
        $findings = array_merge($findings, $more);
    }
    return $findings;
}

/**
 * Heuristic scan on wp-config.php, .htaccess files, and the uploads directory.
 *
 * @return WpcFinding[]
 */
function wpc_scan_special_files(string $wpRoot): array
{
    $findings = [];
    $specials = [
        $wpRoot . DIRECTORY_SEPARATOR . 'wp-config.php',
        $wpRoot . DIRECTORY_SEPARATOR . '.htaccess',
        $wpRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . '.htaccess',
    ];

    foreach ($specials as $absPath) {
        if (!is_file($absPath)) {
            continue;
        }
        $relPath = str_replace($wpRoot . DIRECTORY_SEPARATOR, '', $absPath);
        $relPath = str_replace('\\', '/', $relPath);
        $more    = wpc_scan_heuristic_file($absPath, $relPath);
        $findings = array_merge($findings, $more);

        // Extra check: code BEFORE the opening <?php tag in wp-config.php
        if (basename($absPath) === 'wp-config.php') {
            $content = (string) @file_get_contents($absPath);
            $phpPos  = strpos($content, '<?php');
            if ($phpPos !== false && $phpPos > 0) {
                $before = trim(substr($content, 0, $phpPos));
                if ($before !== '') {
                    $findings[] = new WpcFinding(
                        'heuristic', 'critical', $relPath,
                        "Code found BEFORE opening <?php tag — possible prepend injection",
                        [substr($before, 0, 200)]
                    );
                }
            }
        }
    }

    // Scan uploads for executable files (PHP/scripts should never be there)
    $uploadsDir = $wpRoot . DIRECTORY_SEPARATOR . 'wp-content' . DIRECTORY_SEPARATOR . 'uploads';
    if (is_dir($uploadsDir)) {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($uploadsDir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }
            $ext = strtolower(pathinfo($file->getPathname(), PATHINFO_EXTENSION));
            if (in_array($ext, WPC_UPLOAD_EXTENSIONS, true)) {
                $relPath = str_replace('\\', '/', substr($file->getPathname(), strlen($wpRoot) + 1));
                $findings[] = new WpcFinding(
                    'extra', 'critical', $relPath,
                    "Executable file found in uploads directory (PHP/scripts must not be here)"
                );
            }
        }
    }

    return $findings;
}

// ════════════════════════════════════════════════════════════════════════════
//  DATABASE SCAN (read-only)
// ════════════════════════════════════════════════════════════════════════════

/**
 * @return array{findings: WpcFinding[], sql: string[]}
 */
function wpc_scan_db(array $dbCfg): array
{
    $findings = [];
    $sql      = [];
    $prefix   = $dbCfg['table_prefix'];

    // Parse host:port
    $host = $dbCfg['db_host'];
    $port = 3306;
    if (str_contains($host, ':')) {
        [$host, $portStr] = explode(':', $host, 2);
        $port = (int) $portStr;
    }

    try {
        $dsn = sprintf(
            'mysql:host=%s;port=%d;dbname=%s;charset=%s',
            $host, $port, $dbCfg['db_name'], $dbCfg['db_charset']
        );
        $pdo = new PDO($dsn, $dbCfg['db_user'], $dbCfg['db_password'], [
            PDO::ATTR_ERRMODE  => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_TIMEOUT  => 10,
        ]);
    } catch (PDOException $e) {
        return ['findings' => [
            new WpcFinding('db', 'warning', 'database', "Cannot connect to DB: " . $e->getMessage()),
        ], 'sql' => []];
    }

    // 1. Admin users (informational)
    try {
        $stmt = $pdo->query(
            "SELECT u.ID, u.user_login, u.user_email
               FROM {$prefix}users u
               JOIN {$prefix}usermeta um ON u.ID = um.user_id
              WHERE um.meta_key = '{$prefix}capabilities'
                AND um.meta_value LIKE '%administrator%'"
        );
        foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $findings[] = new WpcFinding(
                'db', 'info', 'database:wp_users',
                "Admin: ID={$row['ID']} login={$row['user_login']} email={$row['user_email']}"
            );
        }
    } catch (Exception $e) {
        wpc_verbose("DB admin-users query failed: " . $e->getMessage());
    }

    // 2. Injected JS/iframes in wp_posts
    $jsKeywords = ['<script', '<iframe', 'document.write', 'eval(base64', 'unescape('];
    foreach ($jsKeywords as $kw) {
        try {
            $stmt = $pdo->prepare(
                "SELECT ID, post_title, post_status
                   FROM {$prefix}posts
                  WHERE post_content LIKE :kw
                    AND post_status != 'auto-draft'
                  LIMIT 20"
            );
            $stmt->execute([':kw' => '%' . $kw . '%']);
            foreach ($stmt->fetchAll(PDO::FETCH_ASSOC) as $row) {
                $findings[] = new WpcFinding(
                    'db', 'warning',
                    "database:{$prefix}posts:ID={$row['ID']}",
                    "Post «{$row['post_title']}» ({$row['post_status']}) contains: $kw"
                );
                $sql[] = "-- Post ID {$row['ID']} «{$row['post_title']}» — review for injected code";
                $sql[] = "-- UPDATE {$prefix}posts SET post_content = REPLACE(post_content, 'MALICIOUS_CODE', '') WHERE ID = {$row['ID']};";
                $sql[] = "";
            }
        } catch (Exception $e) {
            wpc_verbose("DB posts query failed for '$kw': " . $e->getMessage());
        }
    }

    // 3. Suspicious wp_options values
    $monitoredOpts = ['siteurl', 'home', 'admin_email', 'blogname', 'blogdescription', 'upload_path'];
    try {
        $in   = implode(',', array_fill(0, count($monitoredOpts), '?'));
        $stmt = $pdo->prepare("SELECT option_name, option_value FROM {$prefix}options WHERE option_name IN ($in)");
        $stmt->execute($monitoredOpts);
        foreach ($stmt->fetchAll(PDO::FETCH_KEY_PAIR) as $name => $value) {
            if (preg_match('/<script|<iframe|eval\s*\(|base64/i', (string) $value)) {
                $findings[] = new WpcFinding(
                    'db', 'critical',
                    "database:{$prefix}options:$name",
                    "Suspicious code in option '$name': " . substr((string) $value, 0, 200)
                );
                $sql[] = "-- REVIEW and fix option '$name' (current value is suspicious)";
                $sql[] = "-- UPDATE {$prefix}options SET option_value = 'CORRECT_VALUE' WHERE option_name = '$name';";
                $sql[] = "";
            }
        }
    } catch (Exception $e) {
        wpc_verbose("DB options query failed: " . $e->getMessage());
    }

    // 4. Hidden/malicious cron jobs
    try {
        $stmt   = $pdo->query("SELECT option_value FROM {$prefix}options WHERE option_name = 'cron' LIMIT 1");
        $cronRaw = $stmt->fetchColumn();
        if ($cronRaw !== false) {
            $cron = @unserialize((string) $cronRaw);
            if (is_array($cron)) {
                foreach ($cron as $timestamp => $events) {
                    if (!is_array($events)) {
                        continue;
                    }
                    foreach (array_keys($events) as $hookName) {
                        if (preg_match('/[a-f0-9]{10,}|eval|base64|shell|cmd/i', (string) $hookName)) {
                            $findings[] = new WpcFinding(
                                'db', 'critical',
                                "database:{$prefix}options:cron",
                                "Suspicious cron hook: '$hookName' scheduled at $timestamp"
                            );
                            $sql[] = "-- Remove suspicious cron hook '$hookName':";
                            $sql[] = "-- wp eval \"wp_clear_scheduled_hook('$hookName');\"";
                            $sql[] = "";
                        }
                    }
                }
            }
        }
    } catch (Exception $e) {
        wpc_verbose("DB cron query failed: " . $e->getMessage());
    }

    return ['findings' => $findings, 'sql' => $sql];
}

// ════════════════════════════════════════════════════════════════════════════
//  CVE CHECK
// ════════════════════════════════════════════════════════════════════════════

/**
 * @return WpcFinding[]
 */
function wpc_check_vulns_core(string $wpVersion): array
{
    $url  = sprintf(WPC_CVE_CORE_URL, $wpVersion);
    $raw  = wpc_http_get($url, 10);
    if ($raw === null) {
        wpc_out("CVE API unavailable for core check (no internet or API down).", 'warn');
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data['vulnerability'])) {
        return [];
    }
    $findings = [];
    foreach ($data['vulnerability'] as $vuln) {
        $cve   = $vuln['cve']        ?? 'no-CVE';
        $title = $vuln['name']       ?? 'Unknown vulnerability';
        $cvss  = $vuln['cvss']['score'] ?? '?';
        $findings[] = new WpcFinding(
            'cve', 'critical',
            "core:$wpVersion",
            "[$cve] CVSS $cvss — $title"
        );
    }
    return $findings;
}

/**
 * @return WpcFinding[]
 */
function wpc_check_vulns_plugin(string $slug, string $version): array
{
    $url  = sprintf(WPC_CVE_PLUGIN_URL, $slug, $version);
    $raw  = wpc_http_get($url, 10);
    if ($raw === null) {
        return [];
    }
    $data = json_decode($raw, true);
    if (!is_array($data) || empty($data['vulnerability'])) {
        return [];
    }
    $findings = [];
    foreach ($data['vulnerability'] as $vuln) {
        $cve   = $vuln['cve']           ?? 'no-CVE';
        $title = $vuln['name']          ?? 'Unknown vulnerability';
        $cvss  = $vuln['cvss']['score'] ?? '?';
        $findings[] = new WpcFinding(
            'cve', 'critical',
            "plugin:$slug:$version",
            "[$cve] CVSS $cvss — $title"
        );
    }
    return $findings;
}

// ════════════════════════════════════════════════════════════════════════════
//  BACKUP & FIX
// ════════════════════════════════════════════════════════════════════════════

function wpc_do_backup(array $relPaths, string $wpRoot, string $backupDir): string
{
    $ts      = date('Y-m-d_H-i-s');
    $destDir = $backupDir . DIRECTORY_SEPARATOR . $ts;
    @mkdir($destDir, 0755, true);

    foreach ($relPaths as $relPath) {
        $src  = $wpRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        $dest = $destDir . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        if (!is_file($src)) {
            continue;
        }
        @mkdir(dirname($dest), 0755, true);
        @copy($src, $dest);
    }

    // Compress backup
    $zipPath = $backupDir . DIRECTORY_SEPARATOR . "backup-{$ts}.zip";
    $zip     = new ZipArchive();
    if ($zip->open($zipPath, ZipArchive::CREATE) === true) {
        $iter = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($destDir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($iter as $f) {
            if ($f->isFile()) {
                $rel = substr($f->getPathname(), strlen($destDir) + 1);
                $zip->addFile($f->getPathname(), $rel);
            }
        }
        $zip->close();
        wpc_out("Backup archive: $zipPath", 'ok');
    }

    return $destDir;
}

/**
 * @return array{fixed: string[], errors: string[]}
 */
function wpc_do_fix(array $findings, string $wpRoot, string $zipPath, string $backupDir): array
{
    $toRestore = [];
    $toRemove  = [];

    foreach ($findings as $f) {
        if ($f->type === 'modified') {
            $toRestore[] = $f->path;
        } elseif ($f->type === 'extra') {
            $toRemove[] = $f->path;
        }
    }

    // Backup everything first
    $allPaths = array_merge($toRestore, $toRemove);
    if (!empty($allPaths)) {
        wpc_do_backup($allPaths, $wpRoot, $backupDir);
    }

    $fixed  = [];
    $errors = [];

    // Restore modified core files from zip
    // Plugin and theme files are NOT in the core zip — skip them with a clear notice
    $cannotRestoreFromCore = ['wp-content/plugins/', 'wp-content/themes/', 'wp-content/mu-plugins/'];
    foreach ($toRestore as $relPath) {
        $isThirdParty = false;
        foreach ($cannotRestoreFromCore as $prefix) {
            if (str_starts_with($relPath, $prefix)) {
                $isThirdParty = true;
                break;
            }
        }
        if ($isThirdParty) {
            $errors[] = "Cannot auto-restore plugin/theme file (restore manually or reinstall the plugin): $relPath";
            wpc_out("Skipped (plugin/theme — must restore manually): $relPath", 'warn');
            continue;
        }

        $content  = wpc_get_zip_file($zipPath, $relPath);
        $diskPath = $wpRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        if ($content === null) {
            $errors[] = "File not found in core zip (unexpected): $relPath";
            continue;
        }
        if (file_put_contents($diskPath, $content) === false) {
            $errors[] = "Cannot write file (check permissions): $diskPath";
            continue;
        }
        $fixed[] = $relPath;
        wpc_out("Restored: $relPath", 'fixed');
    }

    // Remove extra files
    foreach ($toRemove as $relPath) {
        $diskPath = $wpRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relPath);
        if (!is_file($diskPath)) {
            continue;
        }
        if (@unlink($diskPath)) {
            $fixed[] = $relPath . ' (removed)';
            wpc_out("Removed:  $relPath", 'fixed');
        } else {
            $errors[] = "Cannot remove (check permissions): $diskPath";
        }
    }

    return ['fixed' => $fixed, 'errors' => $errors];
}

// ════════════════════════════════════════════════════════════════════════════
//  SIGNATURE UPDATE (self-patching)
// ════════════════════════════════════════════════════════════════════════════

function wpc_update_signatures(): void
{
    wpc_out("Fetching updated signatures from scr34m/php-malware-scanner…", 'step');

    $regexRaw   = wpc_http_get(WPC_SIG_REGEX_URL, 30);
    $literalRaw = wpc_http_get(WPC_SIG_RAW_URL,   30);

    if ($regexRaw === null || $literalRaw === null) {
        wpc_abort("Cannot fetch signatures. Check internet connection.");
    }

    // Parse and validate regex patterns
    $regexLines = array_filter(
        explode("\n", $regexRaw),
        fn($l) => trim($l) !== '' && !str_starts_with(trim($l), '#')
    );
    $validRegex = [];
    foreach ($regexLines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        if (@preg_match($line, '') === false) {
            wpc_verbose("Skipping invalid regex: $line");
            continue;
        }
        $validRegex[] = $line;
    }

    $literalLines = array_filter(
        explode("\n", $literalRaw),
        fn($l) => trim($l) !== '' && !str_starts_with(trim($l), '#')
    );
    $validLiterals = array_values(array_map('trim', array_filter($literalLines, fn($l) => trim($l) !== '')));

    // Build new PHP constant source
    $newBlock  = "const WPC_SIG_REGEX = [\n";
    foreach ($validRegex as $pattern) {
        $esc        = str_replace("'", "\\'", $pattern);
        $newBlock  .= "    '$esc',\n";
    }
    $newBlock .= "];\n\n";
    $newBlock .= "const WPC_SIG_LITERAL = [\n";
    foreach ($validLiterals as $lit) {
        $esc       = str_replace("'", "\\'", $lit);
        $newBlock .= "    '$esc',\n";
    }
    $newBlock .= "];\n\n";
    $newBlock .= "const WPC_SIG_HTACCESS = [\n";
    $newBlock .= "    'auto_prepend'  => '/php_value\\s+auto_prepend_file/i',\n";
    $newBlock .= "    'auto_append'   => '/php_value\\s+auto_append_file/i',\n";
    $newBlock .= "    'add_handler'   => '/AddHandler\\s+application\\/x-httpd-php\\s+\\.\\w+/i',\n";
    $newBlock .= "    'rewrite_ext'   => '/RewriteRule\\s+.+\\s+https?:\\/\\//i',\n";
    $newBlock .= "];\n";

    // Self-patch between markers
    $selfPath    = __FILE__;
    $selfContent = file_get_contents($selfPath);
    if ($selfContent === false) {
        wpc_abort("Cannot read self: $selfPath");
    }

    $startMarker = '// <WP_CLEANER_SIGNATURES_START>';
    $endMarker   = '// <WP_CLEANER_SIGNATURES_END>';
    $startPos    = strpos($selfContent, $startMarker);
    $endPos      = strpos($selfContent, $endMarker);

    if ($startPos === false || $endPos === false) {
        wpc_abort("Signature markers not found in script. File may be corrupted.");
    }

    $before  = substr($selfContent, 0, $startPos + strlen($startMarker));
    $after   = substr($selfContent, $endPos);
    $patched = $before . "\n" . $newBlock . $after;

    if (file_put_contents($selfPath, $patched) === false) {
        wpc_abort("Cannot write to: $selfPath (check permissions)");
    }

    wpc_out(sprintf(
        "Signatures updated — %d regex, %d literals written to: %s",
        count($validRegex),
        count($validLiterals),
        $selfPath
    ), 'ok');
}

// ════════════════════════════════════════════════════════════════════════════
//  REPORTING
// ════════════════════════════════════════════════════════════════════════════

function wpc_render_text(WpcReport $report): string
{
    $sep  = str_repeat('═', 72);
    $sep2 = str_repeat('─', 72);
    $out  = [];

    $out[] = $sep;
    $out[] = "  WP-Cleaner v" . WPC_TOOL_VERSION . " — Security Report";
    $out[] = $sep;
    $out[] = "  WP Root    : " . $report->config->wpRoot;
    $out[] = "  WP Version : " . $report->wpVersion;
    $out[] = "  Timestamp  : " . $report->timestamp;
    $out[] = "  Mode       : " . ($report->config->fixMode ? 'FIX' : 'SCAN (dry-run)');
    $out[] = $sep;

    if (empty($report->findings)) {
        $out[] = "  ✅  No findings detected. WordPress appears clean.";
        $out[] = $sep;
        return implode(PHP_EOL, $out) . PHP_EOL;
    }

    $out[] = sprintf(
        "  Findings: %d total  |  Critical: %d  |  Warning: %d  |  Info: %d",
        count($report->findings),
        $report->countBySeverity('critical'),
        $report->countBySeverity('warning'),
        $report->countBySeverity('info')
    );
    $out[] = $sep;

    $groups = [
        'modified'  => '🔴  MODIFIED CORE FILES',
        'extra'     => '🟠  EXTRA / INJECTED FILES',
        'heuristic' => '⚠️   HEURISTIC HITS',
        'db'        => '🗄️   DATABASE FINDINGS',
        'cve'       => '🛡️   KNOWN CVEs',
        'missing'   => 'ℹ️   MISSING CORE FILES',
    ];

    foreach ($groups as $type => $title) {
        $group = array_filter($report->findings, fn($f) => $f->type === $type);
        if (empty($group)) {
            continue;
        }
        $out[] = '';
        $out[] = "  $title (" . count($group) . ")";
        $out[] = $sep2;
        foreach ($group as $f) {
            $sevTag  = $f->severity === 'critical' ? '[CRIT]' : ($f->severity === 'warning' ? '[WARN]' : '[INFO]');
            $fixTag  = $f->fixed ? '  ✓ FIXED' : '';
            $out[]   = "  $sevTag  {$f->path}{$fixTag}";
            $out[]   = "            → {$f->detail}";
            if (!empty($f->matches)) {
                foreach (array_slice($f->matches, 0, 3) as $match) {
                    $out[] = "            • " . substr($match, 0, 130);
                }
                if (count($f->matches) > 3) {
                    $out[] = "            (+" . (count($f->matches) - 3) . " more patterns matched)";
                }
            }
        }
    }

    if (!empty($report->fixed)) {
        $out[] = '';
        $out[] = $sep2;
        $out[] = "  ✅  FIXED / REMOVED (" . count($report->fixed) . ")";
        foreach ($report->fixed as $path) {
            $out[] = "     • $path";
        }
    }

    if (!empty($report->errors)) {
        $out[] = '';
        $out[] = "  ❌  ERRORS DURING FIX";
        foreach ($report->errors as $err) {
            $out[] = "     • $err";
        }
    }

    if (!empty($report->sqlFixes)) {
        $out[] = '';
        $out[] = $sep2;
        $out[] = "  SQL REMEDIATION — review carefully before running";
        $out[] = $sep2;
        foreach ($report->sqlFixes as $line) {
            $out[] = "  $line";
        }
    }

    $out[] = '';
    $out[] = $sep;
    return implode(PHP_EOL, $out) . PHP_EOL;
}

function wpc_render_html(WpcReport $report): string
{
    $esc = fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

    $rows = '';
    foreach ($report->findings as $f) {
        $sevCls   = $f->severity === 'critical' ? 'crit' : ($f->severity === 'warning' ? 'warn' : 'info');
        $typeLabel= ucfirst($f->type);
        $fixBadge = $f->fixed ? ' <span class="badge-ok">FIXED</span>' : '';
        $matches  = '';
        if (!empty($f->matches)) {
            $items = array_map(
                fn($m) => '<li>' . $esc(substr($m, 0, 200)) . '</li>',
                array_slice($f->matches, 0, 5)
            );
            $matches = '<ul class="matches">' . implode('', $items) . '</ul>';
            if (count($f->matches) > 5) {
                $matches .= '<p class="more">+' . (count($f->matches) - 5) . ' more…</p>';
            }
        }
        $rows .= '<tr class="sev-' . $sevCls . '">'
            . '<td><span class="badge ' . $sevCls . '">' . $f->severity . '</span></td>'
            . '<td>' . $typeLabel . '</td>'
            . '<td class="path">' . $esc($f->path) . $fixBadge . '</td>'
            . '<td>' . $esc($f->detail) . $matches . '</td>'
            . '</tr>' . "\n";
    }

    $isClean = empty($report->findings);
    $banner  = $isClean
        ? '<div class="banner clean">✅ No findings detected. WordPress appears clean.</div>'
        : '<div class="banner warn">⚠️ ' . count($report->findings) . ' finding(s) detected. Review and act below.</div>';

    $table = $isClean ? '' : '<table><thead><tr>'
        . '<th>Severity</th><th>Type</th><th>Path / Location</th><th>Detail</th>'
        . '</tr></thead><tbody>' . $rows . '</tbody></table>';

    $sqlSection = '';
    if (!empty($report->sqlFixes)) {
        $sqlHtml    = $esc(implode("\n", $report->sqlFixes));
        $sqlSection = '<h2>🗄 SQL Remediation</h2>'
            . '<p><strong>Review carefully before running on the database.</strong></p>'
            . '<pre class="sql">' . $sqlHtml . '</pre>';
    }

    $v     = WPC_TOOL_VERSION;
    $ts    = $esc($report->timestamp);
    $wpv   = $esc($report->wpVersion);
    $root  = $esc($report->config->wpRoot);
    $mode  = $report->config->fixMode ? 'FIX' : 'SCAN (dry-run)';
    $stats = sprintf(
        'Total: %d &nbsp;|&nbsp; <span class="crit-text">Critical: %d</span> &nbsp;|&nbsp; Warning: %d &nbsp;|&nbsp; Info: %d',
        count($report->findings),
        $report->countBySeverity('critical'),
        $report->countBySeverity('warning'),
        $report->countBySeverity('info')
    );

    return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WP-Cleaner Report — {$ts}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#222;padding:24px}
.container{max-width:1280px;margin:0 auto;background:#fff;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.1);padding:36px}
h1{font-size:1.7em;margin-bottom:6px;display:flex;align-items:center;gap:10px}
h2{font-size:1.1em;margin:28px 0 10px;padding-bottom:6px;border-bottom:2px solid #eee}
.meta{color:#555;font-size:.9em;margin:12px 0 20px;display:flex;flex-wrap:wrap;gap:18px}
.meta span code{background:#f4f4f4;padding:1px 6px;border-radius:4px;font-size:.95em}
.banner{padding:14px 20px;border-radius:8px;margin:18px 0;font-weight:600;font-size:1.05em}
.banner.clean{background:#d4edda;color:#155724}
.banner.warn{background:#fff3cd;color:#856404}
.stats{margin-bottom:16px;font-size:.9em;color:#444}
.crit-text{color:#dc3545;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:.87em;margin-top:14px}
th{background:#2d3748;color:#fff;padding:9px 12px;text-align:left;font-weight:600}
td{padding:8px 12px;border-bottom:1px solid #f0f0f0;vertical-align:top}
tr.sev-crit{border-left:4px solid #dc3545}
tr.sev-warn{border-left:4px solid #ffc107}
tr.sev-info{border-left:4px solid #17a2b8}
tr:hover td{background:#fafbff}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.78em;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.badge.crit{background:#dc3545;color:#fff}
.badge.warn{background:#ffc107;color:#000}
.badge.info{background:#17a2b8;color:#fff}
.badge-ok{background:#28a745;color:#fff;padding:2px 7px;border-radius:4px;font-size:.75em;font-weight:700;margin-left:8px}
.path{font-family:'SFMono-Regular',Consolas,monospace;word-break:break-all;font-size:.85em}
ul.matches{padding-left:18px;margin-top:6px;color:#555;font-size:.84em;font-family:monospace}
ul.matches li{margin-bottom:3px}
p.more{font-size:.8em;color:#888;margin-top:4px;padding-left:18px}
pre.sql{background:#1e1e2e;color:#cdd6f4;padding:20px;border-radius:8px;overflow-x:auto;font-size:.84em;line-height:1.6;margin-top:12px}
footer{text-align:center;color:#aaa;font-size:.8em;margin-top:28px;padding-top:16px;border-top:1px solid #eee}
</style>
</head>
<body>
<div class="container">
  <h1>🧹 WP-Cleaner <small style="font-size:.55em;color:#888">v{$v}</small></h1>
  <div class="meta">
    <span>📁 Root: <code>{$root}</code></span>
    <span>🔖 WordPress: <strong>{$wpv}</strong></span>
    <span>🕐 {$ts}</span>
    <span>Mode: <strong>{$mode}</strong></span>
  </div>
  {$banner}
  {$table}
  <div class="stats">{$stats}</div>
  {$sqlSection}
  <footer>Generated by WP-Cleaner v{$v} — GPL-3.0-or-later</footer>
</div>
</body>
</html>
HTML;
}

// ════════════════════════════════════════════════════════════════════════════
//  MAIN
// ════════════════════════════════════════════════════════════════════════════

function main(array $argv): int
{
    global $wpc_log_handle, $wpc_config;

    if (PHP_SAPI !== 'cli') {
        echo "ERROR: WP-Cleaner must be run from the command line (CLI).\n";
        return WPC_EXIT_ERROR;
    }

    if (!class_exists('ZipArchive')) {
        echo "ERROR: The php-zip extension is required. Install it (e.g. apt install php-zip).\n";
        return WPC_EXIT_ERROR;
    }

    $config     = wpc_parse_cli($argv);
    $wpc_config = $config;

    // Open log file
    if ($config->logFile !== null) {
        $wpc_log_handle = @fopen($config->logFile, 'a');
        if ($wpc_log_handle === false) {
            $wpc_log_handle = null;
            wpc_out("Cannot open log file: {$config->logFile}", 'warn');
        }
    }

    echo PHP_EOL;
    wpc_out("WP-Cleaner v" . WPC_TOOL_VERSION . " started", 'step');
    echo PHP_EOL;

    // --update-signatures is a standalone operation
    if ($config->updateSigs) {
        wpc_update_signatures();
        return WPC_EXIT_OK;
    }

    // Validate WP root
    if (!is_dir($config->wpRoot)) {
        wpc_abort("Directory not found: {$config->wpRoot}");
    }

    // Detect WP version
    $wpVersion = $config->wpVersion ?? wpc_detect_version($config->wpRoot);
    if ($wpVersion === null) {
        wpc_abort(
            "WordPress version not found.\n" .
            "  Ensure you are in a WordPress root (wp-includes/version.php must exist).\n" .
            "  You can also pass: --wp-version 6.7.1"
        );
    }
    wpc_out("WordPress root    : {$config->wpRoot}", 'info');
    wpc_out("WordPress version : $wpVersion", 'ok');
    echo PHP_EOL;

    // Ensure cache directory
    @mkdir($config->cacheDir, 0755, true);

    // Download + verify official WP release zip
    $zipPath = wpc_ensure_zip($wpVersion, $config->cacheDir);
    echo PHP_EOL;

    // List all official files
    wpc_out("Reading official file manifest from zip…", 'step');
    $zipEntries = wpc_list_zip_entries($zipPath);
    wpc_out(count($zipEntries) . " files in official WordPress $wpVersion release.", 'ok');
    echo PHP_EOL;

    // Load whitelist (default + .wp-cleaner-ignore)
    $config->whitelist = wpc_load_whitelist($config->wpRoot);

    $report = new WpcReport($config, $wpVersion);

    // ── 1. Core integrity ───────────────────────────────────────────────────
    wpc_out("[1/5] Core file integrity scan…", 'step');
    $coreFindings = wpc_scan_core_integrity($config->wpRoot, $zipEntries);
    wpc_out(count($coreFindings) . " modified/missing core file(s).", count($coreFindings) > 0 ? 'warn' : 'ok');
    $report->findings = array_merge($report->findings, $coreFindings);
    echo PHP_EOL;

    // ── 2. Extra files ──────────────────────────────────────────────────────
    wpc_out("[2/5] Extra file detection (core directories + root)…", 'step');
    $extraFindings = wpc_scan_extra_files($config->wpRoot, $zipEntries, $config->whitelist);
    wpc_out(count($extraFindings) . " extra file(s) detected.", count($extraFindings) > 0 ? 'warn' : 'ok');
    $report->findings = array_merge($report->findings, $extraFindings);
    echo PHP_EOL;

    // ── 3. Heuristic scan ───────────────────────────────────────────────────
    wpc_out("[3/5] Heuristic scan (wp-config.php, .htaccess, uploads, plugins)…", 'step');
    $heurFindings = wpc_scan_special_files($config->wpRoot);
    $plugFindings = wpc_scan_plugins($config->wpRoot, $config->cacheDir, $config->whitelist);
    $allHeur      = array_merge($heurFindings, $plugFindings);
    wpc_out(count($allHeur) . " heuristic/plugin finding(s).", count($allHeur) > 0 ? 'warn' : 'ok');
    $report->findings = array_merge($report->findings, $allHeur);
    echo PHP_EOL;

    // ── 4. CVE check (optional) ─────────────────────────────────────────────
    if ($config->checkVulns) {
        wpc_out("[4/5] Checking CVEs for WordPress core $wpVersion…", 'step');
        $cveFindings = wpc_check_vulns_core($wpVersion);
        wpc_out(count($cveFindings) . " CVE(s) found for core.", count($cveFindings) > 0 ? 'warn' : 'ok');
        $report->findings = array_merge($report->findings, $cveFindings);
        echo PHP_EOL;
    } else {
        wpc_verbose("[4/5] CVE check skipped (use --check-vulns to enable)");
    }

    // ── 5. DB scan (optional) ───────────────────────────────────────────────
    if ($config->dbScan) {
        wpc_out("[5/5] Database scan…", 'step');
        $dbCfg = wpc_detect_db_config($config->wpRoot);
        if (empty($dbCfg) || !isset($dbCfg['db_name'])) {
            wpc_out("Cannot read DB credentials from wp-config.php.", 'warn');
        } else {
            $dbResult         = wpc_scan_db($dbCfg);
            $report->findings = array_merge($report->findings, $dbResult['findings']);
            $report->sqlFixes = $dbResult['sql'];
            wpc_out(count($dbResult['findings']) . " DB finding(s).", count($dbResult['findings']) > 0 ? 'warn' : 'ok');
        }
        echo PHP_EOL;
    } else {
        wpc_verbose("[5/5] DB scan skipped (use --db to enable)");
    }

    // ── Fix mode ────────────────────────────────────────────────────────────
    if ($config->fixMode && !empty($report->findings)) {
        echo PHP_EOL;
        wpc_out("FIX MODE — restoring core files and removing extra files…", 'step');
        @mkdir($config->backupDir, 0755, true);
        $fixResult      = wpc_do_fix($report->findings, $config->wpRoot, $zipPath, $config->backupDir);
        $report->fixed  = $fixResult['fixed'];
        $report->errors = $fixResult['errors'];

        // Mark each finding as fixed
        $fixedSet = array_flip($report->fixed);
        foreach ($report->findings as $f) {
            if (isset($fixedSet[$f->path]) || isset($fixedSet[$f->path . ' (removed)'])) {
                $f->fixed = true;
            }
        }
    }

    // ── Reports ─────────────────────────────────────────────────────────────
    echo PHP_EOL;
    $textReport = wpc_render_text($report);
    echo $textReport;

    if ($config->genHtml) {
        $htmlFile = $config->wpRoot . DIRECTORY_SEPARATOR
            . 'wp-cleaner-report-' . date('Y-m-d_H-i-s') . '.html';
        if (file_put_contents($htmlFile, wpc_render_html($report)) !== false) {
            wpc_out("HTML report saved: $htmlFile", 'ok');
        } else {
            wpc_out("Cannot write HTML report: $htmlFile (check permissions)", 'warn');
        }
    }

    if ($wpc_log_handle !== null) {
        fclose($wpc_log_handle);
    }

    return $report->hasFindings() ? WPC_EXIT_FINDINGS : WPC_EXIT_OK;
}

// Guard: only execute when run directly (not when included for unit testing)
if (realpath(__FILE__) === realpath((string) ($_SERVER['SCRIPT_FILENAME'] ?? ''))) {
    exit(main($argv));
}
