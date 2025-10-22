# Laravel Octane Safety Analyzer

## Overview

The `af-octane:test` command is a comprehensive Laravel Octane compatibility scanner that detects code patterns that may cause issues when running your application with Laravel Octane. It scans your entire codebase for singleton misuse, static state, memory leaks, and other Octane-incompatible patterns.

## Command Signature

```bash
php artisan af-octane:test [options]
```

## Options

| Option | Description |
|--------|-------------|
| `--json` | Output results in JSON format (useful for CI/CD pipelines) |
| `--ci` | CI mode - exits with error code if critical issues are found |
| `--fix` | Apply automatic fixes where possible (not yet implemented) |
| `--path=` | Specific path to scan (default: app/) |

## What It Detects

The analyzer includes 11 specialized scanners that check for:

### 1. Singleton Binding Issues
- **What:** Detects `app()->singleton()`, `App::singleton()`, and `bind(..., shared: true)` calls
- **Checks for:**
  - Use of `request()`, `Auth::user()`, `session()` in singletons
  - Facades inside singleton constructors
  - Models or config changes inside singletons
- **Why:** Singletons persist across requests in Octane, causing data leaks between users

### 2. Static Properties
- **What:** Scans all PHP files for static properties
- **Checks for:**
  - Static properties holding User models, request data, tenant info
  - Static arrays or collections
  - Static properties with Model type hints
- **Why:** Static properties persist across all requests, leaking data between users

### 3. Facade Misuse
- **What:** Detects facades used in constructors and boot() methods
- **Checks for:**
  - `Auth::user()`, `auth()->user()` in constructors
  - `request()`, `Request::` in constructors
  - `session()`, `Session::` in constructors
  - `Cookie::` facade in boot methods
- **Why:** Constructors run once at boot, caching request-scoped data for all users

### 4. Runtime Config Modification
- **What:** Detects config or environment modifications at runtime
- **Checks for:**
  - `config([...])` setting config arrays
  - `Config::set()`
  - `putenv()`
  - `$_ENV[]` or `$_SERVER[]` assignments
- **Why:** Config changes persist across requests, affecting all users

### 5. Database Connection Leaks
- **What:** Scans for improper database connection handling
- **Checks for:**
  - `DB::connection()` without `disconnect()`
  - Database queries inside loops (N+1 potential)
  - Long-running queries without proper cleanup
- **Why:** Connections can leak and cause memory/performance issues

### 6. Unsafe Packages
- **What:** Checks composer.lock for packages with known Octane issues
- **Currently detects:**
  - `barryvdh/laravel-debugbar` (high risk - static state)
  - `barryvdh/laravel-ide-helper` (low risk - dev only)
  - `spatie/laravel-ignition` (medium risk - debug mode)
  - `rap2hpoutre/laravel-log-viewer` (medium risk - memory issues)
- **Why:** Some packages use static state incompatible with Octane

### 7. Livewire Octane Issues
- **What:** Scans Livewire components for Octane problems
- **Checks for:**
  - Heavy queries in `render()` without pagination
  - Static properties in components
  - Storing entire models instead of IDs
  - Using deprecated `emit()` instead of `dispatch()`
- **Why:** Livewire components can leak state and cause memory issues

### 8. Blade State Issues
- **What:** Scans Blade templates for stateful problems
- **Checks for:**
  - Static variables in `@php` blocks
  - Use of `$GLOBALS[]`
  - View composers using singletons
- **Why:** Blade state can persist across requests

### 9. Job State Problems
- **What:** Scans queued jobs for state management issues
- **Checks for:**
  - Static properties in job classes
  - State storage in `handle()` method
  - Long-running jobs not implementing `ShouldQueue`
  - Missing `ShouldBeUnique` interface
- **Why:** Jobs can leak memory and state in Octane workers

### 10. Memory Leaks
- **What:** Detects patterns that cause memory leaks
- **Checks for:**
  - Growing static arrays (arrays that are appended to)
  - Static caches without clearing mechanisms
  - Accumulating instance properties in singletons
  - File operations without cleanup
  - Infinite loops (`while(true)`)
- **Why:** Memory leaks cause Octane workers to crash

### 11. Cache Misuse
- **What:** Scans for caching anti-patterns
- **Checks for:**
  - Cache keys without tenant/user context
  - `Cache::rememberForever()` without invalidation
  - Caching request data
  - Generic cache keys (collisions)
  - Cache operations inside loops
- **Why:** Improper caching causes data leaks in multi-tenant apps

## Output Format

### Standard Output

```
╔══════════════════════════════════════════════════════════════╗
║           🚀 Laravel Octane Safety Analyzer 🚀               ║
╚══════════════════════════════════════════════════════════════╝

📊 SCAN SUMMARY
⏱️  Execution Time: 0.99s
📁 Files Scanned: 312
✅ Passed Checks: 2
⚠️  Warnings: 3
❌ Critical Issues: 0

🔍 Singleton Binding Scanner
────────────────────────────────────────────────────────────
⚠️ [MEDIUM] Singleton Binding Detected
   📄 File: app/Providers/AppServiceProvider.php
   📍 Line: 42
   💬 Singleton binding found. Verify this service doesn't store request-specific state
   💡 Fix: Review the singleton implementation. If it stores per-request data, convert to scoped binding
```

### JSON Output (`--json`)

```json
{
  "summary": {
    "execution_time": 0.99,
    "files_scanned": 312,
    "passed_checks": 2,
    "warnings": 3,
    "critical_issues": 0
  },
  "results": {
    "singleton": {
      "name": "Singleton Binding Scanner",
      "description": "Detects singleton bindings that may cause issues with Laravel Octane",
      "scan_time": 0.0034,
      "vulnerabilities": [
        {
          "title": "Singleton Binding Detected",
          "severity": "medium",
          "description": "Singleton binding found...",
          "file": "app/Providers/AppServiceProvider.php",
          "line": 42,
          "code": "$this->app->singleton(MyService::class);",
          "recommendation": "Review the singleton implementation...",
          "metadata": {
            "binding_type": "->singleton()"
          }
        }
      ]
    }
  }
}
```

## Severity Levels

| Level | Icon | Description |
|-------|------|-------------|
| **CRITICAL** | ❌ | Must fix before Octane deployment |
| **HIGH** | 🔴 | Should fix - likely to cause issues |
| **MEDIUM** | ⚠️ | Review and fix if applicable |
| **LOW** | ⚡ | Best practice suggestions |

## CI/CD Integration

### Exit Codes

- `0`: Success (no critical issues)
- `1`: Failure (critical issues found in `--ci` mode)

### GitHub Actions Example

```yaml
name: Octane Safety Check

on: [push, pull_request]

jobs:
  octane-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      
      - name: Install Dependencies
        run: composer install
      
      - name: Run Octane Safety Analyzer
        run: php artisan af-octane:test --ci --json > octane-report.json
      
      - name: Upload Report
        uses: actions/upload-artifact@v2
        if: always()
        with:
          name: octane-safety-report
          path: octane-report.json
```

## Usage Examples

### Basic Scan
```bash
php artisan af-octane:test
```

### Scan Specific Path
```bash
php artisan af-octane:test --path=app/Services
```

### Generate JSON Report
```bash
php artisan af-octane:test --json > octane-report.json
```

### CI Mode (Fail Build on Critical Issues)
```bash
php artisan af-octane:test --ci
```

## Common Issues & Fixes

### Issue: Singleton with Request Data

**Problem:**
```php
// AppServiceProvider.php
$this->app->singleton(UserService::class, function ($app) {
    return new UserService(auth()->user()); // ❌ Wrong!
});
```

**Fix:**
```php
// AppServiceProvider.php
$this->app->scoped(UserService::class, function ($app) {
    return new UserService(auth()->user()); // ✅ Correct!
});
```

### Issue: Static Properties

**Problem:**
```php
class ReportGenerator
{
    private static $currentUser; // ❌ Wrong!
    
    public function generate()
    {
        self::$currentUser = auth()->user();
    }
}
```

**Fix:**
```php
class ReportGenerator
{
    private $currentUser; // ✅ Correct!
    
    public function generate()
    {
        $this->currentUser = auth()->user();
    }
}
```

### Issue: Facade in Constructor

**Problem:**
```php
class MyService
{
    private $user;
    
    public function __construct()
    {
        $this->user = Auth::user(); // ❌ Wrong!
    }
}
```

**Fix:**
```php
class MyService
{
    public function doSomething()
    {
        $user = Auth::user(); // ✅ Correct!
        // Use $user here
    }
}
```

### Issue: Cache Without Context

**Problem:**
```php
Cache::rememberForever('users', function () {
    return User::all(); // ❌ Wrong - shared across tenants!
});
```

**Fix:**
```php
Cache::rememberForever('tenant:' . tenant('id') . ':users', function () {
    return User::all(); // ✅ Correct - tenant-specific!
});
```

## Recommendations

After running the analyzer, consider these best practices:

1. **Test with Octane** - Run `php artisan octane:start` and test your app
2. **Monitor Memory** - Use `php artisan octane:status` to check worker health
3. **Use Scoped Bindings** - Prefer `scoped()` over `singleton()` for request-specific data
4. **Clear Static State** - Implement clearing in Octane tick events:
   ```php
   Octane::tick('clear-state', function () {
       MyService::clearCache();
   });
   ```
5. **Tenant-Aware Cache** - Always include tenant context in cache keys
6. **Test Under Load** - Use tools like Apache Bench to detect state leaks
7. **Review Documentation** - Read [Laravel Octane docs](https://laravel.com/docs/octane)

## Performance

- **Fast:** Scans ~300 files in under 1 second
- **Lightweight:** No external dependencies required
- **Read-only:** Never modifies your code (unless `--fix` is used)
- **Safe:** Can be run in production environments

## Limitations

- Does not detect all possible Octane issues (manual review still recommended)
- Cannot analyze package code (only application code)
- `--fix` flag not yet implemented (planned for future release)
- May have false positives for complex codebases

## Future Enhancements

- [ ] Implement `--fix` flag for automatic refactoring
- [ ] Add support for custom scanner rules
- [ ] Detect memory usage by running test requests
- [ ] Support for scanning package code
- [ ] Integration with Laravel Telescope
- [ ] Historical trend analysis
- [ ] Automatic PR comments with scan results

## Support

For issues or questions:
- Check the [Laravel Octane documentation](https://laravel.com/docs/octane)
- Review the [Octane GitHub repository](https://github.com/laravel/octane)
- Contact your development team

## License

This analyzer is part of the `artflow-studio/laravel-security` package.
