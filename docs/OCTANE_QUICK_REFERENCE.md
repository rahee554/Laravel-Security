# Octane Analyzer - Quick Reference

## Command

```bash
php artisan af-octane:test [--json] [--ci] [--path=app/]
```

## 11 Scanners

| # | Scanner | What It Checks |
|---|---------|----------------|
| 1 | **Singleton Binding** | `singleton()` with request/auth/session data |
| 2 | **Static Properties** | Static vars holding models, users, requests |
| 3 | **Facade Misuse** | Auth/Request/Session in constructors |
| 4 | **Runtime Config** | `config([])`, `Config::set()`, `putenv()` |
| 5 | **DB Connections** | `DB::connection()` without disconnect, queries in loops |
| 6 | **Unsafe Packages** | debugbar, ignition, log-viewer issues |
| 7 | **Livewire** | Heavy queries in render(), static props, storing models |
| 8 | **Blade State** | Static vars in @php, $GLOBALS usage |
| 9 | **Job State** | Static props in jobs, state in handle() |
| 10 | **Memory Leaks** | Growing static arrays, infinite loops, no cleanup |
| 11 | **Cache Misuse** | Keys without context, rememberForever, caching requests |

## Severity Levels

- ❌ **CRITICAL** - Must fix before Octane
- 🔴 **HIGH** - Should fix - likely problems
- ⚠️ **MEDIUM** - Review and fix if applicable  
- ⚡ **LOW** - Best practice suggestions

## Common Fixes

### ❌ Singleton with Request Data
```php
// WRONG
$this->app->singleton(Service::class, fn() => new Service(auth()->user()));

// CORRECT
$this->app->scoped(Service::class, fn() => new Service(auth()->user()));
```

### ❌ Static Property with User Data
```php
// WRONG
class Service {
    private static $user;
}

// CORRECT
class Service {
    private $user;
}
```

### ❌ Facade in Constructor
```php
// WRONG
public function __construct() {
    $this->user = Auth::user();
}

// CORRECT
public function doAction() {
    $user = Auth::user();
}
```

### ❌ Cache Without Tenant Context
```php
// WRONG
Cache::remember('data', 60, fn() => User::all());

// CORRECT
Cache::remember('tenant:'.tenant('id').':data', 60, fn() => User::all());
```

### ❌ Runtime Config Change
```php
// WRONG
config(['app.name' => 'New Name']);

// CORRECT - Use .env or database instead
Setting::set('app_name', 'New Name');
```

## CI/CD Integration

```yaml
- name: Octane Safety Check
  run: php artisan af-octane:test --ci --json > report.json
```

Exit code `1` if critical issues found.

## JSON Output Structure

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
    "scanner_name": {
      "vulnerabilities": [...]
    }
  }
}
```

## Best Practices

1. ✅ Use `scoped()` instead of `singleton()` for request data
2. ✅ Never store request/user/session in static properties
3. ✅ Call Auth/Request facades only in methods, not constructors
4. ✅ Include tenant/user context in all cache keys
5. ✅ Clear static state in Octane tick events
6. ✅ Use instance properties, not static properties
7. ✅ Implement `ShouldQueue` for long-running jobs
8. ✅ Test under load to detect state leaks

## Monitor Octane Health

```bash
php artisan octane:status        # Check worker health
php artisan octane:cache:warm    # Warm cache before deploy
```

## Resources

- [Laravel Octane Docs](https://laravel.com/docs/octane)
- [Octane GitHub](https://github.com/laravel/octane)
- Full documentation: `OCTANE_ANALYZER_DOCUMENTATION.md`
