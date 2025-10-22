# 🔍 Laravel Octane Analyzer - Quick Check Reference

## 📋 All 22 Scanner Checks

### 🎯 Core Octane Issues (8 Scanners)

#### 1. Singleton Binding Scanner
- ✅ `app()->singleton()` with Auth/Request/Session
- ✅ Singleton storing user/tenant data
- ✅ Singleton storing request-scoped models

#### 2. Static Property Scanner
- ✅ Static properties with User models
- ✅ Static arrays holding request data
- ✅ Static cache properties
- ✅ Static tenant information

#### 3. Facade Usage Scanner
- ✅ `Auth::user()` in constructors
- ✅ `request()` helper in constructors
- ✅ `session()` helper in constructors
- ✅ Request/Session facade in boot methods

#### 4. Runtime Config Modification Scanner
- ✅ `Config::set()` at runtime
- ✅ `config([...])` helper
- ✅ `putenv()` calls
- ✅ `$_ENV[]` assignments

#### 5. Database Connection Scanner
- ✅ `DB::connection()` switching in requests
- ✅ Database queries inside loops (N+1)
- ✅ Connection leaks
- ✅ Heavy queries without pagination

#### 6. Unsafe Package Scanner
- ✅ Octane-incompatible packages in composer.lock
- ✅ Packages with known state issues
- ✅ Packages requiring worker restarts

#### 7. Memory Leak Scanner
- ✅ Growing static arrays without cleanup
- ✅ Infinite loops or recursive calls
- ✅ Event listeners without detachment
- ✅ File handles not closed
- ✅ Resources not released

#### 8. Cache Misuse Scanner
- ✅ Generic cache keys ("data", "items", "list")
- ✅ Caching request data
- ✅ `Cache::rememberForever()` without context
- ✅ Cache operations in loops
- ✅ No cache invalidation logic

---

### 🧩 Component-Specific Scanners (4 Scanners)

#### 9. Service Provider State Scanner ⭐ NEW
- ✅ `app()->instance()` usage (singleton registration)
- ✅ `$this->prop = Auth::user()` in boot/register
- ✅ Config/tenant storage in provider properties
- ✅ Request data access in boot/register

#### 10. Middleware State Scanner ⭐ NEW
- ✅ Static properties in middleware
- ✅ Storing `$request->user()` in properties
- ✅ Caching request data in middleware
- ✅ Instance properties holding auth state

#### 11. Model Boot Scanner ⭐ NEW
- ✅ `Auth::user()` in `Model::booted()`
- ✅ `request()` in boot methods
- ✅ `session()` in boot methods
- ✅ Static property assignments in boot
- ✅ `Cache::rememberForever()` in boot

#### 12. Job State Scanner (Enhanced)
- ✅ Static properties in job classes
- ✅ ⭐ `Auth::user()` in job constructor (NEW)
- ✅ ⭐ `request()` in job constructor (NEW)
- ✅ State storage in handle() method
- ✅ Long-running jobs not queued
- ✅ Missing `ShouldBeUnique` interface

---

### 🎨 Livewire & Blade (3 Scanners)

#### 13. Livewire Octane Compatibility Scanner
- ✅ Heavy queries in `render()` method
- ✅ Static properties in Livewire components
- ✅ Storing models in public properties
- ✅ Query Builder usage in render without pagination

#### 14. Livewire Lifecycle Scanner ⭐ NEW
- ✅ Heavy database queries in `mount()`
- ✅ Caching in `mount()`
- ✅ Property assignment in `hydrate()`
- ✅ Auth access in `hydrate()`
- ✅ Non-serializable data in `dehydrate()`
- ✅ Static properties in components

#### 15. Blade State Scanner (Enhanced)
- ✅ Static variables in `@php` blocks
- ✅ `$GLOBALS` usage in templates
- ✅ ⭐ `@inject` directive usage (NEW)
- ✅ ⭐ Heavy queries in `@php` blocks (NEW)
- ✅ ⭐ Database queries in templates (NEW)
- ✅ ⭐ `@auth/@guest` with guards (NEW)

---

### 🎪 Event & Rate Limiting (2 Scanners)

#### 16. Dynamic Event Listener Scanner ⭐ NEW
- ✅ `Event::listen()` in controllers/middleware/routes
- ✅ `$events->listen()` dynamic registration
- ✅ `app('events')->listen()` via container
- ✅ `Queue::before()`, `Queue::after()` outside providers
- ✅ Listeners that stack on every request

#### 17. Rate Limiter Scanner ⭐ NEW
- ✅ `RateLimiter::for()` using static properties
- ✅ `tenant()` access without request context
- ✅ Hardcoded rate limit keys
- ✅ `Auth::id()` instead of `$request->user()->id`
- ✅ `throttle` middleware without user context

---

### ⚡ Performance & Best Practices (5 Scanners)

#### 18. Global PHP Function Scanner ⭐ NEW
- ✅ `date_default_timezone_set()` - changes timezone globally
- ✅ `ini_set()` - changes PHP config globally
- ✅ `putenv()` - modifies environment variables
- ✅ `setlocale()` - changes locale globally
- ✅ `error_reporting()` - changes error level
- ✅ `set_time_limit()` - doesn't work in Octane
- ✅ `chdir()` - changes working directory
- ✅ `define()` - runtime constant declaration
- ✅ `register_shutdown_function()` - functions stack

#### 19. Container Resolution in Loop Scanner ⭐ NEW
- ✅ `app('Service')` in loops
- ✅ `resolve('Service')` in loops
- ✅ `$container->make()` or `->get()` in loops
- ✅ `new Model()` in loops
- ✅ `config()` in loops

#### 20. Serialization Scanner ⭐ NEW
- ✅ `serialize($model)` - PDO connection issues
- ✅ `json_encode($model->get())` direct encoding
- ✅ `Cache::put('key', function() {})` - caching closures
- ✅ Storing objects in session
- ✅ `__sleep()` and `__wakeup()` magic methods
- ✅ `var_export()` on objects
- ✅ `unserialize()` security risks

#### 21. Performance Killer Scanner ⭐ NEW
- ✅ `sleep()` or `usleep()` - blocks worker
- ✅ `Model::all()` without limits
- ✅ `->get()` in loops (N+1)
- ✅ `DB::select('SELECT *')` without LIMIT
- ✅ `->get()->count()` instead of `->count()`
- ✅ `->save()` in loops - use bulk operations
- ✅ `file_get_contents()` on large files
- ✅ `response()->download()` without streaming
- ✅ `implode()` on large query results

#### 22. Bootstrap & Helper Scanner ⭐ NEW
- ✅ Static variables in helper functions
- ✅ `$GLOBALS` usage in bootstrap/helpers
- ✅ Auth facade in helpers (ensure request-scoped)
- ✅ `Cache::rememberForever()` in helpers
- ✅ Conditional middleware registration
- ✅ Dynamic service provider registration
- ✅ Request-dependent route registration

---

## 🎯 Severity Levels

### 🔴 CRITICAL
Issues that **WILL** cause data leaks or security vulnerabilities:
- Static properties with user/request data
- `Auth::user()` in constructors
- `Event::listen()` outside providers
- `date_default_timezone_set()`, `putenv()`
- `sleep()` blocking workers
- Service provider storing request state

### 🟠 HIGH
Issues that **LIKELY** cause problems in production:
- `Model::all()` without limits
- Runtime config modifications
- Database queries in loops
- Heavy queries in Livewire `mount()`
- Middleware storing request data

### 🟡 MEDIUM
Issues that **MAY** cause problems under load:
- Generic cache keys
- Caching in loops
- `file_get_contents()` usage
- Job properties not serializable

### 🟢 LOW
Issues that are **BEST PRACTICES** violations:
- `Cache::rememberForever()` without invalidation
- `set_time_limit()` usage
- Public properties in jobs

---

## 📊 Quick Stats

- **Total Scanners**: 22
- **New Scanners**: 11 ⭐
- **Enhanced Scanners**: 2
- **Total Checks**: 100+
- **Files Scanned**: 2,177
- **Scan Time**: 0.7 seconds

---

## 🚀 Command Cheat Sheet

```bash
# Basic scan
php artisan af-octane:test

# JSON output
php artisan af-octane:test --json

# CI mode (fail on critical)
php artisan af-octane:test --ci

# Scan specific path
php artisan af-octane:test --path=app/Livewire
```

---

## 🎓 Top 10 Most Common Issues

1. 🔴 `Model::all()` without pagination (43 found)
2. 🟠 Heavy queries in Livewire `mount()` (22 found)
3. 🟠 Database queries in loops (14 found)
4. 🟠 Static properties with request data (8 found)
5. 🔴 Database queries in Blade @php (7 found)
6. 🟡 Heavy queries in Livewire `render()` (6 found)
7. 🟡 Generic cache keys (8 found)
8. 🔴 Runtime config modifications (5 found)
9. 🔴 Facade usage in constructors (3 found)
10. 🟡 `file_get_contents()` usage (2 found)

---

## ✅ Checklist: Is My App Octane-Ready?

- [ ] No static properties with user/request data
- [ ] No `Auth::user()` in constructors or boot methods
- [ ] No `Event::listen()` outside service providers
- [ ] No `Config::set()` or `putenv()` at runtime
- [ ] No `Model::all()` without pagination
- [ ] No database queries in loops
- [ ] No `sleep()` or blocking operations
- [ ] All cache keys include user/tenant context
- [ ] No heavy queries in Livewire `mount()`
- [ ] No database queries in Blade templates
- [ ] Middleware doesn't store request state
- [ ] Jobs don't access `Auth::user()` in constructor
- [ ] No global PHP functions that change state

---

**💡 Tip**: Run `php artisan af-octane:test --ci` in your CI/CD pipeline to catch issues before deployment!
