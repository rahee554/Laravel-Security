# 🛡️ Laravel Security - Console Protection Module

**Package**: `artflow-studio/laravel-security`  
**Version**: 2.0.0  
**Purpose**: Comprehensive runtime protection combining vulnerability scanning with active console/DevTools detection, token-based request verification, and automatic data tampering prevention.

---

## 🎯 Enhanced Goals & Threat Model

### Primary Goals

* ✅ **Prevent view-source exposure** of sensitive Livewire/Blade markup before handshake
* ✅ **Detect and block DevTools** (docked/undocked) in real-time
* ✅ **Automatic token renewal** - Zero 419 CSRF errors, seamless user experience
* ✅ **Console tampering detection** - Prevent data manipulation via browser console
* ✅ **Livewire request protection** - Validate every component update
* ✅ **Short-lived rotating tokens** - Minimize replay attack window
* ✅ **CSP header integration** - Content Security Policy enforcement
* ✅ **AI-powered detection** (optional) - Identify suspicious automation patterns

### Security Layers

1. **Pre-Handshake Layer**: Minimal loader HTML (no sensitive data)
2. **Token Layer**: Encrypted session-bound tokens with auto-rotation
3. **Detection Layer**: Multi-method DevTools and tampering detection
4. **Protection Layer**: Automatic blocking and graceful recovery
5. **Intelligence Layer**: Pattern analysis and threat scoring

---

## 📋 Table of Contents

1. [Enhanced Architecture](#enhanced-architecture)
2. [Package Structure](#package-structure)
3. [Configuration](#configuration)
4. [Middleware: ConsoleStrictMiddleware](#middleware-consolestrictmiddleware)
5. [Handshake Controller](#handshake-controller)
6. [Token Management](#token-management)
7. [Views & UI Components](#views--ui-components)
8. [JavaScript Shield](#javascript-shield)
9. [Blade Directive: @afConsoleSecurity](#blade-directive-afconsolesecurity)
10. [Livewire Integration](#livewire-integration)
11. [CSP Headers](#csp-headers)
12. [AI Detection (Optional)](#ai-detection-optional)
13. [Security Hardening](#security-hardening)
14. [Testing Strategy](#testing-strategy)
15. [Installation & Usage](#installation--usage)
16. [Troubleshooting](#troubleshooting)
17. [Roadmap](#roadmap)

---

## 1. Goals & Threat Model

**Primary Goals**

* Ensure initial HTML containing sensitive markup/data is not served until browser executes handshake JS.
* Detect DevTools (attached/detached) and prevent the app from rendering while DevTools are open.
* Provide a signed/encrypted handshake token (cookie) that middleware validates on each request.
* Make spoofing the handshake significantly harder by optionally binding token to server session.
* Provide configuration and safe defaults to avoid locking out legitimate users.

**Threats addressed**

* Casual users copying Livewire markup or initial page data via `view-source:`.
* Basic scrapers and bots fetching raw HTML without executing JS.
* Users attempting to open DevTools to tamper with initial page state before handshake.

**Threats NOT fully addressed**

* Advanced adversaries who can manually set cookies, run custom browsers, or replicate session tokens.
* Network-level attackers without HTTPS/TLS protections.

---

## 2. High-level Architecture

1. **Middleware** — gates requests: if handshake cookie absent/invalid, return `loader` view.
2. **Loader view** — minimal HTML + JS that runs DevTools detection and requests a handshake from server.
3. **Handshake endpoint** — server verifies and sets an encrypted/signed cookie (optionally stores server token in session).
4. **Blocked view** — user-friendly page shown when DevTools detected. Contains auto-return logic.
5. **Client detector** — JS module used by loader, blocked page, and optionally the main app to watch for DevTools.
6. **Config** — publishable config file to tune thresholds, cookie names, excluded paths, and whitelists.

---

## 3. Package Structure

```
laravel-secure-handshake/
├─ src/
│  ├─ HandshakeServiceProvider.php
│  ├─ Http/
│  │  ├─ Middleware/EnsureHandshake.php
│  │  └─ Controllers/HandshakeController.php
│  └─ config/handshake.php
├─ resources/
│  └─ views/
│     ├─ loader.blade.php
│     └─ blocked.blade.php
├─ routes/web.php
├─ composer.json
└─ README.md
```

---

## 4. Config (`config/handshake.php`)

```php
<?php
return [
    'enabled' => env('HANDSHAKE_ENABLED', true),
    'cookie_name' => env('HANDSHAKE_COOKIE', 'secure_handshake'),
    'cookie_minutes' => env('HANDSHAKE_MINUTES', 30),
    'signed' => true, // encrypt cookie value
    'token_bound_to_session' => true,
    'excluded_paths' => [
        'blocked', 'loader', '_handshake/*', 'assets/*', 'api/*'
    ],
    'detection' => [
        'size_threshold_px' => 160,
        'loop_iterations' => 100000,
        'loop_time_threshold_ms' => 120
    ],
    'admin_whitelist_ips' => explode(',', env('HANDSHAKE_ADMIN_IPS', '')),
];
```

---

## 5. Middleware: `EnsureHandshake`

**Responsibilities**

* Skip enforcement for configured excluded paths and whitelisted IPs.
* If cookie exists and validation (decrypt + optional session bound token) passes, allow request.
* Otherwise, return the `loader` view (no app markup).

**Behavior notes**

* Use `Cache-Control: no-store, no-cache` headers on loader responses to avoid caching.
* Do minimal work (decrypt and simple comparison) to keep per-request cost negligible.

**Key snippet (logic only, not full file)**

```php
$cookie = $request->cookie(config('handshake.cookie_name'));
if ($cookie) {
    try {
        $value = config('handshake.signed') ? decrypt($cookie) : $cookie;
        if (config('handshake.token_bound_to_session')) {
            $sessionToken = $request->session()->get('_handshake_token');
            if ($sessionToken && hash_equals($sessionToken, $value)) {
                return $next($request);
            }
        } else {
            if ($value === 'ok') return $next($request);
        }
    } catch (\Exception $e) {
        // invalid cookie -> fall through to loader
    }
}
return response()->view('handshake::loader')->header('Cache-Control','no-store, no-cache, must-revalidate');
```

---

## 6. Handshake Controller & Route

**Route (package)**

```php
Route::post('/_handshake/verify', [HandshakeController::class, 'verify'])->name('handshake.verify');
```

**Controller responsibilities**

* If `token_bound_to_session` is enabled, create a random server token (UUID), store in session under `_handshake_token`, and return a cookie that contains the token (encrypted if `signed`).
* If not session-bound, return a simple encrypted `ok` value in cookie.
* Return JSON `{ ok: true }` so loader JS knows it succeeded.

**Key snippet (logic only)**

```php
if (config('handshake.token_bound_to_session')) {
    $token = (string) Str::uuid();
    $request->session()->put('_handshake_token', $token);
    $cookieVal = config('handshake.signed') ? encrypt($token) : $token;
} else {
    $cookieVal = config('handshake.signed') ? encrypt('ok') : 'ok';
}
return response()->json(['ok'=>true])
    ->cookie(config('handshake.cookie_name'), $cookieVal, config('handshake.cookie_minutes'));
```

---

## 7. Views: `loader.blade.php` & `blocked.blade.php`

### `loader.blade.php` (minimal)

* Minimal head and body.
* Small inline JS (or import of a tiny JS module) that runs detection, performs `fetch` to `/ _handshake/verify` with `credentials: 'same-origin'` and `X-CSRF-TOKEN` header, waits for success, then reloads.
* If detection fails, `location.replace('/blocked')`.

**Important**: Keep this view tiny so `view-source:` only reveals a loader.

### `blocked.blade.php`

* Friendly message: "Access restricted — developer tools detected.".
* Script that polls `devToolsStillOpen()` and redirects back to previous URL saved in `sessionStorage` once DevTools closes.

---

## 8. Client JS: DevTools Detector & Handshake Flow

**Combined detection heuristics (no `debugger`)**

1. **Size check**: `outerWidth - innerWidth` or `outerHeight - innerHeight` > threshold.
2. **Console object-inspection trick**: `console.log('%c', { toString(){ opened=true; return '' } })` — when console open, `toString` called.
3. **Synchronous loop timing**: measure a tight loop execution time; slower when console open.

**Loader flow**

1. Small delay (e.g., `setTimeout(init, 50)`) to allow metrics to stabilize.
2. Run `detectDevTools()`; if true → redirect to `/blocked`.
3. If false → `fetch('/_handshake/verify', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-TOKEN': document.querySelector('meta[name="csrf-token"]').content } })`.
4. On success (`{ok:true}`) → `location.reload()`.
5. On failure → redirect `/blocked`.

**Blocked page flow**

* Poll `detectDevTools()` every 700 ms; when it becomes false, read `prev_url` from `sessionStorage` and `location.replace(prev_url || '/')`.

**Edge cases**

* Slow devices may trigger loop timing checks: make thresholds configurable and conservative.
* Mobile browsers have different outer/inner behavior; tune `size_threshold_px` per UA or exclude mobile.

---

## 9. Cookie / Token Strategy (simple vs. strong)

**Simple (easy, weaker)**

* JS sets `secure_handshake=ok` via `document.cookie`; middleware checks equality.
* Upside: very simple to implement.
* Downside: cookie can be manually set by attacker.

**Strong (recommended)**

* `/ _handshake/verify` creates a session token and stores it in session (`_handshake_token`).
* Server returns encrypted cookie containing the token. Middleware decrypts, compares to session value.
* Upside: token must be associated with session; manual cookie forgery is not enough.
* Downside: requires sessions and server-side storage; ensure session driver configured properly in load-balanced setups.

**Encryption / signing**

* Use `encrypt()` / `decrypt()` or signed routes (URL::temporarySignedRoute) built into Laravel. Do not roll your own crypto.

---

## 10. Livewire Integration Notes

* Ensure the loader is returned **before** Livewire assets are executed. Middleware should gate the HTML response so Livewire scripts are not loaded until handshake passes.
* Livewire AJAX calls will include the handshake cookie; middleware will validate it the same as full page requests.
* Avoid embedding sensitive initial payloads or Blade templates into public JS files. Server should only render sensitive data after handshake verification.

---

## 11. Security Hardening

* **Use HTTPS** and enable HSTS.
* Set `secure` and `HttpOnly` flags for cookies where appropriate. (HttpOnly prevents JS reading, but the handshake logic often needs JS to set cookie — so use encrypted cookie set by server when possible.)
* Set `SameSite=Lax` or `Strict` for handshake cookie.
* Limit handshake cookie lifetime to a short window (e.g., 15–60 minutes).
* Rate limit `/ _handshake/verify` endpoint.
* Verify `X-Requested-With` and CSRF token in handshake POSTs.
* Log blocked events (IP, UA, path) for tuning thresholds.
* Use `Content-Security-Policy` to curb script injection.

---

## 12. UX & False Positive Handling

* Use conservative defaults to avoid blocking legitimate slow devices.
* Provide admin whitelist (IP or user agent) to prevent lockout.
* Optionally provide a "Continue anyway" manual override backed by multi-factor check for support scenarios (use sparingly — weakens protection).
* Show a friendly explanation on `/blocked` with steps to resolve if user thinks they were blocked incorrectly.

---

## 13. Logging, Monitoring & Analytics

* Track handshake successes, failures, and blocked counts.
* Include UA, IP, path, timestamp.
* Use logs to tune thresholds and decide if admin whitelist changes needed.

---

## 14. Tests to include

* Unit: cookie decrypt/validate logic, middleware allowed/blocked branches.
* Integration: request protected route without cookie → loader returned; handshake endpoint issues cookie → second request returns app.
* E2E: headless browser simulating loader execution and handshake flow.
* Threshold tests: simulate slow CPU to ensure detection thresholds do not false-positive excessively.

---

## 15. Installer & Usage (README snippet)

1. `composer require vendor/laravel-secure-handshake`
2. `php artisan vendor:publish --provider="Vendor\Handshake\HandshakeServiceProvider" --tag=config`
3. Add middleware to `app/Http/Kernel.php` web group:

```php
\Vendor\Handshake\Http\Middleware\EnsureHandshake::class,
```

4. Publish views if needed. Configure `.env` values: `HANDSHAKE_ENABLED`, `HANDSHAKE_COOKIE`, `HANDSHAKE_MINUTES`.
5. Ensure `meta[name=csrf-token]` is present in your main layout (for loader fetch POST).

---

## 16. Limitations & Ethical Notes

* This package provides obfuscation and deterrence. It is not a security boundary. Always protect sensitive endpoints server-side.
* Overly aggressive blocking may harm accessibility, developer workflows, and legitimate users (e.g., browser extensions that open DevTools-like windows).
* Provide clear admin escape/handover procedures and document expected behavior.

---

## 17. Changelog / Versioning Guidance

* v1.0.0 — Basic handshake, loader, blocked page, session-bound token option.
* v1.1.0 — Admin dashboard for blocked events, threshold auto-tuning.
* v2.0.0 — Optional WebAuthn/device-bound challenges for very sensitive pages.

---

### Final Notes for the AI Agent

* Follow Laravel coding conventions and PSR-4 for package namespace.
* Keep loader HTML minimal and avoid putting anything sensitive in published views before handshake.
* Keep client JS tiny and unobtrusive; allow optionally loading the detection module from a published asset.
* Include a comprehensive README and examples showing how to exclude API routes and tune config.

---

If you want, I can also output the **exact code files** (middleware class, controller, blade views, route definitions, config file) ready to paste into the package. Just tell me which file to output first.
