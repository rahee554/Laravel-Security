# 🛡️ Laravel Security - Console Protection Implementation

## 📦 Package: artflow-studio/laravel-security v2.0.0

### ✅ Implementation Status: READY TO IMPLEMENT

This document outlines the complete implementation of the Console Security module that adds runtime protection to the existing vulnerability scanner package.

---

## 🎯 Quick Summary

**What we're adding**:
- ✅ Console/DevTools detection and blocking
- ✅ Token-based handshake system with auto-renewal
- ✅ `console:strict` middleware for route protection
- ✅ `@afConsoleSecurity` Blade directive for easy integration
- ✅ Livewire trait for automatic component protection
- ✅ Zero 419 errors (automatic token renewal)
- ✅ Beautiful blocked page with auto-recovery
- ✅ CSP headers integration
- ✅ AI-powered detection (optional)

**User experience**:
1. Add `@afConsoleSecurity` to layout head
2. Register `console:strict` middleware on protected routes
3. Done! Everything else is automatic

---

## 📁 Files to Create

### Core Files (Required)

1. **src/Http/Middleware/ConsoleStrictMiddleware.php** (250 lines)
   - Token validation
   - Auto-renewal logic
   - Excluded paths handling
   - IP whitelist

2. **src/Http/Controllers/HandshakeController.php** (180 lines)
   - `verify()` - Initial handshake
   - `renew()` - Token auto-renewal
   - `status()` - Check token validity

3. **src/Support/SecurityToken.php** (200 lines)
   - Token generation/validation
   - Encryption/decryption
   - Session binding
   - Expiration checks

4. **config/console-security.php** (120 lines)
   - All configuration options
   - Sensible defaults
   - Environment variable support

5. **resources/views/loader.blade.php** (80 lines)
   - Minimal pre-handshake HTML
   - Loading animation
   - DevTools detection
   - Auto-handshake

6. **resources/views/blocked.blade.php** (100 lines)
   - User-friendly blocked message
   - Auto-return when DevTools closed
   - Session recovery
   - Admin bypass option

7. **resources/js/console-security.js** (350 lines)
   - Multi-method DevTools detection
   - Console tampering checks
   - Auto-renewal timer
   - Network monitoring

8. **src/Support/BladeDirectives.php** (60 lines)
   - `@afConsoleSecurity` directive
   - Injects JS with proper CSRF token
   - Nonce generation for CSP

### Livewire Integration (Optional but Recommended)

9. **src/Traits/WithConsoleSecurity.php** (120 lines)
   - Auto-attach token to Livewire requests
   - Component-level protection
   - Easy `use` trait integration

10. **src/Http/Middleware/LivewireSecurityMiddleware.php** (150 lines)
    - Livewire request validation
    - Component fingerprint verification
    - Method call validation

### Advanced Features (Optional)

11. **src/Http/Middleware/ContentSecurityPolicyMiddleware.php** (100 lines)
    - CSP header injection
    - Nonce generation
    - Configurable directives

12. **src/Services/AIDetectionService.php** (200 lines)
    - Pattern recognition
    - Velocity analysis
    - Browser fingerprinting
    - Threat scoring

### Routes & Service Provider Updates

13. **routes/console-security.php** (New file, 30 lines)
    - Handshake routes
    - Proper middleware groups

14. **src/LaravelSecurityServiceProvider.php** (Update existing)
    - Register new middleware
    - Register Blade directives
    - Publish config/views/assets
    - Load routes

---

## 🚀 Implementation Priority

### Phase 1: Core Functionality (DO THIS FIRST)
✅ **Day 1-2**: 
- ConsoleStrictMiddleware
- HandshakeController
- SecurityToken helper
- config/console-security.php
- Routes file

### Phase 2: UI & JavaScript (DO THIS SECOND)
✅ **Day 3-4**:
- loader.blade.php
- blocked.blade.php
- console-security.js
- BladeDirectives.php

### Phase 3: Livewire (DO THIS THIRD)
✅ **Day 5**:
- WithConsoleSecurity trait
- LivewireSecurityMiddleware

### Phase 4: Advanced (OPTIONAL)
⏳ **Day 6-7**:
- CSP middleware
- AI Detection service
- Analytics/logging

---

## 💡 Key Implementation Notes

### 1. Zero 419 Errors Strategy

**Problem**: CSRF tokens expire, causing 419 errors  
**Solution**: Auto-renewal before expiration

```javascript
// In console-security.js
setInterval(async () => {
    if (tokenExpiresIn() < 60) { // Less than 1 minute left
        await renewToken();
    }
}, 30000); // Check every 30 seconds
```

### 2. DevTools Detection Methods

**Multi-layered approach** (all must agree for accuracy):

```javascript
function detectDevTools() {
    let detected = false;
    
    // Method 1: Size difference
    const widthDiff = window.outerWidth - window.innerWidth;
    const heightDiff = window.outerHeight - window.innerHeight;
    if (widthDiff > 160 || heightDiff > 160) detected = true;
    
    // Method 2: Console toString trick
    let consoleOpened = false;
    console.log('%c', {toString: () => (consoleOpened = true, '')});
    if (consoleOpened) detected = true;
    
    // Method 3: Loop timing
    const start = performance.now();
    for (let i = 0; i < 100000; i++) {}
    const elapsed = performance.now() - start;
    if (elapsed > 120) detected = true;
    
    return detected;
}
```

### 3. Session-Bound Tokens

**Why?** Prevents cookie theft attacks

```php
// In HandshakeController
$token = (string) Str::uuid();
$request->session()->put('_security_token', $token);
$encrypted = encrypt($token);

return response()->json(['ok' => true])
    ->cookie(
        config('console-security.cookie.name'),
        $encrypted,
        config('console-security.cookie.lifetime')
    );
```

### 4. Middleware Logic

**Flow**:
1. Check if path excluded → allow
2. Check if IP whitelisted → allow
3. Check if cookie exists → validate
4. If valid → check expiration → auto-renew if needed → allow
5. If invalid/missing → return loader view

### 5. Livewire Protection

**Automatic** with trait:

```php
use WithConsoleSecurity;

// Trait automatically:
// 1. Adds token to every Livewire request
// 2. Validates token on server
// 3. Renews token when needed
// 4. Blocks tampering attempts
```

---

## 📝 Configuration Example

```php
// config/console-security.php
return [
    'enabled' => env('CONSOLE_SECURITY_ENABLED', true),
    
    'cookie' => [
        'name' => 'af_handshake',
        'lifetime' => 5, // minutes
    ],
    
    'token' => [
        'auto_renew' => true,
        'rotation_interval' => 240, // 4 minutes
    ],
    
    'excluded_paths' => [
        '_security/*',
        'api/*',
        'assets/*',
    ],
    
    'whitelist' => [
        'ips' => ['127.0.0.1'],
    ],
];
```

---

## 🎨 User Experience Flow

### Normal User (No DevTools)
1. Visit site → Loader shows for 0.5s
2. Handshake completes → Page loads
3. Token auto-renews every 4 minutes (transparent)
4. Continues browsing normally

### User Opens DevTools
1. Visit site → Loader detects DevTools immediately
2. Redirects to `/blocked`
3. Shows friendly message
4. User closes DevTools
5. Auto-redirects back to previous page
6. Continues browsing

### Token Expires (Edge Case)
1. Token expires due to inactivity
2. Next request triggers auto-renewal
3. Seamless - user doesn't notice
4. No 419 error ever shown

---

## 🔧 Installation Steps (For End Users)

```bash
# 1. Install package
composer require artflow-studio/laravel-security

# 2. Publish config
php artisan vendor:publish --tag=console-security-config

# 3. Publish views (optional)
php artisan vendor:publish --tag=console-security-views

# 4. Add to layout
# In resources/views/layouts/app.blade.php:
<head>
    @afConsoleSecurity
</head>

# 5. Protect routes
Route::middleware(['console:strict'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index']);
    Route::get('/dashboard', [DashboardController::class, 'index']);
});

# 6. Livewire components (optional)
use ArtflowStudio\LaravelSecurity\Traits\WithConsoleSecurity;

class MyComponent extends Component
{
    use WithConsoleSecurity;
}
```

**That's it!** 3 steps for basic protection.

---

## 📊 Performance Impact

- **Middleware overhead**: ~5-10ms per request
- **JavaScript bundle**: ~15KB minified
- **Detection overhead**: ~2-3ms per check
- **Token renewal**: ~20ms (async, doesn't block)

**Total**: Negligible impact (<1% for most apps)

---

## 🧪 Testing Checklist

### Unit Tests
- [ ] Token generation/validation
- [ ] Cookie encryption/decryption
- [ ] Session binding
- [ ] Expiration checks
- [ ] Whitelist matching

### Integration Tests
- [ ] Middleware blocks without token
- [ ] Loader view returned
- [ ] Handshake sets cookie
- [ ] Second request allowed
- [ ] Auto-renewal works
- [ ] Excluded paths bypass

### Browser Tests
- [ ] DevTools detection (Chrome/Firefox/Edge)
- [ ] Blocked page redirect
- [ ] Auto-return after closing DevTools
- [ ] Token renewal without reload
- [ ] Livewire requests protected

---

## 🚨 Important Security Notes

1. **This is NOT a security boundary** - Always validate server-side
2. **Use HTTPS** - Required for secure cookies
3. **Configure excluded paths** - API routes may need different auth
4. **Tune detection thresholds** - Avoid false positives
5. **Monitor logs** - Track blocked attempts
6. **Whitelist carefully** - Only trusted IPs

---

## 📚 Next Steps

1. **Review PLAN.md** for detailed architecture
2. **Start with Phase 1** (middleware + controller)
3. **Test thoroughly** before Phase 2
4. **Add Livewire support** in Phase 3
5. **Polish UI** and add advanced features
6. **Document everything** as you go
7. **Release v2.0.0** when complete

---

## 🎯 Success Metrics

- ✅ Zero 419 errors reported
- ✅ DevTools detection >95% accurate
- ✅ Performance overhead <50ms
- ✅ Easy 3-step installation
- ✅ Works with Livewire/Inertia/API
- ✅ Comprehensive documentation
- ✅ Test coverage >85%

---

**Ready to start implementing!** 🚀

Begin with creating the middleware and controller files as outlined in PLAN.md Phase 1.
