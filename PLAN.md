# 🛡️ Laravel Security Package - Implementation Plan

## Package: artflow-studio/laravel-security

**Version**: 2.0.0 (Console Security & Runtime Protection)  
**Date**: October 8, 2025

---

## 🎯 Overview

Extending the existing vulnerability scanner with **runtime protection features**:
- Console/DevTools detection and blocking
- Token-based request verification
- Automatic handshake middleware
- Data tampering prevention
- Auto-renewal of expired tokens (no 419 errors)

---

## 📋 Phase 1: Core Console Security Features

### 1.1 Middleware Implementation

**File**: `src/Http/Middleware/ConsoleStrictMiddleware.php`

**Features**:
- ✅ Handshake token verification on each request
- ✅ Automatic token renewal when expired (prevents 419 errors)
- ✅ Session-bound encrypted tokens
- ✅ Configurable excluded paths (API, assets, public routes)
- ✅ IP whitelist for admin/dev environments
- ✅ Graceful degradation for non-JS clients

**Registration**:
```php
Route::middleware(['console:strict'])->group(function () {
    // Protected routes
});
```

### 1.2 Handshake Controller

**File**: `src/Http/Controllers/HandshakeController.php`

**Endpoints**:
- `POST /_security/handshake/verify` - Initial handshake
- `POST /_security/handshake/renew` - Auto-renewal endpoint
- `GET /_security/handshake/status` - Check token validity

**Features**:
- Generate UUID-based session tokens
- Encrypted cookie storage
- Automatic CSRF protection
- Rate limiting (30 requests/minute)
- JSON responses for AJAX

### 1.3 Blade Directive

**Directive**: `@afConsoleSecurity`

**Usage in layout**:
```blade
<head>
    @afConsoleSecurity
</head>
```

**Injects**:
- DevTools detection script
- Console tampering detection
- Token management JavaScript
- Auto-renewal logic
- Blocked page redirect

### 1.4 JavaScript Shield

**File**: `resources/js/console-security.js`

**Detection Methods**:
1. **DevTools Detection**:
   - Window size changes (outerWidth/innerWidth)
   - Console log toString() trick
   - Synchronous loop timing analysis
   - ResizeObserver monitoring

2. **Console Tampering Detection**:
   - Console method override detection
   - Prototype pollution checks
   - Global object modification tracking

3. **Suspicious Behavior**:
   - Rapid API calls (>50/sec)
   - Cookie manipulation attempts
   - LocalStorage tampering
   - Network request interception

**Auto-Renewal**:
```javascript
// Token expires in 5 minutes, renew at 4 minutes
setInterval(async () => {
    await fetch('/_security/handshake/renew', {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'X-CSRF-TOKEN': csrfToken }
    });
}, 240000); // 4 minutes
```

---

## 📋 Phase 2: Views & UI

### 2.1 Loader Page

**File**: `resources/views/loader.blade.php`

**Purpose**: Shown before handshake completes

**Features**:
- Minimal HTML (prevents view-source exposure)
- Animated loading spinner
- DevTools detection during load
- Automatic redirect on success
- Fallback for slow connections

### 2.2 Blocked Page

**File**: `resources/views/blocked.blade.php`

**Purpose**: Shown when DevTools/tampering detected

**Features**:
- User-friendly explanation
- Auto-redirect when DevTools closed
- Session recovery (returns to previous page)
- Admin bypass option (IP whitelist)
- Support contact information

### 2.3 Expired Token Page (Optional)

**File**: `resources/views/expired.blade.php`

**Purpose**: Shown if auto-renewal fails

**Features**:
- One-click manual renewal
- Session preservation
- Error reporting
- Automatic retry mechanism

---

## 📋 Phase 3: Livewire Integration

### 3.1 Livewire Trait

**File**: `src/Traits/WithConsoleSecurity.php`

**Usage**:
```php
use ArtflowStudio\LaravelSecurity\Traits\WithConsoleSecurity;

class MyComponent extends Component
{
    use WithConsoleSecurity;
    
    // Automatically protected
}
```

**Features**:
- Auto-attaches security token to Livewire requests
- Validates token on each Livewire update
- Prevents component state tampering
- Blocks requests from DevTools
- Automatic token refresh

### 3.2 Livewire Middleware

**File**: `src/Http/Middleware/LivewireSecurityMiddleware.php`

**Features**:
- Validates Livewire request signatures
- Prevents property manipulation
- Checks component fingerprint
- Verifies method calls
- Rate limiting per component

---

## 📋 Phase 4: Token Management

### 4.1 Token Helper Class

**File**: `src/Support/SecurityToken.php`

**Methods**:
```php
SecurityToken::generate();        // Create new token
SecurityToken::verify($token);    // Validate token
SecurityToken::renew($token);     // Renew expiring token
SecurityToken::revoke($token);    // Invalidate token
SecurityToken::isExpiring($token); // Check if needs renewal
```

**Features**:
- UUID-based tokens
- AES-256 encryption
- Session binding
- Automatic expiration (configurable: 5-60 minutes)
- Token rotation every X minutes
- Redis/Cache support for distributed systems

### 4.2 Token Rotation Strategy

**Strategy**: Short-lived tokens with auto-renewal

**Flow**:
1. Token valid for 5 minutes
2. Client auto-renews at 4 minutes
3. Old token valid for 1 minute grace period
4. Seamless user experience (no 419 errors)
5. Reduces replay attack window

---

## 📋 Phase 5: Configuration

### 5.1 Config File

**File**: `config/console-security.php`

```php
return [
    'enabled' => env('CONSOLE_SECURITY_ENABLED', true),
    
    'cookie' => [
        'name' => env('CONSOLE_SECURITY_COOKIE', 'af_handshake'),
        'lifetime' => env('CONSOLE_SECURITY_LIFETIME', 5), // minutes
        'secure' => env('CONSOLE_SECURITY_SECURE', true),
        'same_site' => 'lax',
    ],
    
    'token' => [
        'session_bound' => true,
        'auto_renew' => true,
        'grace_period' => 60, // seconds
        'rotation_interval' => 240, // seconds (4 minutes)
    ],
    
    'detection' => [
        'devtools_enabled' => true,
        'console_tampering' => true,
        'network_monitoring' => true,
        'size_threshold' => 160, // pixels
        'timing_threshold' => 120, // milliseconds
        'loop_iterations' => 100000,
    ],
    
    'excluded_paths' => [
        '_security/*',
        'blocked',
        'loader',
        'api/*',
        'livewire/*',
        'assets/*',
        'vendor/*',
    ],
    
    'whitelist' => [
        'ips' => explode(',', env('CONSOLE_SECURITY_WHITELIST_IPS', '')),
        'user_agents' => ['Googlebot', 'Lighthouse'], // SEO/testing tools
    ],
    
    'responses' => [
        'loader_view' => 'laravel-security::loader',
        'blocked_view' => 'laravel-security::blocked',
        'expired_view' => 'laravel-security::expired',
    ],
    
    'rate_limiting' => [
        'handshake' => '30,1', // 30 per minute
        'renewal' => '60,1',    // 60 per minute
    ],
    
    'logging' => [
        'enabled' => true,
        'channel' => 'security',
        'log_blocked' => true,
        'log_renewals' => false,
    ],
    
    'csp' => [
        'enabled' => true,
        'directives' => [
            'script-src' => "'self' 'unsafe-inline'",
            'style-src' => "'self' 'unsafe-inline'",
            'img-src' => "'self' data: https:",
        ],
    ],
];
```

---

## 📋 Phase 6: Advanced Features

### 6.1 CSP Headers Integration

**File**: `src/Http/Middleware/ContentSecurityPolicyMiddleware.php`

**Features**:
- Automatic CSP header injection
- Nonce generation for inline scripts
- Report-URI for violation tracking
- Configurable directives
- Development vs production modes

### 6.2 AI-Powered Detection (Optional)

**File**: `src/Services/AIDetectionService.php`

**Features**:
- Pattern recognition for bot behavior
- Suspicious request sequence detection
- Velocity analysis (requests per second)
- Browser fingerprint validation
- Machine learning model (optional TensorFlow.js)

### 6.3 Analytics Dashboard (Future)

**Files**:
- `src/Http/Controllers/SecurityDashboardController.php`
- `resources/views/dashboard.blade.php`

**Metrics**:
- Total handshakes performed
- Blocked attempts (with reasons)
- Token renewals
- DevTools detection events
- Geographic distribution
- Browser/device statistics
- Threat level timeline

---

## 📋 Phase 7: Testing & Documentation

### 7.1 Tests

**Unit Tests**:
- Token generation/validation
- Cookie encryption/decryption
- Session binding logic
- Whitelist matching

**Integration Tests**:
- Middleware flow (blocked → handshake → allowed)
- Token auto-renewal
- Livewire trait integration
- Excluded paths handling

**Browser Tests** (Dusk):
- DevTools detection
- Blocked page redirect
- Auto-return after closing DevTools
- Token renewal without page reload

### 7.2 Documentation

**README Updates**:
- Installation instructions
- Middleware registration
- Blade directive usage
- Livewire trait setup
- Configuration options
- Troubleshooting guide
- Performance impact notes

**Wiki Pages**:
- How DevTools detection works
- Token rotation strategy
- CSP best practices
- Debugging in development
- Production deployment checklist

---

## 📋 Implementation Checklist

### Phase 1: Core (Week 1)
- [ ] Create middleware structure
- [ ] Implement HandshakeController
- [ ] Build JavaScript detection module
- [ ] Create @afConsoleSecurity directive
- [ ] Add token helper class
- [ ] Write config file

### Phase 2: Views (Week 1)
- [ ] Design loader.blade.php
- [ ] Design blocked.blade.php
- [ ] Add auto-renewal JS
- [ ] Implement session recovery

### Phase 3: Livewire (Week 2)
- [ ] Create WithConsoleSecurity trait
- [ ] Add Livewire middleware
- [ ] Test component protection
- [ ] Document Livewire usage

### Phase 4: Advanced (Week 2)
- [ ] CSP middleware
- [ ] Rate limiting
- [ ] Logging infrastructure
- [ ] Whitelist logic

### Phase 5: Testing (Week 3)
- [ ] Write unit tests
- [ ] Write integration tests
- [ ] Browser testing with Dusk
- [ ] Performance benchmarking

### Phase 6: Documentation (Week 3)
- [ ] Update README
- [ ] Write installation guide
- [ ] Create troubleshooting guide
- [ ] Record video tutorials

---

## 🎯 Success Criteria

1. ✅ Zero 419 errors (automatic token renewal)
2. ✅ DevTools detection accuracy >95%
3. ✅ Performance overhead <50ms per request
4. ✅ No false positives for legitimate users
5. ✅ Works with Livewire, Inertia, and API routes
6. ✅ Simple 3-step installation
7. ✅ Comprehensive documentation
8. ✅ Test coverage >85%

---

## 🚀 Future Enhancements (v2.1+)

### Q1 2026
- [ ] WebAuthn/FIDO2 integration
- [ ] Device fingerprinting
- [ ] Behavioral biometrics
- [ ] Real-time threat dashboard

### Q2 2026
- [ ] Mobile app SDK (React Native/Flutter)
- [ ] Browser extension for enhanced protection
- [ ] Centralized security monitoring service
- [ ] Threat intelligence feed integration

### Q3 2026
- [ ] Zero-trust architecture support
- [ ] Blockchain-based token verification
- [ ] Quantum-resistant encryption
- [ ] AI-powered adaptive security

---

## 📊 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Browser (Client)                          │
│  ┌────────────────────────────────────────────────────┐    │
│  │  @afConsoleSecurity Script                         │    │
│  │  - DevTools Detection                              │    │
│  │  - Token Auto-Renewal                              │    │
│  │  - Console Tampering Check                         │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Laravel Application (Server)                    │
│  ┌────────────────────────────────────────────────────┐    │
│  │  ConsoleStrictMiddleware                           │    │
│  │  1. Check handshake cookie                         │    │
│  │  2. Validate session token                         │    │
│  │  3. Auto-renew if expiring                         │    │
│  │  4. Return loader if missing                       │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────┐    │
│  │  HandshakeController                               │    │
│  │  - /verify   (initial handshake)                   │    │
│  │  - /renew    (auto-renewal)                        │    │
│  │  - /status   (token check)                         │    │
│  └────────────────────────────────────────────────────┘    │
│                          │                                   │
│                          ▼                                   │
│  ┌────────────────────────────────────────────────────┐    │
│  │  SecurityToken Helper                              │    │
│  │  - Generate UUID                                   │    │
│  │  - Encrypt with APP_KEY                            │    │
│  │  - Bind to session                                 │    │
│  │  - Automatic rotation                              │    │
│  └────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 Key Design Decisions

### 1. **Why Session-Bound Tokens?**
- Prevents simple cookie theft
- Requires valid session to forge token
- Works with load-balanced setups (Redis sessions)

### 2. **Why Auto-Renewal?**
- No user disruption
- Seamless experience
- No 419 CSRF errors
- Maintains security with short token lifetime

### 3. **Why Multiple Detection Methods?**
- DevTools has many forms (docked, undocked, mobile)
- Single method easily bypassed
- Layered approach increases accuracy
- Configurable thresholds reduce false positives

### 4. **Why Excluded Paths?**
- API routes may use different auth (tokens, OAuth)
- Public assets shouldn't require handshake
- Livewire internal requests already protected
- Flexibility for mixed applications

---

## 📝 Notes for Implementation

1. **Start with middleware** - Core functionality that gates requests
2. **Build views second** - Loader and blocked pages are critical UX
3. **Add JavaScript third** - Detection and auto-renewal logic
4. **Livewire integration fourth** - Trait and specialized middleware
5. **Polish last** - CSP, AI detection, dashboard

**Keep it simple**: Users should just add `@afConsoleSecurity` and register middleware. Everything else automatic.

---

**Ready to implement?** Let's start with Phase 1!
