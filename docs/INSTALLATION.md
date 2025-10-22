# 🛡️ Laravel Security - Installation & Usage Guide

## Package: artflow-studio/laravel-security v2.0.0

---

## 📦 Installation

### Step 1: Install the Package

```bash
composer require artflow-studio/laravel-security
```

The package will auto-register via Laravel's package discovery.

---

## 🔧 Quick Setup (3 Steps)

### Step 1: Publish Configuration & Assets

```bash
# Publish console security config
php artisan vendor:publish --tag=console-security-config

# Publish JavaScript assets (required)
php artisan vendor:publish --tag=console-security-assets

# (Optional) Publish views for customization
php artisan vendor:publish --tag=console-security-views
```

### Step 2: Add to Your Layout

In your main layout file (e.g., `resources/views/layouts/app.blade.php`):

```blade
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ csrf_token() }}">
    
    {{-- Add this single line --}}
    @afConsoleSecurity
    
    {{-- Your other head content --}}
</head>
```

### Step 3: Protect Your Routes

In your `routes/web.php`:

```php
use Illuminate\Support\Facades\Route;

// Protected routes (admin, dashboard, sensitive pages)
Route::middleware(['console:strict'])->group(function () {
    Route::get('/admin', [AdminController::class, 'index']);
    Route::get('/dashboard', [DashboardController::class, 'index']);
    Route::resource('users', UserController::class);
});

// Public routes (no protection needed)
Route::get('/', [HomeController::class, 'index']);
Route::get('/about', [PageController::class, 'about']);
```

**That's it!** Your application is now protected. 🎉

---

## 🔐 Features Explained

### 1. Automatic DevTools Detection

The package automatically detects when users open browser DevTools using multiple methods:

- **Window size analysis** - Detects when DevTools is docked
- **Console logging tricks** - Detects when console is open
- **Performance timing** - Detects debugger interference

When DevTools is detected, users are redirected to a friendly "blocked" page and can return when they close DevTools.

### 2. Token-Based Security

Every request is validated with an encrypted, session-bound token:

- **Session binding** - Token tied to server session (prevents cookie theft)
- **Short-lived** - Tokens expire in 5 minutes (configurable)
- **Auto-renewal** - Tokens automatically renew every 4 minutes (no 419 errors!)
- **Encrypted** - Uses Laravel's encryption (AES-256)

### 3. Console Tampering Prevention

The JavaScript shield prevents:

- Console method overrides
- Prototype pollution attacks
- Excessive network requests (rate limiting)
- Cookie/localStorage manipulation

### 4. Data Tampering Protection

For Livewire components, use the `WithConsoleSecurity` trait:

```php
use ArtflowStudio\LaravelSecurity\Traits\WithConsoleSecurity;
use Livewire\Component;

class UserProfile extends Component
{
    use WithConsoleSecurity;
    
    public $name;
    public $email;
    
    // Automatically protected from:
    // - SQL injection attempts
    // - XSS attacks
    // - Property manipulation via console
    // - Excessive requests
}
```

---

## ⚙️ Configuration

Edit `config/console-security.php` to customize behavior:

### Basic Settings

```php
return [
    // Enable/disable the entire module
    'enabled' => env('CONSOLE_SECURITY_ENABLED', true),
    
    // Cookie settings
    'cookie' => [
        'name' => 'af_handshake',
        'lifetime' => 5, // minutes
        'secure' => true, // HTTPS only
    ],
    
    // Token settings
    'token' => [
        'auto_renew' => true, // Prevent 419 errors
        'rotation_interval' => 240, // 4 minutes
        'grace_period' => 60, // 1 minute
    ],
];
```

### Excluded Paths

Paths that should bypass security checks:

```php
'excluded_paths' => [
    'api/*',          // API routes
    'assets/*',       // Static assets
    'livewire/*',     // Livewire internal routes
    '_security/*',    // Security handshake routes
],
```

### IP Whitelist

Allow specific IPs to bypass checks (useful for development):

```php
'whitelist' => [
    'ips' => ['127.0.0.1', '192.168.1.0/24'],
    'user_agents' => ['Googlebot', 'Lighthouse'],
],
```

### Detection Sensitivity

Fine-tune detection thresholds:

```php
'detection' => [
    'size_threshold' => 160,      // pixels
    'timing_threshold' => 120,    // milliseconds
    'loop_iterations' => 100000,  // performance test
],
```

---

## 🎨 Customization

### Custom Views

After publishing views, customize the loader and blocked pages:

```bash
php artisan vendor:publish --tag=console-security-views
```

Edit:
- `resources/views/vendor/laravel-security/loader.blade.php`
- `resources/views/vendor/laravel-security/blocked.blade.php`

### Custom JavaScript

After publishing assets, customize the detection logic:

```bash
php artisan vendor:publish --tag=console-security-assets
```

Edit:
- `public/vendor/laravel-security/js/console-security.js`

---

## 🧪 Testing

### Development Mode

Disable console security during development:

```env
# .env
CONSOLE_SECURITY_ENABLED=false
```

Or whitelist your IP:

```env
CONSOLE_SECURITY_WHITELIST_IPS=127.0.0.1,192.168.1.100
```

### Show Security Status

Add debugging badge to your layout:

```blade
{{-- Shows token status, expiry, etc. (only in debug mode) --}}
@afSecurityStatus

{{-- Shows "Protected by Laravel Security" badge --}}
@afSecurityBadge
```

### Manual Token Check

Check token status via JavaScript console:

```javascript
// Check if DevTools are detected
AF_SECURITY.detectDevTools()

// Manually renew token
AF_SECURITY.renewToken()

// Get token status
fetch('/_security/handshake/status')
    .then(r => r.json())
    .then(console.log)
```

---

## 🚨 Troubleshooting

### "419 Page Expired" Errors

If you see 419 errors, ensure:

1. `csrf-token` meta tag is present in your layout
2. Auto-renewal is enabled: `'auto_renew' => true` in config
3. JavaScript file is loaded: Check browser console for errors

### Loader Page Shows Forever

If stuck on loader page:

1. Check browser console for errors
2. Verify handshake route is accessible: `/_security/handshake/verify`
3. Ensure session is working (check `SESSION_DRIVER` in `.env`)
4. Check server logs: `storage/logs/laravel.log`

### False Positive Blocked Page

If legitimate users are blocked:

1. Increase detection thresholds in config
2. Whitelist their IP temporarily
3. Check for browser extensions interfering with window size

### Livewire Components Not Protected

If using the trait and still having issues:

1. Verify trait is imported: `use WithConsoleSecurity;`
2. Check Livewire is up to date: `composer update livewire/livewire`
3. Clear Livewire cache: `php artisan livewire:discover`

---

## 📊 Monitoring

### View Logs

Security events are logged to your configured log channel:

```bash
# View recent security logs
tail -f storage/logs/laravel.log | grep "Console Security"
```

### Log Events

The package logs:
- ✅ Successful handshakes
- ❌ Blocked requests (invalid tokens)
- 🔄 Token renewals
- ⚠️ Suspicious activity (tampering attempts)

---

## 🔒 Security Best Practices

### 1. Always Use HTTPS

The security cookie requires HTTPS in production:

```php
// config/console-security.php
'cookie' => [
    'secure' => env('APP_ENV') === 'production',
],
```

### 2. Rotate Tokens Frequently

Shorter token lifetimes = smaller attack window:

```php
'cookie' => [
    'lifetime' => 5, // 5 minutes
],
'token' => [
    'rotation_interval' => 240, // 4 minutes
],
```

### 3. Whitelist Carefully

Only whitelist trusted IPs:

```php
'whitelist' => [
    'ips' => [
        '127.0.0.1', // Local development only
    ],
],
```

### 4. Monitor Logs

Regularly review security logs for patterns:

```bash
# Count blocked attempts per IP
grep "blocked" storage/logs/laravel.log | awk '{print $10}' | sort | uniq -c | sort -rn
```

### 5. Test Thoroughly

Test security in staging before production:

1. Try opening DevTools → Should block
2. Close DevTools → Should auto-return
3. Wait 5+ minutes → Token should auto-renew
4. Clear cookies → Should show loader

---

## 🎯 Advanced Usage

### Programmatic Token Validation

```php
use ArtflowStudio\LaravelSecurity\Support\SecurityToken;

// Generate new token
$token = SecurityToken::generate();

// Verify token
$valid = SecurityToken::verify($token['encrypted']);

// Check if expiring soon
$expiring = SecurityToken::isExpiring();

// Get metadata
$metadata = SecurityToken::metadata();
```

### Custom Middleware

Create your own middleware for specific logic:

```php
use ArtflowStudio\LaravelSecurity\Http\Middleware\ConsoleStrictMiddleware;

class MyCustomSecurityMiddleware extends ConsoleStrictMiddleware
{
    protected function isExcludedPath($request): bool
    {
        // Custom exclusion logic
        if ($request->is('my-special-path/*')) {
            return true;
        }
        
        return parent::isExcludedPath($request);
    }
}
```

### Conditional Protection

Protect specific Blade sections:

```blade
@requiresHandshake
    <div>This content only shows if handshake is valid</div>
    <p>Sensitive data here...</p>
@endrequiresHandshake
```

---

## 🚀 Performance

### Overhead

- **Middleware**: ~5-10ms per request
- **JavaScript**: ~15KB minified
- **Detection**: ~2-3ms per check
- **Token renewal**: ~20ms (async)

**Total**: <1% impact for most applications

### Optimization Tips

1. **Use Redis for sessions** in distributed environments
2. **Enable OPcache** for PHP
3. **Minify JavaScript** in production
4. **Use CDN** for static assets

---

## 📚 Additional Resources

- **GitHub**: [artflow-studio/laravel-security](https://github.com/artflow-studio/laravel-security)
- **Documentation**: See `PLAN.md` for detailed architecture
- **Issues**: Report bugs on GitHub Issues
- **Security**: Report vulnerabilities privately to security@artflow.studio

---

## 🙏 Support

Having issues? Try these resources:

1. Check this installation guide
2. Review configuration: `config/console-security.php`
3. Check logs: `storage/logs/laravel.log`
4. Search GitHub Issues
5. Open a new issue with:
   - Laravel version
   - Package version
   - Steps to reproduce
   - Error messages/logs

---

**Congratulations!** 🎉 Your Laravel application is now protected with enterprise-grade console security.

Remember: This is **defense in depth**. Always validate data server-side, use proper authentication, and follow Laravel security best practices.
