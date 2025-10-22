<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Console Security Enabled
    |--------------------------------------------------------------------------
    |
    | Enable or disable the entire console security module. When disabled,
    | no handshake checks will be performed and all requests will pass through.
    |
    */
    'enabled' => env('CONSOLE_SECURITY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Cookie Configuration
    |--------------------------------------------------------------------------
    |
    | Configure the handshake cookie settings. The cookie stores an encrypted
    | token that is validated on each request.
    |
    */
    'cookie' => [
        'name' => env('CONSOLE_SECURITY_COOKIE', 'af_handshake'),
        'lifetime' => env('CONSOLE_SECURITY_LIFETIME', 5), // minutes
        'secure' => env('CONSOLE_SECURITY_SECURE', true), // HTTPS only
        'same_site' => env('CONSOLE_SECURITY_SAME_SITE', 'lax'), // lax, strict, none
    ],

    /*
    |--------------------------------------------------------------------------
    | Token Configuration
    |--------------------------------------------------------------------------
    |
    | Configure token generation, validation, and rotation settings.
    |
    */
    'token' => [
        // Bind token to session ID (prevents cookie theft)
        'session_bound' => true,

        // Automatically renew tokens before expiration
        'auto_renew' => true,

        // Grace period in seconds after expiration
        'grace_period' => 60,

        // Token rotation interval in seconds (renew every X seconds)
        'rotation_interval' => 240, // 4 minutes

        // Validate user agent matches (prevents session hijacking)
        'fingerprint_validation' => true,

        // Strict IP checking (may cause issues with mobile networks)
        'strict_ip_check' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Detection Configuration
    |--------------------------------------------------------------------------
    |
    | Configure DevTools and console tampering detection settings.
    |
    */
    'detection' => [
        // Enable DevTools detection
        'devtools_enabled' => true,

        // Enable console tampering detection
        'console_tampering' => true,

        // Enable network request monitoring
        'network_monitoring' => true,

        // Window size difference threshold (pixels)
        'size_threshold' => 160,

        // Synchronous loop timing threshold (milliseconds)
        'timing_threshold' => 120,

        // Number of loop iterations for timing test
        'loop_iterations' => 100000,

        // Auto-renew check interval (seconds)
        'renewal_check_interval' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Excluded Paths
    |--------------------------------------------------------------------------
    |
    | Paths that should bypass console security checks. Use glob patterns.
    | These paths will not require a handshake token.
    |
    */
    'excluded_paths' => [
        '_security/*',
        'blocked',
        'loader',
        'api/*',
        'livewire/message/*',
        'livewire/upload-file',
        'assets/*',
        'vendor/*',
        'storage/*',
        'build/*',
        'favicon.ico',
        'robots.txt',
    ],

    /*
    |--------------------------------------------------------------------------
    | Whitelist Configuration
    |--------------------------------------------------------------------------
    |
    | IPs and user agents that should bypass console security. Useful for
    | development, CI/CD, and allowing legitimate bots.
    |
    */
    'whitelist' => [
        // Whitelisted IP addresses (supports CIDR notation and wildcards)
        'ips' => array_filter(explode(',', env('CONSOLE_SECURITY_WHITELIST_IPS', ''))),

        // Whitelisted user agents (case-insensitive substring match)
        'user_agents' => [
            'Googlebot',
            'Bingbot',
            'Lighthouse',
            'PageSpeed',
            'GTmetrix',
            'Pingdom',
            'UptimeRobot',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Response Views
    |--------------------------------------------------------------------------
    |
    | Configure which views to show for different security states.
    |
    */
    'responses' => [
        // View shown before handshake completes
        'loader_view' => 'laravel-security::loader',

        // View shown when DevTools detected
        'blocked_view' => 'laravel-security::blocked',

        // View shown when token expires (optional)
        'expired_view' => 'laravel-security::expired',
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting
    |--------------------------------------------------------------------------
    |
    | Configure rate limits for handshake and renewal endpoints.
    | Format: [attempts, decay_minutes]
    |
    */
    'rate_limiting' => [
        // Handshake verification rate limit
        'handshake_attempts' => 30,
        'handshake_decay' => 1, // minutes

        // Token renewal rate limit
        'renewal_attempts' => 60,
        'renewal_decay' => 1, // minutes
    ],

    /*
    |--------------------------------------------------------------------------
    | Logging Configuration
    |--------------------------------------------------------------------------
    |
    | Configure what security events should be logged.
    |
    */
    'logging' => [
        // Enable security event logging
        'enabled' => env('CONSOLE_SECURITY_LOGGING', true),

        // Log channel to use
        'channel' => env('CONSOLE_SECURITY_LOG_CHANNEL', 'stack'),

        // Log blocked requests
        'log_blocked' => true,

        // Log successful handshakes
        'log_handshakes' => false,

        // Log token renewals
        'log_renewals' => false,

        // Log revocations
        'log_revocations' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Security Policy (CSP)
    |--------------------------------------------------------------------------
    |
    | Configure CSP headers for additional script protection.
    |
    */
    'csp' => [
        // Enable CSP headers
        'enabled' => false,

        // CSP directives
        'directives' => [
            'default-src' => "'self'",
            'script-src' => "'self' 'unsafe-inline' 'unsafe-eval'",
            'style-src' => "'self' 'unsafe-inline'",
            'img-src' => "'self' data: https:",
            'font-src' => "'self' data:",
            'connect-src' => "'self'",
            'frame-ancestors' => "'none'",
        ],

        // Report violations to this URI
        'report_uri' => null,

        // Report-only mode (logs violations but doesn't block)
        'report_only' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Livewire Integration
    |--------------------------------------------------------------------------
    |
    | Configure automatic Livewire component protection.
    |
    */
    'livewire' => [
        // Automatically protect all Livewire components
        'auto_protect' => false,

        // Validate Livewire request signatures
        'validate_signatures' => true,

        // Validate component fingerprints
        'validate_fingerprints' => true,

        // Rate limit per component (requests per minute)
        'rate_limit' => 120,
    ],

    /*
    |--------------------------------------------------------------------------
    | Advanced Features
    |--------------------------------------------------------------------------
    |
    | Additional security features for enhanced protection.
    |
    */
    'advanced' => [
        // Enable AI-powered behavior analysis (requires additional setup)
        'ai_detection' => false,

        // Browser fingerprinting
        'browser_fingerprinting' => false,

        // Geolocation verification
        'geo_verification' => false,

        // Device trust scoring
        'device_trust' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Development Mode
    |--------------------------------------------------------------------------
    |
    | When enabled, provides detailed error messages and bypasses certain
    | checks. NEVER enable this in production!
    |
    */
    'dev_mode' => env('CONSOLE_SECURITY_DEV_MODE', false),

];
