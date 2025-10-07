<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Scanners
    |--------------------------------------------------------------------------
    |
    | These scanners will be run by default when executing the scan command
    | without specifying which scanners to use.
    |
    */

    'default_scanners' => [
        'livewire',
        'rate-limit',
        'function-security',
        'data-exposure',
        'authentication',
        'authorization',
        'xss',
        'sql-injection',
        'csrf',
    ],

    /*
    |--------------------------------------------------------------------------
    | Scan Paths
    |--------------------------------------------------------------------------
    |
    | Define which directories should be scanned for vulnerabilities.
    | Paths are relative to the Laravel application root.
    |
    */

    'scan_paths' => [
        'app',
        'resources/views',
        'routes',
        'config',
        'database',
    ],

    /*
    |--------------------------------------------------------------------------
    | Exclude Paths
    |--------------------------------------------------------------------------
    |
    | Define which directories should be excluded from scanning.
    |
    */

    'exclude_paths' => [
        'vendor',
        'node_modules',
        'storage',
        'bootstrap/cache',
        'public',
        'tests',
    ],

    /*
    |--------------------------------------------------------------------------
    | File Extensions
    |--------------------------------------------------------------------------
    |
    | Define which file extensions should be scanned.
    |
    */

    'file_extensions' => [
        'php',
        'blade.php',
    ],

    /*
    |--------------------------------------------------------------------------
    | Severity Threshold
    |--------------------------------------------------------------------------
    |
    | Only report vulnerabilities at or above this severity level.
    | Options: critical, high, medium, low, info
    |
    */

    'severity_threshold' => 'low',

    /*
    |--------------------------------------------------------------------------
    | Report Output
    |--------------------------------------------------------------------------
    |
    | Default report format and output directory.
    | Formats: console, json, html, markdown
    |
    */

    'report' => [
        'format' => 'console',
        'output_dir' => storage_path('scanner-reports'),
        'auto_save' => false,
    ],

    /*
    |--------------------------------------------------------------------------
    | Livewire Scanner Configuration
    |--------------------------------------------------------------------------
    */

    'livewire' => [
        'check_public_properties' => true,
        'check_authorization' => true,
        'check_validation' => true,
        'check_mass_assignment' => true,
        'protected_properties' => ['password', 'token', 'secret', 'api_key'],
    ],

    /*
    |--------------------------------------------------------------------------
    | Rate Limiting Configuration
    |--------------------------------------------------------------------------
    */

    'rate_limit' => [
        'check_routes' => true,
        'check_api_routes' => true,
        'check_auth_routes' => true,
        'required_on_patterns' => [
            '/api/*',
            '/login',
            '/register',
            '/password/reset',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Function Security Configuration
    |--------------------------------------------------------------------------
    */

    'function_security' => [
        'dangerous_functions' => [
            'eval',
            'exec',
            'system',
            'shell_exec',
            'passthru',
            'proc_open',
            'popen',
            'unserialize',
            'assert',
            'create_function',
        ],
        'check_raw_queries' => true,
        'check_file_operations' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Data Exposure Configuration
    |--------------------------------------------------------------------------
    */

    'data_exposure' => [
        'check_debug_mode' => true,
        'check_stack_traces' => true,
        'check_api_responses' => true,
        'sensitive_keywords' => [
            'password',
            'secret',
            'token',
            'api_key',
            'private_key',
            'access_token',
            'refresh_token',
            'bearer',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Authentication Configuration
    |--------------------------------------------------------------------------
    */

    'authentication' => [
        'check_password_validation' => true,
        'check_session_config' => true,
        'check_remember_token' => true,
        'minimum_password_length' => 8,
    ],

    /*
    |--------------------------------------------------------------------------
    | XSS Scanner Configuration
    |--------------------------------------------------------------------------
    */

    'xss' => [
        'check_blade_raw_output' => true,
        'check_javascript_injection' => true,
        'check_url_injection' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | SQL Injection Configuration
    |--------------------------------------------------------------------------
    */

    'sql_injection' => [
        'check_raw_queries' => true,
        'check_whereRaw' => true,
        'check_orderByRaw' => true,
        'check_havingRaw' => true,
    ],

    /*
    |--------------------------------------------------------------------------
    | Dependency Scanner Configuration
    |--------------------------------------------------------------------------
    */

    'dependencies' => [
        'check_outdated' => true,
        'check_security_advisories' => true,
        'minimum_support_versions' => [
            'laravel/framework' => '10.0',
            'php' => '8.1',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Custom Rules
    |--------------------------------------------------------------------------
    |
    | Define custom scanning rules for your application.
    |
    */

    'custom_rules' => [
        // Add custom rules here
    ],

    /*
    |--------------------------------------------------------------------------
    | Fix Suggestions
    |--------------------------------------------------------------------------
    |
    | Enable or disable fix suggestions in the report output.
    |
    */

    'show_fix_suggestions' => true,

    /*
    |--------------------------------------------------------------------------
    | Progress Indicators
    |--------------------------------------------------------------------------
    |
    | Show progress bars and status updates during scanning.
    |
    */

    'show_progress' => true,

];
