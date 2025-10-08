<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class CorsScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'CORS & HTTP Headers Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks CORS configuration, HTTP security headers, and cross-origin resource sharing policies';
    }

    public function isApplicable(): bool
    {
        return true; // Always applicable
    }

    protected function execute(): void
    {
        $this->checkCorsMiddleware();
        $this->checkCorsConfiguration();
        $this->checkSecurityHeaders();
        $this->checkKernelMiddleware();
    }

    protected function checkCorsMiddleware(): void
    {
        $kernelFile = base_path('app/Http/Kernel.php');
        $bootstrapAppFile = base_path('bootstrap/app.php');

        // Check Laravel 11 style (bootstrap/app.php)
        if (file_exists($bootstrapAppFile)) {
            $content = file_get_contents($bootstrapAppFile);

            if (! str_contains($content, 'HandleCors') && ! str_contains($content, 'cors')) {
                $this->addVulnerability(
                    'CORS Middleware Not Registered',
                    VulnerabilitySeverity::HIGH,
                    'CORS middleware is not registered in bootstrap/app.php. This may lead to CORS-related security issues.',
                    $bootstrapAppFile,
                    null,
                    null,
                    'Add CORS middleware in bootstrap/app.php: ->withMiddleware(function (Middleware $middleware) { $middleware->web(HandleCors::class); })',
                    ['type' => 'missing_cors_middleware']
                );
            }
        }

        // Check Laravel 10 style (Kernel.php)
        if (file_exists($kernelFile)) {
            $content = file_get_contents($kernelFile);

            if (! str_contains($content, 'HandleCors') && ! str_contains($content, '\\Fruitcake\\Cors\\HandleCors')) {
                $this->addVulnerability(
                    'CORS Middleware Not Registered in Kernel',
                    VulnerabilitySeverity::MEDIUM,
                    'CORS middleware may not be properly registered in HTTP Kernel.',
                    $kernelFile,
                    null,
                    null,
                    'Add HandleCors middleware to $middleware property in Kernel.php',
                    ['type' => 'missing_cors_middleware']
                );
            }
        }
    }

    protected function checkCorsConfiguration(): void
    {
        $configFile = config_path('cors.php');

        if (! file_exists($configFile)) {
            $this->addVulnerability(
                'CORS Configuration File Missing',
                VulnerabilitySeverity::MEDIUM,
                'CORS configuration file (config/cors.php) is missing. Default CORS settings may be insecure.',
                config_path(),
                null,
                null,
                'Publish CORS configuration: php artisan config:publish cors',
                ['type' => 'missing_cors_config']
            );

            return;
        }

        $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

        $content = file_get_contents($configFile);

        // Check for wildcard origin with credentials
        if (str_contains($content, "'*'") && str_contains($content, "'supports_credentials' => true")) {
            $this->addVulnerability(
                'Dangerous CORS Configuration: Wildcard with Credentials',
                VulnerabilitySeverity::CRITICAL,
                'CORS is configured with wildcard origin (*) and credentials enabled. This is a security risk as it allows any origin to make credentialed requests.',
                $configFile,
                null,
                null,
                "Change 'paths' => ['*'] to specific paths, or set 'supports_credentials' => false",
                ['type' => 'wildcard_with_credentials']
            );
        }

        // Check for overly permissive origins
        if (preg_match("/'allowed_origins'\s*=>\s*\[\s*'\*'\s*\]/", $content)) {
            $this->addVulnerability(
                'Overly Permissive CORS: All Origins Allowed',
                VulnerabilitySeverity::HIGH,
                'CORS allows requests from any origin (*). This may expose your API to unauthorized access.',
                $configFile,
                null,
                null,
                "Specify exact allowed origins instead of '*': 'allowed_origins' => ['https://yourdomain.com']",
                ['type' => 'permissive_origins']
            );
        }

        // Check for allowed_origins_patterns with overly broad patterns
        if (preg_match("/'allowed_origins_patterns'\s*=>\s*\[.*\*.*\]/", $content)) {
            $this->addVulnerability(
                'Overly Broad CORS Origin Pattern',
                VulnerabilitySeverity::MEDIUM,
                'CORS origin patterns may be too permissive. Review regex patterns to ensure they only match intended domains.',
                $configFile,
                null,
                null,
                "Use specific patterns like: ['#^https://.*\.yourdomain\.com$#']",
                ['type' => 'broad_origin_pattern']
            );
        }

        // Check for all methods allowed
        if (preg_match("/'allowed_methods'\s*=>\s*\[\s*'\*'\s*\]/", $content)) {
            $this->addVulnerability(
                'All HTTP Methods Allowed in CORS',
                VulnerabilitySeverity::MEDIUM,
                'CORS configuration allows all HTTP methods (*). Consider restricting to only needed methods.',
                $configFile,
                null,
                null,
                "Specify only required methods: 'allowed_methods' => ['GET', 'POST', 'PUT', 'DELETE']",
                ['type' => 'all_methods_allowed']
            );
        }

        // Check for all headers allowed
        if (preg_match("/'allowed_headers'\s*=>\s*\[\s*'\*'\s*\]/", $content)) {
            $this->addVulnerability(
                'All Headers Allowed in CORS',
                VulnerabilitySeverity::LOW,
                'CORS configuration allows all headers (*). Consider specifying only required headers for better security.',
                $configFile,
                null,
                null,
                "Specify required headers: 'allowed_headers' => ['Content-Type', 'Authorization', 'X-Requested-With']",
                ['type' => 'all_headers_allowed']
            );
        }

        // Check max_age configuration
        if (preg_match("/'max_age'\s*=>\s*(\d+)/", $content, $matches)) {
            $maxAge = (int) $matches[1];
            if ($maxAge > 86400) { // 24 hours
                $this->addVulnerability(
                    'Excessive CORS Max Age',
                    VulnerabilitySeverity::INFO,
                    "CORS max_age is set to {$maxAge} seconds (>24 hours). This may cache preflight responses too long.",
                    $configFile,
                    null,
                    null,
                    'Consider reducing max_age to 3600 (1 hour) or 86400 (24 hours)',
                    ['type' => 'excessive_max_age', 'value' => $maxAge]
                );
            }
        }
    }

    protected function checkSecurityHeaders(): void
    {
        $middlewareFiles = $this->fileSystem->getFiles(app_path('Http/Middleware'));

        $hasSecurityHeaders = false;

        foreach ($middlewareFiles as $file) {
            $content = file_get_contents($file);

            if (str_contains($content, 'X-Frame-Options') ||
                str_contains($content, 'X-Content-Type-Options') ||
                str_contains($content, 'Strict-Transport-Security')) {
                $hasSecurityHeaders = true;
                break;
            }
        }

        if (! $hasSecurityHeaders) {
            $this->addVulnerability(
                'Missing Security Headers Middleware',
                VulnerabilitySeverity::MEDIUM,
                'No middleware found that sets security headers (X-Frame-Options, X-Content-Type-Options, HSTS, CSP).',
                app_path('Http/Middleware'),
                null,
                null,
                'Create middleware to add security headers: X-Frame-Options: DENY, X-Content-Type-Options: nosniff, Strict-Transport-Security: max-age=31536000',
                ['type' => 'missing_security_headers']
            );
        }

        // Check for CSP (Content Security Policy)
        $hasCSP = false;
        foreach ($middlewareFiles as $file) {
            $content = file_get_contents($file);
            if (str_contains($content, 'Content-Security-Policy')) {
                $hasCSP = true;

                // Check for unsafe CSP directives
                if (str_contains($content, "'unsafe-inline'") || str_contains($content, "'unsafe-eval'")) {
                    $this->addVulnerability(
                        'Weak Content Security Policy',
                        VulnerabilitySeverity::HIGH,
                        "Content-Security-Policy contains unsafe directives ('unsafe-inline' or 'unsafe-eval').",
                        $file,
                        null,
                        null,
                        "Remove 'unsafe-inline' and 'unsafe-eval' from CSP. Use nonces or hashes for inline scripts.",
                        ['type' => 'weak_csp']
                    );
                }

                break;
            }
        }

        if (! $hasCSP && config('app.env') === 'production') {
            $this->addVulnerability(
                'Missing Content Security Policy',
                VulnerabilitySeverity::MEDIUM,
                'No Content-Security-Policy header found. CSP helps prevent XSS and other injection attacks.',
                app_path('Http/Middleware'),
                null,
                null,
                "Add CSP header in middleware: Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-{random}'",
                ['type' => 'missing_csp']
            );
        }
    }

    protected function checkKernelMiddleware(): void
    {
        $kernelFile = base_path('app/Http/Kernel.php');

        if (! file_exists($kernelFile)) {
            return; // Laravel 11 doesn't use Kernel.php
        }

        $content = file_get_contents($kernelFile);

        // Check for TrustProxies middleware
        if (! str_contains($content, 'TrustProxies')) {
            $this->addVulnerability(
                'Missing TrustProxies Middleware',
                VulnerabilitySeverity::MEDIUM,
                'TrustProxies middleware not found. This may cause issues with HTTPS detection and X-Forwarded headers.',
                $kernelFile,
                null,
                null,
                'Add TrustProxies middleware to $middleware array',
                ['type' => 'missing_trust_proxies']
            );
        }

        // Check for TrustHosts middleware
        if (! str_contains($content, 'TrustHosts')) {
            $this->addVulnerability(
                'Missing TrustHosts Middleware',
                VulnerabilitySeverity::LOW,
                'TrustHosts middleware not found. Consider adding it to prevent host header injection attacks.',
                $kernelFile,
                null,
                null,
                'Add TrustHosts middleware and configure trusted hosts',
                ['type' => 'missing_trust_hosts']
            );
        }
    }
}
