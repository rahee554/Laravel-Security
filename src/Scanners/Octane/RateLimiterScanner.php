<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class RateLimiterScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Rate Limiter Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects rate limiters using static user/tenant data';
    }

    protected function execute(): void
    {
        $paths = ['app/Http/Controllers', 'app/Http/Middleware', 'routes', 'app/Providers'];

        $allFiles = [];
        foreach ($paths as $path) {
            if (File::exists(base_path($path))) {
                $allFiles = array_merge($allFiles, $this->fileSystem->getPhpFiles([$path]));
            }
        }

        foreach ($allFiles as $file) {
            $this->scanForRateLimiters($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForRateLimiters(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for RateLimiter::for() definitions
            if (preg_match('/RateLimiter::for\(/', $line)) {
                // Check if the rate limiter callback might use static data
                $contextLines = array_slice($lines, max(0, $lineNumber - 2), 5);
                $context = implode("\n", $contextLines);

                // Check for static properties in rate limiter
                if (preg_match('/self::\$|static::\$/', $context)) {
                    $this->addVulnerability(
                        'Rate Limiter Using Static Property',
                        VulnerabilitySeverity::CRITICAL,
                        'Rate limiter callback accesses static property. This can cause rate limits to apply '.
                        'globally instead of per-user in Octane.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use $request->user()->id or $request->ip() directly, not static properties.',
                        []
                    );
                }

                // Check for tenant access without proper context
                if (preg_match('/tenant\(\)/', $context) && ! preg_match('/\$request/', $context)) {
                    $this->addVulnerability(
                        'Rate Limiter Using Tenant Without Request',
                        VulnerabilitySeverity::HIGH,
                        'Rate limiter accesses tenant() without request context. May use cached tenant data.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Pass tenant ID from $request to ensure correct tenant context.',
                        []
                    );
                }
            }

            // Check for hardcoded rate limiter keys
            if (preg_match('/Limit::(?:perMinute|perHour|perDay)\(.*[\'"][\w-]+[\'"]/', $line)) {
                $this->addVulnerability(
                    'Hardcoded Rate Limit Key',
                    VulnerabilitySeverity::MEDIUM,
                    'Rate limiter uses hardcoded key. This applies rate limit globally, not per user.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Include user ID or IP address in rate limit key: by($request->user()?->id ?: $request->ip())',
                    []
                );
            }

            // Check for rate limiters using Auth facade
            if (preg_match('/RateLimiter::for\(/', $line)) {
                $contextLines = array_slice($lines, max(0, $lineNumber - 2), 10);
                $context = implode("\n", $contextLines);

                if (preg_match('/Auth::id\(\)/', $context) && ! preg_match('/\$request/', $context)) {
                    $this->addVulnerability(
                        'Rate Limiter Using Auth::id() Without Request',
                        VulnerabilitySeverity::HIGH,
                        'Rate limiter uses Auth::id() instead of $request->user()->id. May cache wrong user.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use $request->user()?->id instead of Auth::id() in rate limiter callbacks.',
                        []
                    );
                }
            }

            // Check for throttle middleware with static keys
            if (preg_match('/->middleware\([\'"]throttle:[^\'"\]]+[\'"]/', $line)) {
                if (! preg_match('/throttle:.*,.*/', $line)) {
                    $this->addVulnerability(
                        'Throttle Middleware Without User Context',
                        VulnerabilitySeverity::MEDIUM,
                        'throttle middleware may not include user-specific rate limiting.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use throttle:60,1,custom-key to specify custom rate limiter with user context.',
                        []
                    );
                }
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Http/Controllers')) ||
               File::exists(base_path('app/Http/Middleware')) ||
               File::exists(base_path('routes')) ||
               File::exists(base_path('app/Providers'));
    }
}
