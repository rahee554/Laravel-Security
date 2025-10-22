<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class BootstrapHelperScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Bootstrap & Helper Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects issues in bootstrap/app.php and helpers.php';
    }

    protected function execute(): void
    {
        $filesToScan = [];

        if (File::exists(base_path('bootstrap/app.php'))) {
            $filesToScan[] = base_path('bootstrap/app.php');
        }

        if (File::exists(base_path('app/Helpers.php'))) {
            $filesToScan[] = base_path('app/Helpers.php');
        }

        if (File::exists(base_path('app/helpers.php'))) {
            $filesToScan[] = base_path('app/helpers.php');
        }

        foreach ($filesToScan as $file) {
            $this->scanBootstrapOrHelper($file);
        }

        $this->result->setFilesScanned(count($filesToScan));
    }

    protected function scanBootstrapOrHelper(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for static variables in helper functions
            if (preg_match('/function\s+\w+\(/', $line)) {
                // Check next few lines for static variables
                $functionBlock = implode("\n", array_slice($lines, $lineNumber, 15));

                if (preg_match('/static\s+\$/', $functionBlock)) {
                    $this->addVulnerability(
                        'Static Variable in Helper Function',
                        VulnerabilitySeverity::CRITICAL,
                        'Helper function uses static variable. Static state persists across all requests in Octane, '.
                        'causing data to leak between users.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Remove static variables. Use cache or pass state explicitly. Never use static in helpers.',
                        []
                    );
                }
            }

            // Check for global variable usage
            if (preg_match('/\$GLOBALS\[/', $line)) {
                $this->addVulnerability(
                    'Global Variable Usage',
                    VulnerabilitySeverity::HIGH,
                    'Using $GLOBALS in bootstrap or helpers causes state to persist across requests.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use config(), cache(), or dependency injection instead of globals.',
                    []
                );
            }

            // Check for Auth/Request/Session in helpers
            if (preg_match('/Auth::(?:user|check|id)/', $line)) {
                $this->addVulnerability(
                    'Auth Facade in Helper',
                    VulnerabilitySeverity::MEDIUM,
                    'Helper function uses Auth facade. Ensure this is request-scoped, not cached.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Helper functions using Auth must be called per-request, not stored statically.',
                    []
                );
            }

            // Check for config caching in helpers
            if (preg_match('/if\s*\(\s*!\s*function_exists/', $line)) {
                // This is OK - just function definition guard
            } elseif (preg_match('/Cache::rememberForever/', $line)) {
                $this->addVulnerability(
                    'Permanent Cache in Helper',
                    VulnerabilitySeverity::MEDIUM,
                    'Helper uses Cache::rememberForever(). First request data cached permanently.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use time-limited cache or ensure cache key includes proper context.',
                    []
                );
            }

            // Check for middleware registration in bootstrap
            if (str_contains($file, 'bootstrap') && preg_match('/->middleware\(/', $line)) {
                // This is generally OK in bootstrap, but check for dynamic registration
                if (preg_match('/if\s*\(.*\)\s*{/', implode("\n", array_slice($lines, max(0, $lineNumber - 2), 5)))) {
                    $this->addVulnerability(
                        'Conditional Middleware Registration',
                        VulnerabilitySeverity::MEDIUM,
                        'Middleware is being registered conditionally. This may not work as expected in Octane.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Middleware should be registered unconditionally in bootstrap. Handle conditions inside middleware.',
                        []
                    );
                }
            }

            // Check for service provider registration with state
            if (str_contains($file, 'bootstrap') && preg_match('/\$app->register\(/', $line)) {
                $this->addVulnerability(
                    'Dynamic Service Provider Registration',
                    VulnerabilitySeverity::LOW,
                    'Service provider is being registered dynamically. Ensure this doesn\'t depend on request state.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Register providers in config/app.php or bootstrap/providers.php when possible.',
                    []
                );
            }

            // Check for route caching issues
            if (str_contains($file, 'bootstrap') && preg_match('/Route::(?:middleware|group)\(/', $line)) {
                $contextLines = array_slice($lines, max(0, $lineNumber - 3), 7);
                $context = implode("\n", $contextLines);

                if (preg_match('/Auth::/', $context) || preg_match('/request\(\)/', $context)) {
                    $this->addVulnerability(
                        'Request-Dependent Route Registration',
                        VulnerabilitySeverity::HIGH,
                        'Route registration depends on request state. Routes are cached in Octane workers.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Routes must be static. Move dynamic logic inside controllers or middleware.',
                        []
                    );
                }
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('bootstrap/app.php')) ||
               File::exists(base_path('app/Helpers.php')) ||
               File::exists(base_path('app/helpers.php'));
    }
}
