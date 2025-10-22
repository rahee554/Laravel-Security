<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class GlobalPhpFunctionScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Global PHP Function Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects dangerous global PHP functions that persist state';
    }

    protected function execute(): void
    {
        $paths = ['app', 'bootstrap', 'routes'];

        $allFiles = [];
        foreach ($paths as $path) {
            if (File::exists(base_path($path))) {
                $allFiles = array_merge($allFiles, $this->fileSystem->getPhpFiles([$path]));
            }
        }

        foreach ($allFiles as $file) {
            $this->scanForGlobalFunctions($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForGlobalFunctions(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for date_default_timezone_set()
            if (preg_match('/date_default_timezone_set\(/', $line)) {
                $this->addVulnerability(
                    'date_default_timezone_set() Usage',
                    VulnerabilitySeverity::CRITICAL,
                    'date_default_timezone_set() changes global timezone for the worker process. '.
                    'First request timezone persists for all subsequent requests.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Set timezone in config/app.php or php.ini. Use Carbon::setLocale() for localization.',
                    []
                );
            }

            // Check for ini_set()
            if (preg_match('/ini_set\(/', $line)) {
                $this->addVulnerability(
                    'ini_set() Usage',
                    VulnerabilitySeverity::HIGH,
                    'ini_set() changes PHP configuration globally for the worker. Settings persist across requests.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Set PHP configuration in php.ini or use per-request alternatives.',
                    []
                );
            }

            // Check for putenv()
            if (preg_match('/putenv\(/', $line)) {
                $this->addVulnerability(
                    'putenv() Usage',
                    VulnerabilitySeverity::HIGH,
                    'putenv() modifies environment variables globally. Changes persist across requests.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use config() or store values in cache/session instead.',
                    []
                );
            }

            // Check for setlocale()
            if (preg_match('/setlocale\(/', $line)) {
                $this->addVulnerability(
                    'setlocale() Usage',
                    VulnerabilitySeverity::HIGH,
                    'setlocale() changes locale globally for the worker process.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use Carbon::setLocale() or pass locale explicitly to formatting functions.',
                    []
                );
            }

            // Check for error_reporting()
            if (preg_match('/error_reporting\(/', $line)) {
                $this->addVulnerability(
                    'error_reporting() Usage',
                    VulnerabilitySeverity::MEDIUM,
                    'error_reporting() changes error level globally for the worker.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Set error reporting in php.ini or use try-catch for error handling.',
                    []
                );
            }

            // Check for set_time_limit()
            if (preg_match('/set_time_limit\(/', $line)) {
                $this->addVulnerability(
                    'set_time_limit() Usage',
                    VulnerabilitySeverity::LOW,
                    'set_time_limit() may not work as expected in Octane. Worker timeout is managed separately.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Configure worker timeout in octane.php config file.',
                    []
                );
            }

            // Check for chdir()
            if (preg_match('/chdir\(/', $line)) {
                $this->addVulnerability(
                    'chdir() Usage',
                    VulnerabilitySeverity::HIGH,
                    'chdir() changes working directory globally for the worker process.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use absolute paths instead. Working directory changes persist across requests.',
                    []
                );
            }

            // Check for define() outside config
            if (preg_match('/define\([\'"](?!LARAVEL_START)/', $line) && ! str_contains($file, 'config')) {
                $this->addVulnerability(
                    'define() Constant Declaration',
                    VulnerabilitySeverity::MEDIUM,
                    'Defining constants at runtime can cause issues if executed multiple times per worker.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use config() for dynamic values or define constants in bootstrap/app.php.',
                    []
                );
            }

            // Check for register_shutdown_function() with state
            if (preg_match('/register_shutdown_function\(/', $line)) {
                $this->addVulnerability(
                    'register_shutdown_function() Usage',
                    VulnerabilitySeverity::MEDIUM,
                    'Shutdown functions persist in the worker. Registering on each request causes them to stack.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Register shutdown functions once in bootstrap, or use Laravel terminating callbacks.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app')) ||
               File::exists(base_path('bootstrap')) ||
               File::exists(base_path('routes'));
    }
}
