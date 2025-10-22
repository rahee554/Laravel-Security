<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class SingletonScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Singleton Binding Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects singleton bindings that may cause issues with Laravel Octane';
    }

    protected function execute(): void
    {
        $serviceProviders = $this->fileSystem->getPhpFiles(['app/Providers']);

        foreach ($serviceProviders as $file) {
            $this->scanServiceProvider($file);
        }

        $this->result->setFilesScanned(count($serviceProviders));
    }

    protected function scanServiceProvider(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        // Patterns to detect singleton bindings
        $singletonPatterns = [
            '/\$this->app->singleton\s*\(/' => 'app()->singleton()',
            '/App::singleton\s*\(/' => 'App::singleton()',
            '/->singleton\s*\(/' => '->singleton()',
            '/\$app->singleton\s*\(/' => '$app->singleton()',
            '/bind\s*\([^,]+,\s*[^,]*shared:\s*true/' => 'bind(..., shared: true)',
        ];

        foreach ($lines as $lineNumber => $line) {
            foreach ($singletonPatterns as $pattern => $type) {
                if (preg_match($pattern, $line)) {
                    $this->checkSingletonUsage($file, $lineNumber + 1, trim($line), $type);
                }
            }
        }
    }

    protected function checkSingletonUsage(string $file, int $line, string $code, string $type): void
    {
        $riskyPatterns = [
            'request()' => 'Request data in singleton',
            'Auth::user()' => 'User authentication in singleton',
            'auth()->user()' => 'User authentication in singleton',
            'session()' => 'Session data in singleton',
            'Session::' => 'Session facade in singleton',
            'Request::' => 'Request facade in singleton',
            'DB::' => 'Database connection in singleton',
            'Cache::' => 'Cache facade in singleton',
            'config([' => 'Runtime config modification',
        ];

        // Read surrounding context (next 20 lines) to check for risky usage
        $content = file_get_contents($file);
        $allLines = explode("\n", $content);
        $contextLines = array_slice($allLines, $line - 1, 20);
        $context = implode("\n", $contextLines);

        foreach ($riskyPatterns as $pattern => $issue) {
            if (stripos($context, $pattern) !== false) {
                $this->addVulnerability(
                    "Risky Singleton: {$issue}",
                    VulnerabilitySeverity::HIGH,
                    "Singleton binding at line {$line} may use request-scoped data ({$pattern}). ".
                    'Singletons persist across requests in Octane, which can leak data between users.',
                    $file,
                    $line,
                    $code,
                    'Convert to scoped binding: $this->app->scoped() or use $this->app->bind() instead. '.
                    "Alternatively, ensure the singleton doesn't store request-specific state.",
                    ['binding_type' => $type, 'risky_pattern' => $pattern]
                );

                return; // Only report once per singleton
            }
        }

        // If no risky patterns found, report as info/warning
        $this->addVulnerability(
            'Singleton Binding Detected',
            VulnerabilitySeverity::MEDIUM,
            "Singleton binding found. Verify this service doesn't store request-specific state (user, session, request data, tenant info).",
            $file,
            $line,
            $code,
            'Review the singleton implementation. If it stores per-request data, convert to scoped binding: $this->app->scoped()',
            ['binding_type' => $type]
        );
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Providers'));
    }
}
