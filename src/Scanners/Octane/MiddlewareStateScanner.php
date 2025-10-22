<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class MiddlewareStateScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Middleware State Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects middleware using static properties or caching request data';
    }

    protected function execute(): void
    {
        if (! File::exists(base_path('app/Http/Middleware'))) {
            return;
        }

        $middlewareFiles = $this->fileSystem->getPhpFiles(['app/Http/Middleware']);

        foreach ($middlewareFiles as $file) {
            $this->scanMiddleware($file);
        }

        $this->result->setFilesScanned(count($middlewareFiles));
    }

    protected function scanMiddleware(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for static properties
            if (preg_match('/(?:private|protected|public)\s+static\s+\$/', $line)) {
                $this->addVulnerability(
                    'Static Property in Middleware',
                    VulnerabilitySeverity::CRITICAL,
                    'Middleware has a static property. Middleware instances are reused across requests in Octane, '.
                    'causing static properties to leak data between users.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Remove static properties. Use instance properties or pass data through the request.',
                    []
                );
            }

            // Check for storing request data in properties within handle()
            if (str_contains($line, '$this->') && (
                preg_match('/\$request->user\(\)/', $line) ||
                preg_match('/Auth::user\(\)/', $line) ||
                preg_match('/\$request->/', $line) ||
                preg_match('/session\(\)/', $line)
            )) {
                $this->addVulnerability(
                    'Storing Request Data in Middleware Property',
                    VulnerabilitySeverity::HIGH,
                    'Middleware is storing request data in an instance property. Middleware instances persist in Octane.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Do not store request data in middleware properties. Process data immediately and pass through.',
                    []
                );
            }

            // Check for caching in middleware
            if (preg_match('/Cache::(?:put|remember|forever)/', $line) && preg_match('/\$request/', $line)) {
                $this->addVulnerability(
                    'Caching Request Data in Middleware',
                    VulnerabilitySeverity::HIGH,
                    'Middleware is caching request-specific data. This can leak between users.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Do not cache request data in middleware. Use session for user-specific data.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Http/Middleware'));
    }
}
