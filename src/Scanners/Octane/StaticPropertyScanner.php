<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class StaticPropertyScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Static Property Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects static properties that persist state across requests in Octane';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForStaticProperties($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForStaticProperties(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        // Patterns for static properties
        $staticPatterns = [
            '/(?:public|protected|private)\s+static\s+\$\w+/' => 'static property',
            '/static\s+\$\w+\s*=/' => 'static variable initialization',
        ];

        foreach ($lines as $lineNumber => $line) {
            foreach ($staticPatterns as $pattern => $type) {
                if (preg_match($pattern, $line)) {
                    $this->checkStaticProperty($file, $lineNumber + 1, trim($line), $content);
                }
            }
        }
    }

    protected function checkStaticProperty(string $file, int $line, string $code, string $fullContent): void
    {
        // Check if file contains risky patterns
        $riskyPatterns = [
            'User' => 'User model/data',
            'Model::' => 'Eloquent model',
            'request' => 'Request data',
            'session' => 'Session data',
            'auth' => 'Authentication data',
            'tenant' => 'Tenant information',
            'cache' => 'Cached data',
            'collection' => 'Data collection',
        ];

        $severity = VulnerabilitySeverity::MEDIUM;
        $riskyFound = [];

        foreach ($riskyPatterns as $pattern => $description) {
            if (stripos($fullContent, $pattern) !== false) {
                $riskyFound[] = $description;
                $severity = VulnerabilitySeverity::HIGH;
            }
        }

        // Check for array or Collection type hints
        if (preg_match('/(array|Collection|Model)\s*\$/', $code)) {
            $severity = VulnerabilitySeverity::HIGH;
        }

        $description = 'Static property detected. Static properties persist across all requests in Octane, '.
                      'which can leak data between users or tenants.';

        if (! empty($riskyFound)) {
            $description .= ' This file contains: '.implode(', ', array_unique($riskyFound)).'.';
        }

        $this->addVulnerability(
            'Potentially Unsafe Static Property',
            $severity,
            $description,
            $file,
            $line,
            $code,
            'Remove static properties that hold request-specific data. Use instance properties instead. '.
            "If the static property is needed, clear it in Octane's 'tick' event: \$sandbox->dispatchEvent(new RequestHandled());",
            ['risky_patterns' => $riskyFound]
        );
    }
}
