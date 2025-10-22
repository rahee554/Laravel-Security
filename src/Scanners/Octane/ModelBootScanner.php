<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class ModelBootScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Model Boot Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects Model::booted() and boot() methods storing static data';
    }

    protected function execute(): void
    {
        if (! File::exists(base_path('app/Models'))) {
            return;
        }

        $modelFiles = $this->fileSystem->getPhpFiles(['app/Models']);

        foreach ($modelFiles as $file) {
            $this->scanModel($file);
        }

        $this->result->setFilesScanned(count($modelFiles));
    }

    protected function scanModel(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        $inBootedMethod = false;
        $inBootMethod = false;

        foreach ($lines as $lineNumber => $line) {
            // Track when we're inside booted() or boot() methods
            if (preg_match('/(?:protected|public)\s+static\s+function\s+booted\(\)/', $line)) {
                $inBootedMethod = true;
            } elseif (preg_match('/(?:protected|public)\s+static\s+function\s+boot\(\)/', $line)) {
                $inBootMethod = true;
            } elseif (preg_match('/^\s*}\s*$/', $line) && ($inBootedMethod || $inBootMethod)) {
                $inBootedMethod = false;
                $inBootMethod = false;
            }

            // If we're in boot/booted methods, check for dangerous patterns
            if ($inBootedMethod || $inBootMethod) {
                // Check for accessing Auth/request/session
                if (preg_match('/Auth::(?:user|check|id)/', $line)) {
                    $this->addVulnerability(
                        'Auth Access in Model Boot',
                        VulnerabilitySeverity::CRITICAL,
                        'Model boot/booted method accesses Auth. Boot methods run once per worker and persist '.
                        'the first request\'s user data for all subsequent requests.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Never access Auth, request, or session in Model::boot() or Model::booted(). '.
                        'Use model events or observers instead.',
                        []
                    );
                }

                if (preg_match('/request\(\)/', $line)) {
                    $this->addVulnerability(
                        'Request Access in Model Boot',
                        VulnerabilitySeverity::CRITICAL,
                        'Model boot/booted method accesses request(). This captures the first request and reuses it.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Do not access request() in boot methods. Use model events instead.',
                        []
                    );
                }

                if (preg_match('/session\(\)/', $line)) {
                    $this->addVulnerability(
                        'Session Access in Model Boot',
                        VulnerabilitySeverity::CRITICAL,
                        'Model boot/booted method accesses session(). Session data will leak between requests.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Do not access session in boot methods.',
                        []
                    );
                }

                // Check for storing data in static properties
                if (preg_match('/self::\$\w+\s*=/', $line) || preg_match('/static::\$\w+\s*=/', $line)) {
                    $this->addVulnerability(
                        'Static Property Assignment in Boot',
                        VulnerabilitySeverity::HIGH,
                        'Model boot/booted method assigns to static property. Static data persists across requests.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Avoid storing request-specific data in static properties within boot methods.',
                        []
                    );
                }

                // Check for Cache::rememberForever or Cache::forever
                if (preg_match('/Cache::(?:rememberForever|forever)/', $line)) {
                    $this->addVulnerability(
                        'Permanent Cache in Model Boot',
                        VulnerabilitySeverity::MEDIUM,
                        'Model boot method uses Cache::rememberForever(). First request data cached permanently.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use time-limited cache or request-scoped data instead.',
                        []
                    );
                }
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Models'));
    }
}
