<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class ConfigRuntimeScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Runtime Config Modification Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects config or environment modifications at runtime';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app',
            'routes',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForConfigChanges($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForConfigChanges(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        $configModificationPatterns = [
            '/config\s*\(\s*\[[^\]]+\]\s*\)/' => 'config([...]) - Setting config at runtime',
            '/Config::set\s*\(/' => 'Config::set() - Setting config at runtime',
            '/putenv\s*\(/' => 'putenv() - Modifying environment',
            '/\$_ENV\s*\[/' => '$_ENV[] assignment',
            '/\$_SERVER\s*\[/' => '$_SERVER[] assignment',
        ];

        foreach ($lines as $lineNumber => $line) {
            // Skip config files
            if (str_contains($file, '/config/')) {
                continue;
            }

            foreach ($configModificationPatterns as $pattern => $description) {
                if (preg_match($pattern, $line)) {
                    $this->addVulnerability(
                        'Runtime Config Modification Detected',
                        VulnerabilitySeverity::HIGH,
                        "{$description} found. In Octane, config changes persist across requests and affect all users. ".
                        'Config should only be set in config files, never at runtime.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Remove runtime config modifications. Use database, cache, or session for per-request values. '.
                        'Config should be immutable after bootstrap.',
                        ['pattern' => $description]
                    );
                }
            }
        }
    }
}
