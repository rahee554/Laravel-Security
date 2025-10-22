<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class UnsafePackageScanner extends AbstractScanner
{
    // Packages known to have Octane compatibility issues
    protected array $unsafePackages = [
        'barryvdh/laravel-debugbar' => [
            'reason' => 'Debug bar uses static state and can leak between requests',
            'severity' => 'high',
            'recommendation' => 'Only use in local environment, disable in production. Consider Laravel Telescope instead.',
        ],
        'barryvdh/laravel-ide-helper' => [
            'reason' => 'IDE helper should only be used in development',
            'severity' => 'low',
            'recommendation' => 'Install with --dev flag only',
        ],
        'spatie/laravel-ignition' => [
            'reason' => 'Debug mode error page uses static state',
            'severity' => 'medium',
            'recommendation' => 'Ensure debug mode is disabled in production',
        ],
        'rap2hpoutre/laravel-log-viewer' => [
            'reason' => 'Log viewer may have memory issues with large logs',
            'severity' => 'medium',
            'recommendation' => 'Use external log management tools in production',
        ],
    ];

    public function getName(): string
    {
        return 'Unsafe Package Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects packages with known Octane compatibility issues';
    }

    protected function execute(): void
    {
        $composerLock = base_path('composer.lock');

        if (! file_exists($composerLock)) {
            return;
        }

        $lockData = json_decode(file_get_contents($composerLock), true);
        $installedPackages = array_merge(
            $lockData['packages'] ?? [],
            $lockData['packages-dev'] ?? []
        );

        $scannedCount = 0;

        foreach ($installedPackages as $package) {
            $packageName = $package['name'];

            if (isset($this->unsafePackages[$packageName])) {
                $info = $this->unsafePackages[$packageName];

                $severity = match ($info['severity']) {
                    'high' => VulnerabilitySeverity::HIGH,
                    'medium' => VulnerabilitySeverity::MEDIUM,
                    'low' => VulnerabilitySeverity::LOW,
                    default => VulnerabilitySeverity::MEDIUM,
                };

                $this->addVulnerability(
                    "Potentially Unsafe Package: {$packageName}",
                    $severity,
                    $info['reason'],
                    'composer.lock',
                    null,
                    "\"name\": \"{$packageName}\"",
                    $info['recommendation'],
                    [
                        'package' => $packageName,
                        'version' => $package['version'] ?? 'unknown',
                    ]
                );

                $scannedCount++;
            }
        }

        $this->result->setFilesScanned(count($installedPackages));
    }

    public function isApplicable(): bool
    {
        return file_exists(base_path('composer.lock'));
    }
}
