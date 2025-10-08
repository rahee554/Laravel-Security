<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class DependencyScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Dependency Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks for outdated and vulnerable dependencies';
    }

    protected function execute(): void
    {
        $packages = $this->composer->getInstalledPackages();
        $this->result->setFilesScanned(count($packages));

        foreach ($packages as $package) {
            $this->checkPackageSecurity($package);
        }
    }

    protected function checkPackageSecurity(array $package): void
    {
        $name = $package['name'] ?? 'unknown';
        $version = $package['version'] ?? 'unknown';

        // Check for known vulnerable patterns (simplified - in real implementation, query security advisory API)
        if (str_starts_with($version, 'dev-') || str_contains($version, '@dev')) {
            $this->addVulnerability(
                'Development Dependency in Production',
                VulnerabilitySeverity::MEDIUM,
                "Package '{$name}' is using a development version: {$version}",
                'composer.json',
                null,
                null,
                'Use stable versions in production.',
                ['package' => $name, 'version' => $version]
            );
        }
    }
}
