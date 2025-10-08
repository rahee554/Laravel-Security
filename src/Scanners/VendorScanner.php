<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class VendorScanner extends AbstractScanner
{
    protected array $knownVulnerabilities = [];

    protected array $abandonedPackages = [
        'swiftmailer/swiftmailer' => 'symfony/mailer',
        'phpunit/php-token-stream' => 'nikic/php-parser',
        'fzaninotto/faker' => 'fakerphp/faker',
        'doctrine/cache' => 'psr/cache',
    ];

    public function getName(): string
    {
        return 'Vendor & Dependency Deep Scanner';
    }

    public function getDescription(): string
    {
        return 'Deep scans vendor folder, checks composer.lock for vulnerabilities, outdated packages, and abandoned dependencies';
    }

    public function isApplicable(): bool
    {
        return file_exists(base_path('vendor')) && file_exists(base_path('composer.lock'));
    }

    protected function execute(): void
    {
        $this->loadKnownVulnerabilities();
        $this->checkComposerLock();
        $this->checkAbandonedPackages();
        $this->checkOutdatedPackages();
        $this->checkVendorPermissions();
        $this->checkVendorFileIntegrity();
    }

    protected function loadKnownVulnerabilities(): void
    {
        // In production, this would load from a CVE database or security advisories API
        $this->knownVulnerabilities = [
            'laravel/framework' => [
                '<8.0.0' => 'CVE-2021-XXXX - SQL Injection vulnerability',
                '<9.0.0' => 'CVE-2022-XXXX - XSS vulnerability in Blade',
            ],
            'symfony/http-kernel' => [
                '<5.4.20' => 'CVE-2023-XXXX - HTTP Header Injection',
            ],
            'guzzlehttp/guzzle' => [
                '<7.4.5' => 'CVE-2022-31042 - Cookie injection',
            ],
        ];
    }

    protected function checkComposerLock(): void
    {
        $lockFile = base_path('composer.lock');

        if (! file_exists($lockFile)) {
            $this->addVulnerability(
                'Composer Lock File Missing',
                VulnerabilitySeverity::CRITICAL,
                'composer.lock file is missing. This means dependencies are not locked and may vary between environments.',
                base_path(),
                null,
                null,
                'Run: composer install to generate composer.lock',
                ['type' => 'missing_lock_file']
            );

            return;
        }

        $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

        $lockData = json_decode(file_get_contents($lockFile), true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->addVulnerability(
                'Corrupt Composer Lock File',
                VulnerabilitySeverity::HIGH,
                'composer.lock file is corrupt or contains invalid JSON.',
                $lockFile,
                null,
                null,
                'Delete composer.lock and run: composer install',
                ['type' => 'corrupt_lock_file']
            );

            return;
        }

        // Check platform requirements
        if (isset($lockData['platform'])) {
            $phpVersion = $lockData['platform']['php'] ?? null;

            if ($phpVersion && version_compare(PHP_VERSION, $phpVersion, '<')) {
                $this->addVulnerability(
                    'PHP Version Mismatch',
                    VulnerabilitySeverity::HIGH,
                    "composer.lock requires PHP {$phpVersion} but current version is ".PHP_VERSION,
                    $lockFile,
                    null,
                    null,
                    'Update PHP version or run composer update to match current PHP version',
                    ['type' => 'php_version_mismatch', 'required' => $phpVersion, 'current' => PHP_VERSION]
                );
            }
        }

        // Check packages for known vulnerabilities
        $packages = array_merge(
            $lockData['packages'] ?? [],
            $lockData['packages-dev'] ?? []
        );

        foreach ($packages as $package) {
            $name = $package['name'];
            $version = $package['version'];

            // Check against known vulnerabilities
            if (isset($this->knownVulnerabilities[$name])) {
                foreach ($this->knownVulnerabilities[$name] as $constraint => $cve) {
                    if ($this->matchesConstraint($version, $constraint)) {
                        $this->addVulnerability(
                            "Known Vulnerability in {$name}",
                            VulnerabilitySeverity::CRITICAL,
                            "Package {$name} version {$version} has a known vulnerability: {$cve}",
                            $lockFile,
                            null,
                            null,
                            "Update package: composer require {$name}:^latest",
                            ['type' => 'known_vulnerability', 'package' => $name, 'version' => $version, 'cve' => $cve]
                        );
                    }
                }
            }

            // Check for dev dependencies in production lock
            if (! isset($lockData['packages-dev']) || ! in_array($package, $lockData['packages-dev'])) {
                if (str_contains($name, 'phpunit') || str_contains($name, 'mockery') || str_contains($name, 'faker')) {
                    $this->addVulnerability(
                        'Development Package in Production Dependencies',
                        VulnerabilitySeverity::MEDIUM,
                        "Development package {$name} is listed in production dependencies.",
                        $lockFile,
                        null,
                        null,
                        "Move to require-dev: composer require --dev {$name}",
                        ['type' => 'dev_in_prod', 'package' => $name]
                    );
                }
            }

            // Check for old Laravel versions
            if ($name === 'laravel/framework') {
                $majorVersion = (int) explode('.', str_replace('v', '', $version))[0];

                if ($majorVersion < 10) {
                    $this->addVulnerability(
                        'Outdated Laravel Framework',
                        VulnerabilitySeverity::HIGH,
                        "Laravel {$version} is outdated. Consider upgrading to Laravel 10 or 11 for security updates.",
                        $lockFile,
                        null,
                        null,
                        'Upgrade Laravel: composer require laravel/framework:^11.0',
                        ['type' => 'outdated_laravel', 'version' => $version]
                    );
                }
            }
        }
    }

    protected function checkAbandonedPackages(): void
    {
        $lockFile = base_path('composer.lock');

        if (! file_exists($lockFile)) {
            return;
        }

        $lockData = json_decode(file_get_contents($lockFile), true);
        $packages = array_merge(
            $lockData['packages'] ?? [],
            $lockData['packages-dev'] ?? []
        );

        foreach ($packages as $package) {
            $name = $package['name'];

            if (isset($this->abandonedPackages[$name])) {
                $replacement = $this->abandonedPackages[$name];

                $this->addVulnerability(
                    "Abandoned Package: {$name}",
                    VulnerabilitySeverity::HIGH,
                    "Package {$name} is abandoned and no longer maintained. It may contain unpatched security vulnerabilities.",
                    $lockFile,
                    null,
                    null,
                    "Replace with maintained alternative: composer require {$replacement}",
                    ['type' => 'abandoned_package', 'package' => $name, 'replacement' => $replacement]
                );
            }

            // Check for packages marked as abandoned in composer.lock
            if (isset($package['abandoned']) && $package['abandoned'] === true) {
                $this->addVulnerability(
                    "Package Marked as Abandoned: {$name}",
                    VulnerabilitySeverity::MEDIUM,
                    "Package {$name} is marked as abandoned by its maintainers.",
                    $lockFile,
                    null,
                    null,
                    'Find a maintained alternative or fork and maintain it yourself',
                    ['type' => 'abandoned_package', 'package' => $name]
                );
            }
        }
    }

    protected function checkOutdatedPackages(): void
    {
        $composerFile = base_path('composer.json');

        if (! file_exists($composerFile)) {
            return;
        }

        $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

        $composerData = json_decode(file_get_contents($composerFile), true);
        $requires = $composerData['require'] ?? [];

        foreach ($requires as $package => $constraint) {
            // Check for wildcard constraints
            if ($constraint === '*' || $constraint === '@dev') {
                $this->addVulnerability(
                    "Unsafe Version Constraint: {$package}",
                    VulnerabilitySeverity::HIGH,
                    "Package {$package} uses unsafe version constraint '{$constraint}'. This can install unstable versions.",
                    $composerFile,
                    null,
                    null,
                    'Use specific version constraint: "^1.0" instead of "*"',
                    ['type' => 'unsafe_constraint', 'package' => $package, 'constraint' => $constraint]
                );
            }

            // Check for branch aliases (dev-master, dev-develop)
            if (str_starts_with($constraint, 'dev-')) {
                $this->addVulnerability(
                    "Development Branch Constraint: {$package}",
                    VulnerabilitySeverity::MEDIUM,
                    "Package {$package} uses development branch '{$constraint}'. This is unstable for production.",
                    $composerFile,
                    null,
                    null,
                    'Use tagged release: "^1.0" instead of "dev-master"',
                    ['type' => 'dev_branch', 'package' => $package, 'constraint' => $constraint]
                );
            }
        }
    }

    protected function checkVendorPermissions(): void
    {
        $vendorPath = base_path('vendor');

        if (! is_dir($vendorPath)) {
            return;
        }

        $perms = fileperms($vendorPath);
        $octal = substr(sprintf('%o', $perms), -4);

        // Check if vendor directory is writable by group/others
        if ($perms & 0x0010 || $perms & 0x0002) { // writable by group or others
            $this->addVulnerability(
                'Vendor Directory Has Insecure Permissions',
                VulnerabilitySeverity::MEDIUM,
                "Vendor directory has permissions {$octal} which allows writing by group or others.",
                $vendorPath,
                null,
                null,
                'Set proper permissions: chmod 755 vendor/',
                ['type' => 'vendor_permissions', 'permissions' => $octal]
            );
        }
    }

    protected function checkVendorFileIntegrity(): void
    {
        // Check for suspicious files in vendor
        $vendorPath = base_path('vendor');

        if (! is_dir($vendorPath)) {
            return;
        }

        $suspiciousFiles = [
            'shell.php',
            'backdoor.php',
            'c99.php',
            'r57.php',
            'webshell.php',
        ];

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($vendorPath, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::SELF_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $fileName = $file->getFilename();

                foreach ($suspiciousFiles as $suspicious) {
                    if (stripos($fileName, $suspicious) !== false) {
                        $this->addVulnerability(
                            'Suspicious File in Vendor Directory',
                            VulnerabilitySeverity::CRITICAL,
                            "Suspicious file '{$fileName}' found in vendor directory. This may indicate a compromised dependency.",
                            $file->getPathname(),
                            null,
                            null,
                            'Investigate immediately. Remove vendor/ and run composer install from scratch.',
                            ['type' => 'suspicious_vendor_file', 'file' => $file->getPathname()]
                        );
                    }
                }
            }
        }
    }

    protected function matchesConstraint(string $version, string $constraint): bool
    {
        // Simple constraint matching (in production, use composer/semver library)
        $version = str_replace('v', '', $version);

        if (str_starts_with($constraint, '<')) {
            $constraintVersion = str_replace(['<', '=', ' '], '', $constraint);

            return version_compare($version, $constraintVersion, '<');
        }

        return false;
    }
}
