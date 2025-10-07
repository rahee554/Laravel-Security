<?php

namespace ArtflowStudio\Scanner\Services;

use Illuminate\Support\Facades\File;

class ComposerAnalyzerService
{
    protected array $composerData = [];
    protected array $composerLock = [];

    public function __construct()
    {
        $this->loadComposerFiles();
    }

    /**
     * Load composer.json and composer.lock
     */
    protected function loadComposerFiles(): void
    {
        $composerPath = base_path('composer.json');
        $lockPath = base_path('composer.lock');

        if (File::exists($composerPath)) {
            $this->composerData = json_decode(File::get($composerPath), true) ?? [];
        }

        if (File::exists($lockPath)) {
            $this->composerLock = json_decode(File::get($lockPath), true) ?? [];
        }
    }

    /**
     * Get all installed packages
     */
    public function getInstalledPackages(): array
    {
        return $this->composerLock['packages'] ?? [];
    }

    /**
     * Get package version
     */
    public function getPackageVersion(string $packageName): ?string
    {
        foreach ($this->getInstalledPackages() as $package) {
            if ($package['name'] === $packageName) {
                return $package['version'];
            }
        }

        return null;
    }

    /**
     * Check if package is installed
     */
    public function hasPackage(string $packageName): bool
    {
        return $this->getPackageVersion($packageName) !== null;
    }

    /**
     * Get required packages from composer.json
     */
    public function getRequiredPackages(): array
    {
        return array_merge(
            $this->composerData['require'] ?? [],
            $this->composerData['require-dev'] ?? []
        );
    }

    /**
     * Check if Livewire is installed
     */
    public function hasLivewire(): bool
    {
        return $this->hasPackage('livewire/livewire');
    }

    /**
     * Check if Sanctum is installed
     */
    public function hasSanctum(): bool
    {
        return $this->hasPackage('laravel/sanctum');
    }

    /**
     * Check if Passport is installed
     */
    public function hasPassport(): bool
    {
        return $this->hasPackage('laravel/passport');
    }

    /**
     * Get Laravel version
     */
    public function getLaravelVersion(): ?string
    {
        return $this->getPackageVersion('laravel/framework');
    }

    /**
     * Compare version
     */
    public function isVersionBelow(string $packageName, string $version): bool
    {
        $installedVersion = $this->getPackageVersion($packageName);

        if ($installedVersion === null) {
            return false;
        }

        return version_compare($installedVersion, $version, '<');
    }
}
