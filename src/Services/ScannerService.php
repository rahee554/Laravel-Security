<?php

namespace ArtflowStudio\Scanner\Services;

use ArtflowStudio\Scanner\Contracts\ScannerInterface;
use ArtflowStudio\Scanner\Exceptions\ScannerException;
use ArtflowStudio\Scanner\Scanners\AuthenticationScanner;
use ArtflowStudio\Scanner\Scanners\AuthorizationScanner;
use ArtflowStudio\Scanner\Scanners\ConfigurationScanner;
use ArtflowStudio\Scanner\Scanners\ConsoleSecurityScanner;
use ArtflowStudio\Scanner\Scanners\CorsScanner;
use ArtflowStudio\Scanner\Scanners\CsrfScanner;
use ArtflowStudio\Scanner\Scanners\DataExposureScanner;
use ArtflowStudio\Scanner\Scanners\DependencyScanner;
use ArtflowStudio\Scanner\Scanners\FileSecurityScanner;
use ArtflowStudio\Scanner\Scanners\FunctionSecurityScanner;
use ArtflowStudio\Scanner\Scanners\LivewireScanner;
use ArtflowStudio\Scanner\Scanners\PerformanceScanner;
use ArtflowStudio\Scanner\Scanners\RateLimitScanner;
use ArtflowStudio\Scanner\Scanners\RouteSecurityScanner;
use ArtflowStudio\Scanner\Scanners\SqlInjectionScanner;
use ArtflowStudio\Scanner\Scanners\VendorScanner;
use ArtflowStudio\Scanner\Scanners\XssScanner;
use Illuminate\Foundation\Application;

class ScannerService
{
    protected array $scanners = [];

    public function __construct(protected Application $app)
    {
        $this->registerScanners();
    }

    /**
     * Register all available scanners
     */
    protected function registerScanners(): void
    {
        $this->scanners = [
            'livewire' => LivewireScanner::class,
            'rate-limit' => RateLimitScanner::class,
            'function-security' => FunctionSecurityScanner::class,
            'data-exposure' => DataExposureScanner::class,
            'console-security' => ConsoleSecurityScanner::class,
            'authentication' => AuthenticationScanner::class,
            'authorization' => AuthorizationScanner::class,
            'dependencies' => DependencyScanner::class,
            'configuration' => ConfigurationScanner::class,
            'xss' => XssScanner::class,
            'sql-injection' => SqlInjectionScanner::class,
            'file-security' => FileSecurityScanner::class,
            'csrf' => CsrfScanner::class,
            'cors' => CorsScanner::class,
            'route-security' => RouteSecurityScanner::class,
            'vendor' => VendorScanner::class,
            'performance' => PerformanceScanner::class,
        ];
    }

    /**
     * Get all available scanners
     */
    public function getAvailableScanners(): array
    {
        return array_keys($this->scanners);
    }

    /**
     * Get scanner instance
     */
    public function getScanner(string $name): ScannerInterface
    {
        if (! isset($this->scanners[$name])) {
            throw ScannerException::scannerNotFound($name);
        }

        return $this->app->make($this->scanners[$name]);
    }

    /**
     * Get multiple scanner instances
     */
    public function getScanners(array $names): array
    {
        $instances = [];

        foreach ($names as $name) {
            $instances[$name] = $this->getScanner($name);
        }

        return $instances;
    }

    /**
     * Get all scanner instances
     */
    public function getAllScanners(): array
    {
        return $this->getScanners($this->getAvailableScanners());
    }

    /**
     * Run specific scanners
     */
    public function runScanners(array $scannerNames): array
    {
        $results = [];

        foreach ($scannerNames as $name) {
            $scanner = $this->getScanner($name);

            if ($scanner->isApplicable()) {
                $results[$name] = $scanner->scan();
            }
        }

        return $results;
    }

    /**
     * Run all scanners
     */
    public function runAllScanners(): array
    {
        return $this->runScanners($this->getAvailableScanners());
    }
}
