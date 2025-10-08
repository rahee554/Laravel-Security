<?php

namespace ArtflowStudio\LaravelSecurity\Services;

use ArtflowStudio\LaravelSecurity\Contracts\ScannerInterface;
use ArtflowStudio\LaravelSecurity\Exceptions\ScannerException;
use ArtflowStudio\LaravelSecurity\Scanners\AuthenticationScanner;
use ArtflowStudio\LaravelSecurity\Scanners\AuthorizationScanner;
use ArtflowStudio\LaravelSecurity\Scanners\ConfigurationScanner;
use ArtflowStudio\LaravelSecurity\Scanners\ConsoleSecurityScanner;
use ArtflowStudio\LaravelSecurity\Scanners\CorsScanner;
use ArtflowStudio\LaravelSecurity\Scanners\CsrfScanner;
use ArtflowStudio\LaravelSecurity\Scanners\DataExposureScanner;
use ArtflowStudio\LaravelSecurity\Scanners\DependencyScanner;
use ArtflowStudio\LaravelSecurity\Scanners\FileSecurityScanner;
use ArtflowStudio\LaravelSecurity\Scanners\FunctionSecurityScanner;
use ArtflowStudio\LaravelSecurity\Scanners\LivewireScanner;
use ArtflowStudio\LaravelSecurity\Scanners\PerformanceScanner;
use ArtflowStudio\LaravelSecurity\Scanners\RateLimitScanner;
use ArtflowStudio\LaravelSecurity\Scanners\RouteSecurityScanner;
use ArtflowStudio\LaravelSecurity\Scanners\SqlInjectionScanner;
use ArtflowStudio\LaravelSecurity\Scanners\VendorScanner;
use ArtflowStudio\LaravelSecurity\Scanners\XssScanner;
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
