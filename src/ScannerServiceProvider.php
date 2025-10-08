<?php

namespace ArtflowStudio\Scanner;

use ArtflowStudio\Scanner\Commands\GenerateReportCommand;
use ArtflowStudio\Scanner\Commands\ScanAuthenticationCommand;
use ArtflowStudio\Scanner\Commands\ScanCommand;
use ArtflowStudio\Scanner\Commands\ScanConfigurationCommand;
use ArtflowStudio\Scanner\Commands\ScanCorsCommand;
use ArtflowStudio\Scanner\Commands\ScanDependenciesCommand;
use ArtflowStudio\Scanner\Commands\ScanFixCommand;
use ArtflowStudio\Scanner\Commands\ScanLivewireCommand;
use ArtflowStudio\Scanner\Commands\ScanPerformanceCommand;
use ArtflowStudio\Scanner\Commands\ScanRateLimitCommand;
use ArtflowStudio\Scanner\Commands\ScanRouteCommand;
use ArtflowStudio\Scanner\Commands\ScanSecurityCommand;
use ArtflowStudio\Scanner\Commands\ScanVendorCommand;
use Illuminate\Support\ServiceProvider;

class ScannerServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/laravel-security.php', 'scanner'
        );

        $this->app->singleton('scanner', function ($app) {
            return new Services\ScannerService($app);
        });

        $this->app->singleton('scanner.fixer', function ($app) {
            return new Services\FixerService;
        });
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            // Publish configuration
            $this->publishes([
                __DIR__.'/../config/laravel-security.php' => config_path('scanner.php'),
            ], 'scanner-config');

            // Register commands
            $this->commands([
                ScanCommand::class,
                ScanLivewireCommand::class,
                ScanRateLimitCommand::class,
                ScanSecurityCommand::class,
                ScanDependenciesCommand::class,
                ScanConfigurationCommand::class,
                ScanAuthenticationCommand::class,
                ScanCorsCommand::class,
                ScanRouteCommand::class,
                ScanVendorCommand::class,
                ScanPerformanceCommand::class,
                GenerateReportCommand::class,
                ScanFixCommand::class,
            ]);
        }
    }

    /**
     * Get the services provided by the provider.
     */
    public function provides(): array
    {
        return ['scanner'];
    }
}
