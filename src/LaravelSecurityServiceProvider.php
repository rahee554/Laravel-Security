<?php

namespace ArtflowStudio\LaravelSecurity;

use ArtflowStudio\LaravelSecurity\Commands\GenerateReportCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanAuthenticationCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanConfigurationCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanCorsCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanDependenciesCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanFixCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanLivewireCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanPerformanceCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanRateLimitCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanRouteCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanSecurityCommand;
use ArtflowStudio\LaravelSecurity\Commands\ScanVendorCommand;
use Illuminate\Support\ServiceProvider;

class LaravelSecurityServiceProvider extends ServiceProvider
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
