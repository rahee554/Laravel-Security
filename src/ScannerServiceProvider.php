<?php

namespace ArtflowStudio\Scanner;

use Illuminate\Support\ServiceProvider;
use ArtflowStudio\Scanner\Commands\ScanCommand;
use ArtflowStudio\Scanner\Commands\ScanLivewireCommand;
use ArtflowStudio\Scanner\Commands\ScanRateLimitCommand;
use ArtflowStudio\Scanner\Commands\ScanSecurityCommand;
use ArtflowStudio\Scanner\Commands\ScanDependenciesCommand;
use ArtflowStudio\Scanner\Commands\ScanConfigurationCommand;
use ArtflowStudio\Scanner\Commands\ScanAuthenticationCommand;
use ArtflowStudio\Scanner\Commands\GenerateReportCommand;

class ScannerServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(
            __DIR__.'/../config/scanner.php', 'scanner'
        );

        $this->app->singleton('scanner', function ($app) {
            return new Services\ScannerService($app);
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
                __DIR__.'/../config/scanner.php' => config_path('scanner.php'),
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
                GenerateReportCommand::class,
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
