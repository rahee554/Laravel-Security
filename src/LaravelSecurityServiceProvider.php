<?php

namespace ArtflowStudio\LaravelSecurity;

use ArtflowStudio\LaravelSecurity\Commands\GenerateReportCommand;
use ArtflowStudio\LaravelSecurity\Commands\OctaneAnalyzeCommand;
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
use ArtflowStudio\LaravelSecurity\Http\Middleware\ConsoleStrictMiddleware;
use ArtflowStudio\LaravelSecurity\Support\BladeDirectives;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class LaravelSecurityServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        // Merge scanner configuration
        $this->mergeConfigFrom(
            __DIR__.'/../config/laravel-security.php', 'scanner'
        );

        // Merge console security configuration
        $this->mergeConfigFrom(
            __DIR__.'/../config/console-security.php', 'console-security'
        );

        // Register scanner service
        $this->app->singleton('scanner', function ($app) {
            return new Services\ScannerService($app);
        });

        // Register fixer service
        $this->app->singleton('scanner.fixer', function ($app) {
            return new Services\FixerService;
        });
    }

    /**
     * Bootstrap services.
    */
    public function boot(): void
    {
        // Register middleware aliases
        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('console.strict', ConsoleStrictMiddleware::class);

        // Register Blade directives
        BladeDirectives::register();

        // Load routes
        $this->loadRoutesFrom(__DIR__.'/../routes/console-security.php');

        // Load views
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'laravel-security');

        if ($this->app->runningInConsole()) {
            // Publish scanner configuration
            $this->publishes([
                __DIR__.'/../config/laravel-security.php' => config_path('scanner.php'),
            ], 'scanner-config');

            // Publish console security configuration
            $this->publishes([
                __DIR__.'/../config/console-security.php' => config_path('console-security.php'),
            ], 'console-security-config');

            // Publish views
            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/laravel-security'),
            ], 'console-security-views');

            // Publish JavaScript assets
            $this->publishes([
                __DIR__.'/../resources/js' => public_path('vendor/laravel-security/js'),
            ], 'console-security-assets');

            // Register scanner commands
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
                OctaneAnalyzeCommand::class,
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
