<?php

namespace ArtflowStudio\LaravelSecurity\Commands;

use ArtflowStudio\LaravelSecurity\Scanners\Octane\BladeStateScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\BootstrapHelperScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\CacheMisuseScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\ConfigRuntimeScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\ContainerLoopScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\DatabaseConnectionScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\EventListenerDynamicScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\FacadeUsageScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\GlobalPhpFunctionScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\JobStateScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\LivewireLifecycleScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\LivewireOctaneScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\MemoryLeakScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\MiddlewareStateScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\ModelBootScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\PerformanceKillerScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\RateLimiterScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\SerializationScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\ServiceProviderStateScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\SingletonScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\StaticPropertyScanner;
use ArtflowStudio\LaravelSecurity\Scanners\Octane\UnsafePackageScanner;
use Illuminate\Console\Command;

class OctaneAnalyzeCommand extends Command
{
    protected $signature = 'af-octane:test 
                            {--json : Output results as JSON}
                            {--ci : CI mode - exit with error code if critical issues found}
                            {--fix : Apply automatic fixes where possible (not implemented yet)}
                            {--path= : Specific path to scan (default: app/)}';

    protected $description = 'Scan application for Laravel Octane unsafe code and stateful usage';

    protected array $scanners = [];

    protected array $results = [];

    protected float $startTime;

    protected int $totalFiles = 0;

    protected int $passedChecks = 0;

    protected int $warnings = 0;

    protected int $criticalIssues = 0;

    public function handle(): int
    {
        $this->startTime = microtime(true);

        $this->displayBanner();

        if ($this->option('fix')) {
            $this->warn('[WARNING] --fix flag is not yet implemented. Running in analysis mode only.');
            $this->newLine();
        }

        $this->info('Initializing Laravel Octane Safety Analyzer...');
        $this->newLine();

        // Initialize all scanners
        $this->initializeScanners();

        // Run all scans
        $this->runScans();

        // Display results
        if ($this->option('json')) {
            $this->outputJson();
        } else {
            $this->displayReport();
        }

        // CI mode - fail build if critical issues
        if ($this->option('ci') && $this->criticalIssues > 0) {
            $this->error("\n[FAILURE] Build failed due to {$this->criticalIssues} critical Octane safety issue(s).");

            return self::FAILURE;
        }

        return self::SUCCESS;
    }

    protected function displayBanner(): void
    {
        $this->newLine();
        $this->line('===============================================================');
        $this->line('                                                               ');
        $this->line('            Laravel Octane Safety Analyzer                    ');
        $this->line('                                                               ');
        $this->line('  Detect singleton misuse, static state, memory leaks,        ');
        $this->line('  and other Octane-incompatible patterns in your codebase     ');
        $this->line('                                                               ');
        $this->line('===============================================================');
        $this->newLine();
    }

    protected function initializeScanners(): void
    {
        $this->scanners = [
            // Core Octane Issues
            'singleton' => new SingletonScanner,
            'static_property' => new StaticPropertyScanner,
            'facade_usage' => new FacadeUsageScanner,
            'config_runtime' => new ConfigRuntimeScanner,
            'database_connection' => new DatabaseConnectionScanner,
            'unsafe_package' => new UnsafePackageScanner,
            'memory_leak' => new MemoryLeakScanner,
            'cache_misuse' => new CacheMisuseScanner,

            // Component-Specific Scanners
            'service_provider_state' => new ServiceProviderStateScanner,
            'middleware_state' => new MiddlewareStateScanner,
            'model_boot' => new ModelBootScanner,
            'job_state' => new JobStateScanner,

            // Livewire & Blade
            'livewire_octane' => new LivewireOctaneScanner,
            'livewire_lifecycle' => new LivewireLifecycleScanner,
            'blade_state' => new BladeStateScanner,

            // Event & Rate Limiting
            'event_listener_dynamic' => new EventListenerDynamicScanner,
            'rate_limiter' => new RateLimiterScanner,

            // Performance & Best Practices
            'global_php_function' => new GlobalPhpFunctionScanner,
            'container_loop' => new ContainerLoopScanner,
            'serialization' => new SerializationScanner,
            'performance_killer' => new PerformanceKillerScanner,
            'bootstrap_helper' => new BootstrapHelperScanner,
        ];

        $this->info('[OK] Loaded '.count($this->scanners).' scanner modules');
        $this->newLine();
    }

    protected function runScans(): void
    {
        $progressBar = $this->output->createProgressBar(count($this->scanners));
        $progressBar->setFormat(' %current%/%max% [%bar%] %percent:3s%% - %message%');
        $progressBar->setMessage('Starting...');
        $progressBar->start();

        foreach ($this->scanners as $key => $scanner) {
            $progressBar->setMessage('Scanning: '.$scanner->getName());

            if ($scanner->isApplicable()) {
                $result = $scanner->scan();
                $this->results[$key] = $result;

                $this->totalFiles += $result->getFilesScanned();

                $counts = $result->getCountBySeverity();
                $this->criticalIssues += $counts['critical'] + $counts['high'];
                $this->warnings += $counts['medium'] + $counts['low'];
                $this->passedChecks += ($result->getFilesScanned() > 0 && $result->getTotalCount() === 0) ? 1 : 0;
            }

            $progressBar->advance();
        }

        $progressBar->setMessage('Complete!');
        $progressBar->finish();
        $this->newLine(2);
    }

    protected function displayReport(): void
    {
        $executionTime = round(microtime(true) - $this->startTime, 2);

        $this->info('===============================================================');
        $this->info('                      SCAN SUMMARY                             ');
        $this->info('===============================================================');
        $this->newLine();

        $this->line("  Execution Time: <fg=cyan>{$executionTime}s</>");
        $this->line("  Files Scanned: <fg=cyan>{$this->totalFiles}</>");
        $this->line("  Passed Checks: <fg=green>{$this->passedChecks}</>");
        $this->line("  Warnings: <fg=yellow>{$this->warnings}</>");
        $this->line("  Critical Issues: <fg=red>{$this->criticalIssues}</>");
        $this->newLine();

        // Display detailed results for each scanner
        foreach ($this->results as $key => $result) {
            $this->displayScannerResult($result);
        }

        // Display recommendations
        $this->displayRecommendations();

        // Final summary
        $this->displayFinalSummary();
    }

    protected function displayScannerResult($result): void
    {
        $name = $result->getScannerName();
        $vulnerabilities = $result->getVulnerabilities();

        if (empty($vulnerabilities)) {
            $this->line("[OK] <fg=green>{$name}</>: No issues found");

            return;
        }

        $this->newLine();
        $this->line("<fg=cyan;options=bold>{$name}</>");
        $this->line(str_repeat('-', 60));

        foreach ($vulnerabilities as $vuln) {
            $severityColor = match ($vuln->severity->value) {
                'critical' => 'red',
                'high' => 'red',
                'medium' => 'yellow',
                'low' => 'yellow',
                default => 'white',
            };

            $icon = match ($vuln->severity->value) {
                'critical' => '[X]',
                'high' => '[!]',
                'medium' => '[*]',
                'low' => '[-]',
                default => '[.]',
            };

            $this->line("{$icon} <fg={$severityColor};options=bold>[".strtoupper($vuln->severity->value)."]</> {$vuln->title}");
            $this->line("    File: <fg=cyan>{$vuln->file}</>");

            if ($vuln->line) {
                $this->line("    Line: <fg=cyan>{$vuln->line}</>");
            }

            $this->line("    Description: {$vuln->description}");

            if ($vuln->code) {
                $this->line("    Code: <fg=gray>{$vuln->code}</>");
            }

            if ($vuln->recommendation) {
                $this->line("    Fix: <fg=green>{$vuln->recommendation}</>");
            }

            $this->newLine();
        }
    }

    protected function displayRecommendations(): void
    {
        $this->newLine();
        $this->info('===============================================================');
        $this->info('                     RECOMMENDATIONS                           ');
        $this->info('===============================================================');
        $this->newLine();

        $recommendations = [
            '  1. Run php artisan octane:status to check Octane health',
            '  2. Use php artisan octane:cache:warm before deployment',
            '  3. Test with OCTANE_WATCH_MODE=true in development',
            '  4. Monitor memory usage with octane:status regularly',
            '  5. Use scoped bindings instead of singletons where possible',
            '  6. Clear static properties in Octane tick/terminating events',
            '  7. Avoid storing models/users in static properties',
            '  8. Use tenant-aware cache keys for multi-tenant apps',
            '  9. Test under load to detect state leaks',
            '  10. Review Octane documentation: https://laravel.com/docs/octane',
        ];

        foreach ($recommendations as $rec) {
            $this->line($rec);
        }

        $this->newLine();
    }

    protected function displayFinalSummary(): void
    {
        // Collect detailed statistics by issue type
        $issueStats = $this->collectIssueStatistics();

        $this->info('===============================================================');
        $this->info('                   DETAILED ISSUE BREAKDOWN                    ');
        $this->info('===============================================================');
        $this->newLine();

        if (! empty($issueStats)) {
            // Sort by count descending
            arsort($issueStats);

            foreach ($issueStats as $issueType => $count) {
                $icon = $this->getIssueIcon($issueType);
                $color = $count >= 10 ? 'red' : ($count >= 5 ? 'yellow' : 'cyan');
                $this->line(sprintf('  %s <fg=%s>%-50s %3d issues</>', $icon, $color, $issueType, $count));
            }

            $this->newLine();
        }

        $this->info('===============================================================');
        $this->info('                       OVERALL STATISTICS                      ');
        $this->info('===============================================================');
        $this->newLine();

        $executionTime = round(microtime(true) - $this->startTime, 2);

        $this->line('  PERFORMANCE METRICS:');
        $this->line("    Execution Time:          <fg=cyan>{$executionTime}s</>");
        $this->line("    Files Scanned:           <fg=cyan>{$this->totalFiles}</>");
        $this->line('    Scanners Executed:       <fg=cyan>'.count($this->scanners).'</>');
        $this->newLine();

        $this->line('  ISSUE SUMMARY:');
        $this->line('    Total Issues Found:      <fg=cyan>'.($this->criticalIssues + $this->warnings).'</>');
        $this->line("    Critical/High Issues:    <fg=red>{$this->criticalIssues}</>");
        $this->line("    Medium/Low Warnings:     <fg=yellow>{$this->warnings}</>");
        $this->line("    Clean Scanners:          <fg=green>{$this->passedChecks}</>");
        $this->newLine();

        $this->info('===============================================================');
        $this->info('                        FINAL VERDICT                          ');
        $this->info('===============================================================');
        $this->newLine();

        if ($this->criticalIssues === 0 && $this->warnings === 0) {
            $this->line('  EXCELLENT! Your codebase appears Octane-safe!');
            $this->line('  No critical issues or warnings detected.');
        } elseif ($this->criticalIssues === 0) {
            $this->line('  GOOD! No critical issues found.');
            $this->line("  However, there are {$this->warnings} warning(s) to review.");
        } elseif ($this->criticalIssues < 5) {
            $this->line("  ATTENTION NEEDED! Found {$this->criticalIssues} critical issue(s).");
            $this->line('  Please address these before running with Octane.');
        } else {
            $this->line("  CRITICAL! Found {$this->criticalIssues} critical issue(s).");
            $this->line('  Your application is NOT ready for Octane.');
            $this->line('  Please fix all critical issues before deployment.');
        }

        $this->newLine();

        if ($this->criticalIssues > 0 || $this->warnings > 0) {
            $this->line('  Need help? Check out:');
            $this->line('    - Laravel Octane Docs: https://laravel.com/docs/octane');
            $this->line('    - Octane Best Practices: https://github.com/laravel/octane');
            $this->newLine();
        }
    }

    protected function collectIssueStatistics(): array
    {
        $stats = [];

        foreach ($this->results as $result) {
            foreach ($result->getVulnerabilities() as $vuln) {
                $issueType = $vuln->title;

                if (! isset($stats[$issueType])) {
                    $stats[$issueType] = 0;
                }

                $stats[$issueType]++;
            }
        }

        return $stats;
    }

    protected function getIssueIcon(string $issueType): string
    {
        $iconMap = [
            'Model::all() Without Limits' => '💾',
            'Heavy Query in mount()' => '⚡',
            'Database Query Inside Loop' => '🔄',
            'Static Property' => '📌',
            'Heavy Database Query in Blade @php' => '🎨',
            'Runtime Config Modification Detected' => '⚙️',
            'Unsafe Facade Usage' => '🚫',
            'Generic Cache Key' => '🗝️',
            'Cache Operations Inside Loop' => '🔁',
            'Caching Request Data' => '💰',
            'putenv() Usage' => '🌍',
            'Heavy Query in Livewire render()' => '🔌',
            'file_get_contents() Usage' => '📄',
            'Individual save() in Loop' => '💿',
            'Query in Loop (N+1)' => '🔃',
        ];

        foreach ($iconMap as $pattern => $icon) {
            if (str_contains($issueType, $pattern)) {
                return $icon;
            }
        }

        return '•';
    }

    protected function outputJson(): void
    {
        $output = [
            'summary' => [
                'execution_time' => round(microtime(true) - $this->startTime, 2),
                'files_scanned' => $this->totalFiles,
                'passed_checks' => $this->passedChecks,
                'warnings' => $this->warnings,
                'critical_issues' => $this->criticalIssues,
            ],
            'results' => [],
        ];

        foreach ($this->results as $key => $result) {
            $output['results'][$key] = [
                'name' => $result->getScannerName(),
                'description' => $result->getScannerDescription(),
                'scan_time' => $result->getScanTime(),
                'vulnerabilities' => array_map(function ($vuln) {
                    return [
                        'title' => $vuln->title,
                        'severity' => $vuln->severity->value,
                        'description' => $vuln->description,
                        'file' => $vuln->file,
                        'line' => $vuln->line,
                        'code' => $vuln->code,
                        'recommendation' => $vuln->recommendation,
                        'metadata' => $vuln->metadata,
                    ];
                }, $result->getVulnerabilities()),
            ];
        }

        $this->line(json_encode($output, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    }
}
