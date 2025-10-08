<?php

namespace ArtflowStudio\LaravelSecurity\Commands;

use ArtflowStudio\LaravelSecurity\Services\FixerService;
use ArtflowStudio\LaravelSecurity\Services\ScannerService;
use Illuminate\Console\Command;

class ScanFixCommand extends Command
{
    protected $signature = 'scan:fix 
                            {--scanner= : Specific scanner to fix issues for}
                            {--type= : Specific vulnerability type to fix}
                            {--dry-run : Preview changes without applying them}
                            {--auto : Auto-fix without confirmation}
                            {--backup : Create backup before fixing}';

    protected $description = 'Automatically fix detected security vulnerabilities';

    public function handle(FixerService $fixerService, ScannerService $scannerService): int
    {
        $this->displayBanner();

        // Run scan first to get vulnerabilities
        $this->info('🔍 Scanning for vulnerabilities...');
        $scanners = $this->option('scanner')
            ? [$this->option('scanner')]
            : $scannerService->getAvailableScanners();

        $results = $scannerService->runScanners($scanners);

        // Count total fixable issues
        $fixableCount = $fixerService->countFixableIssues($results);

        if ($fixableCount === 0) {
            $this->info('✅ No fixable vulnerabilities found!');

            return self::SUCCESS;
        }

        $this->newLine();
        $this->info("📝 Found {$fixableCount} fixable issue(s)");
        $this->newLine();

        // Filter by type if specified
        $type = $this->option('type');
        if ($type) {
            $results = $fixerService->filterByType($results, $type);
        }

        // Show what will be fixed
        $this->displayFixPlan($results, $fixerService);

        // Dry run mode - just show what would be fixed
        if ($this->option('dry-run')) {
            $this->info("\n🔍 DRY RUN MODE - No changes will be made");
            $this->displayDiffPreview($results, $fixerService);

            return self::SUCCESS;
        }

        // Auto mode - fix without confirmation
        if (! $this->option('auto')) {
            if (! $this->confirm('Do you want to proceed with these fixes?', true)) {
                $this->warn('❌ Fix operation cancelled.');

                return self::SUCCESS;
            }
        }

        // Create backup if requested
        if ($this->option('backup')) {
            $this->info('💾 Creating backup...');
            $fixerService->createBackup();
            $this->info('✅ Backup created successfully');
        }

        // Apply fixes
        $this->info("\n🔧 Applying fixes...");
        $progressBar = $this->output->createProgressBar($fixableCount);

        $fixed = 0;
        $failed = 0;

        foreach ($results as $scannerName => $result) {
            $fixResult = $fixerService->fixVulnerabilities($result, function () use ($progressBar) {
                $progressBar->advance();
            });

            $fixed += $fixResult['fixed'];
            $failed += $fixResult['failed'];
        }

        $progressBar->finish();
        $this->newLine(2);

        // Display results
        $this->displayFixResults($fixed, $failed);

        return self::SUCCESS;
    }

    protected function displayBanner(): void
    {
        $this->info('╔══════════════════════════════════════════════════════════════╗');
        $this->info('║        Artflow Auto-Fix System v1.0.0                        ║');
        $this->info('╚══════════════════════════════════════════════════════════════╝');
        $this->newLine();
    }

    protected function displayFixPlan(array $results, FixerService $fixerService): void
    {
        $this->info('📋 Fix Plan:');
        $this->newLine();

        foreach ($results as $scannerName => $result) {
            $fixable = $fixerService->getFixableVulnerabilities($result);

            if (empty($fixable)) {
                continue;
            }

            $this->line("  🛡️  {$result->getScannerName()}: ".count($fixable).' issue(s)');

            // Group by file
            $fileGroups = [];
            foreach ($fixable as $vuln) {
                $file = $vuln->file;
                if (! isset($fileGroups[$file])) {
                    $fileGroups[$file] = [];
                }
                $fileGroups[$file][] = $vuln;
            }

            foreach ($fileGroups as $file => $vulns) {
                $this->line("     📁 {$file}: ".count($vulns).' fix(es)');
            }
        }

        $this->newLine();
    }

    protected function displayDiffPreview(array $results, FixerService $fixerService): void
    {
        $this->info('📄 Preview of changes:');
        $this->newLine();

        foreach ($results as $scannerName => $result) {
            $diffs = $fixerService->generateDiffPreview($result);

            foreach ($diffs as $diff) {
                $this->line("  📁 {$diff['file']}");
                $this->line("<fg=red>  - {$diff['old']}</>");
                $this->line("<fg=green>  + {$diff['new']}</>");
                $this->newLine();
            }
        }
    }

    protected function displayFixResults(int $fixed, int $failed): void
    {
        $this->info('╔══════════════════════════════════════════════════════════════╗');
        $this->info('║                     FIX RESULTS                              ║');
        $this->info('╚══════════════════════════════════════════════════════════════╝');
        $this->newLine();

        if ($fixed > 0) {
            $this->info("✅ Successfully fixed: {$fixed}");
        }

        if ($failed > 0) {
            $this->warn("⚠️  Failed to fix: {$failed}");
        }

        if ($fixed > 0 && $failed === 0) {
            $this->newLine();
            $this->info('🎉 All issues have been fixed successfully!');
            $this->info('💡 Run "php artisan scan --all" to verify.');
        }
    }
}
