<?php

namespace ArtflowStudio\Scanner\Commands;

use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Reports\HtmlReport;
use ArtflowStudio\Scanner\Reports\JsonReport;
use ArtflowStudio\Scanner\Reports\MarkdownReport;
use ArtflowStudio\Scanner\Services\ScannerService;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'scan 
                            {--scanners=* : Specific scanners to run}
                            {--all : Run all available scanners}
                            {--format=console : Report format (console, json, html, markdown)}
                            {--output= : Output file path}';

    protected $description = 'Interactive vulnerability scanner for Laravel applications';

    public function handle(ScannerService $scannerService): int
    {
        $this->displayBanner();

        $scanners = $this->selectScanners($scannerService);

        if (empty($scanners)) {
            $this->error('No scanners selected.');

            return self::FAILURE;
        }

        $this->info("\n🔍 Starting vulnerability scan...\n");

        $results = [];
        $progressBar = $this->output->createProgressBar(count($scanners));
        $progressBar->start();

        foreach ($scanners as $scannerName) {
            $scanner = $scannerService->getScanner($scannerName);

            if ($scanner->isApplicable()) {
                $results[$scannerName] = $scanner->scan();
            }

            $progressBar->advance();
        }

        $progressBar->finish();
        $this->newLine(2);

        $this->displayResults($results);

        if ($this->option('output')) {
            $this->saveReport($results);
        }

        return self::SUCCESS;
    }

    protected function displayBanner(): void
    {
        $this->info('╔══════════════════════════════════════════════════════════════╗');
        $this->info('║        Artflow Vulnerability Scanner v1.0.0                  ║');
        $this->info('╚══════════════════════════════════════════════════════════════╝');
        $this->newLine();
    }

    protected function selectScanners(ScannerService $scannerService): array
    {
        if ($this->option('all')) {
            return $scannerService->getAvailableScanners();
        }

        if (! empty($this->option('scanners'))) {
            return $this->option('scanners');
        }

        // Interactive selection with numbered menu
        $availableScanners = $scannerService->getAvailableScanners();

        $this->info('📋 Available Security Scanners:');
        $this->newLine();

        // Display menu with numbers
        $this->line('  [0] 🔍 All Scanners (Comprehensive Scan)');
        $index = 1;
        $scannerMap = [];

        foreach ($availableScanners as $key) {
            $displayName = ucwords(str_replace('-', ' ', $key));
            $this->line("  [{$index}] 🛡️  {$displayName}");
            $scannerMap[$index] = $key;
            $index++;
        }

        $this->newLine();

        $selection = $this->ask('Enter scanner number to run (0 for all)', '0');

        // Validate input
        if (! is_numeric($selection)) {
            $this->error('Invalid selection. Please enter a number.');

            return $this->selectScanners($scannerService);
        }

        $selection = (int) $selection;

        // Return all scanners if 0 selected
        if ($selection === 0) {
            return $availableScanners;
        }

        // Return selected scanner
        if (isset($scannerMap[$selection])) {
            return [$scannerMap[$selection]];
        }

        $this->error('Invalid selection. Please try again.');

        return $this->selectScanners($scannerService);
    }

    protected function displayResults(array $results): void
    {
        $report = new ConsoleReport;
        $output = $report->generate($results);

        $this->line($output);
    }

    protected function saveReport(array $results): void
    {
        $format = $this->option('format');
        $outputPath = $this->option('output');

        $generator = match ($format) {
            'json' => new JsonReport,
            'html' => new HtmlReport,
            'markdown' => new MarkdownReport,
            default => new ConsoleReport,
        };

        if ($generator->save($results, $outputPath)) {
            $this->info("\n✅ Report saved to: {$outputPath}");
        } else {
            $this->error("\n❌ Failed to save report to: {$outputPath}");
        }
    }
}
