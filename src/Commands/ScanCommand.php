<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Services\ScannerService;
use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Reports\JsonReport;
use ArtflowStudio\Scanner\Reports\HtmlReport;
use ArtflowStudio\Scanner\Reports\MarkdownReport;

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

        if (!empty($this->option('scanners'))) {
            return $this->option('scanners');
        }

        // Interactive selection
        $availableScanners = $scannerService->getAvailableScanners();
        $choices = array_merge(['all' => 'All Scanners'], $availableScanners);

        $selected = $this->choice(
            'Which scanners would you like to run?',
            $choices,
            'all',
            null,
            true
        );

        if (in_array('all', $selected) || in_array('All Scanners', $selected)) {
            return $availableScanners;
        }

        return $selected;
    }

    protected function displayResults(array $results): void
    {
        $report = new ConsoleReport();
        $output = $report->generate($results);
        
        $this->line($output);
    }

    protected function saveReport(array $results): void
    {
        $format = $this->option('format');
        $outputPath = $this->option('output');

        $generator = match($format) {
            'json' => new JsonReport(),
            'html' => new HtmlReport(),
            'markdown' => new MarkdownReport(),
            default => new ConsoleReport(),
        };

        if ($generator->save($results, $outputPath)) {
            $this->info("\n✅ Report saved to: {$outputPath}");
        } else {
            $this->error("\n❌ Failed to save report to: {$outputPath}");
        }
    }
}
