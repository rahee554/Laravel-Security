<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Services\ScannerService;
use ArtflowStudio\Scanner\Reports\JsonReport;
use ArtflowStudio\Scanner\Reports\HtmlReport;
use ArtflowStudio\Scanner\Reports\MarkdownReport;

class GenerateReportCommand extends Command
{
    protected $signature = 'scan:report 
                            {format : Report format (json, html, markdown)}
                            {--output= : Output file path}
                            {--scanners=* : Scanners to include}';

    protected $description = 'Generate a vulnerability scan report in various formats';

    public function handle(ScannerService $scannerService): int
    {
        $format = $this->argument('format');
        $outputPath = $this->option('output') ?? storage_path("scanner-reports/report-" . date('Y-m-d-His') . ".{$format}");

        $scanners = $this->option('scanners') ?: $scannerService->getAvailableScanners();

        $this->info('🔍 Running scans...');
        
        $results = [];
        foreach ($scanners as $scannerName) {
            $scanner = $scannerService->getScanner($scannerName);
            if ($scanner->isApplicable()) {
                $this->line("  → {$scanner->getName()}");
                $results[$scannerName] = $scanner->scan();
            }
        }

        $this->info("\n📝 Generating {$format} report...");

        $generator = match($format) {
            'json' => new JsonReport(),
            'html' => new HtmlReport(),
            'markdown', 'md' => new MarkdownReport(),
            default => null,
        };

        if ($generator === null) {
            $this->error("Invalid format: {$format}. Supported formats: json, html, markdown");
            return self::FAILURE;
        }

        // Ensure directory exists
        $directory = dirname($outputPath);
        if (!is_dir($directory)) {
            mkdir($directory, 0755, true);
        }

        if ($generator->save($results, $outputPath)) {
            $this->info("\n✅ Report saved successfully:");
            $this->line("   📄 {$outputPath}");
            return self::SUCCESS;
        } else {
            $this->error("\n❌ Failed to save report.");
            return self::FAILURE;
        }
    }
}
