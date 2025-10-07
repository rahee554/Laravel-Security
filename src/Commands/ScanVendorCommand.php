<?php

namespace ArtflowStudio\Scanner\Commands;

use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Scanners\VendorScanner;
use Illuminate\Console\Command;

class ScanVendorCommand extends Command
{
    protected $signature = 'scan:vendor {--json : Output as JSON}';

    protected $description = 'Deep scan vendor folder for vulnerabilities, outdated packages, and security issues';

    public function handle(VendorScanner $scanner): int
    {
        $this->info('🔍 Deep Scanning Vendor Folder & Dependencies...');
        $this->newLine();

        if (! $scanner->isApplicable()) {
            $this->warn('Vendor folder or composer.lock not found.');

            return self::FAILURE;
        }

        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport;
            $this->line($report->generate(['vendor' => $result]));
        }

        return self::SUCCESS;
    }
}
