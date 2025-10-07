<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Scanners\ConfigurationScanner;
use ArtflowStudio\Scanner\Reports\ConsoleReport;

class ScanConfigurationCommand extends Command
{
    protected $signature = 'scan:configuration {--json : Output as JSON}';
    protected $description = 'Check application configuration for security issues';

    public function handle(ConfigurationScanner $scanner): int
    {
        $this->info('🔍 Scanning configuration...');
        
        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport();
            $this->line($report->generate(['configuration' => $result]));
        }

        return self::SUCCESS;
    }
}
