<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Scanners\DependencyScanner;
use ArtflowStudio\Scanner\Reports\ConsoleReport;

class ScanDependenciesCommand extends Command
{
    protected $signature = 'scan:dependencies {--json : Output as JSON}';
    protected $description = 'Check dependencies for security vulnerabilities';

    public function handle(DependencyScanner $scanner): int
    {
        $this->info('🔍 Scanning dependencies...');
        
        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport();
            $this->line($report->generate(['dependencies' => $result]));
        }

        return self::SUCCESS;
    }
}
