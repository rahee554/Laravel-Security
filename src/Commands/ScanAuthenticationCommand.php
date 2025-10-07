<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Scanners\AuthenticationScanner;
use ArtflowStudio\Scanner\Reports\ConsoleReport;

class ScanAuthenticationCommand extends Command
{
    protected $signature = 'scan:authentication {--json : Output as JSON}';
    protected $description = 'Check authentication and session security';

    public function handle(AuthenticationScanner $scanner): int
    {
        $this->info('🔍 Scanning authentication...');
        
        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport();
            $this->line($report->generate(['authentication' => $result]));
        }

        return self::SUCCESS;
    }
}
