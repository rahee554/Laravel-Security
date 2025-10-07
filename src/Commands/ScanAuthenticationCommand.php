<?php

namespace ArtflowStudio\Scanner\Commands;

use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Scanners\AuthenticationScanner;
use Illuminate\Console\Command;

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
            $report = new ConsoleReport;
            $this->line($report->generate(['authentication' => $result]));
        }

        return self::SUCCESS;
    }
}
