<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Scanners\RateLimitScanner;
use ArtflowStudio\Scanner\Reports\ConsoleReport;

class ScanRateLimitCommand extends Command
{
    protected $signature = 'scan:rate-limit {--json : Output as JSON}';
    protected $description = 'Check routes for proper rate limiting';

    public function handle(RateLimitScanner $scanner): int
    {
        $this->info('🔍 Checking rate limiting...');
        
        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport();
            $this->line($report->generate(['rate-limit' => $result]));
        }

        return self::SUCCESS;
    }
}
