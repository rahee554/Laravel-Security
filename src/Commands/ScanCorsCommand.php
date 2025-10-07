<?php

namespace ArtflowStudio\Scanner\Commands;

use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Scanners\CorsScanner;
use Illuminate\Console\Command;

class ScanCorsCommand extends Command
{
    protected $signature = 'scan:cors {--json : Output as JSON}';

    protected $description = 'Check CORS configuration and HTTP security headers';

    public function handle(CorsScanner $scanner): int
    {
        $this->info('🔍 Scanning CORS & HTTP Headers Security...');
        $this->newLine();

        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport;
            $this->line($report->generate(['cors' => $result]));
        }

        return self::SUCCESS;
    }
}
