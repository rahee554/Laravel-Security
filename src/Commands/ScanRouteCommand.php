<?php

namespace ArtflowStudio\Scanner\Commands;

use ArtflowStudio\Scanner\Reports\ConsoleReport;
use ArtflowStudio\Scanner\Scanners\RouteSecurityScanner;
use Illuminate\Console\Command;

class ScanRouteCommand extends Command
{
    protected $signature = 'scan:route {--json : Output as JSON}';

    protected $description = 'Check route security, middleware, closures, and endpoint protection';

    public function handle(RouteSecurityScanner $scanner): int
    {
        $this->info('🔍 Scanning Route & Endpoint Security...');
        $this->newLine();

        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport;
            $this->line($report->generate(['route-security' => $result]));
        }

        return self::SUCCESS;
    }
}
