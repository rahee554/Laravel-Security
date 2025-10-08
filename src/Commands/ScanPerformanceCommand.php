<?php

namespace ArtflowStudio\LaravelSecurity\Commands;

use ArtflowStudio\LaravelSecurity\Reports\ConsoleReport;
use ArtflowStudio\LaravelSecurity\Scanners\PerformanceScanner;
use Illuminate\Console\Command;

class ScanPerformanceCommand extends Command
{
    protected $signature = 'scan:performance {--json : Output as JSON}';

    protected $description = 'Scan for N+1 queries, memory issues, and performance bottlenecks';

    public function handle(PerformanceScanner $scanner): int
    {
        $this->info('⚡ Scanning for Performance Issues...');
        $this->newLine();

        if (! $scanner->isApplicable()) {
            $this->warn('No applicable files found for performance scanning.');

            return self::FAILURE;
        }

        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport;
            $this->line($report->generate(['performance' => $result]));
        }

        return self::SUCCESS;
    }
}
