<?php

namespace ArtflowStudio\LaravelSecurity\Commands;

use ArtflowStudio\LaravelSecurity\Reports\ConsoleReport;
use ArtflowStudio\LaravelSecurity\Scanners\CsrfScanner;
use ArtflowStudio\LaravelSecurity\Scanners\FunctionSecurityScanner;
use ArtflowStudio\LaravelSecurity\Scanners\SqlInjectionScanner;
use ArtflowStudio\LaravelSecurity\Scanners\XssScanner;
use Illuminate\Console\Command;

class ScanSecurityCommand extends Command
{
    protected $signature = 'scan:security {--json : Output as JSON}';

    protected $description = 'Run comprehensive security scans (XSS, SQL Injection, CSRF, dangerous functions)';

    public function handle(): int
    {
        $this->info('🔍 Running security scans...');

        $scanners = [
            'function-security' => new FunctionSecurityScanner,
            'sql-injection' => new SqlInjectionScanner,
            'xss' => new XssScanner,
            'csrf' => new CsrfScanner,
        ];

        $results = [];

        foreach ($scanners as $name => $scanner) {
            $this->line("  → Scanning: {$scanner->getName()}");
            $results[$name] = $scanner->scan();
        }

        if ($this->option('json')) {
            $jsonData = [];
            foreach ($results as $name => $result) {
                $jsonData[$name] = $result->toArray();
            }
            $this->line(json_encode($jsonData, JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport;
            $this->line($report->generate($results));
        }

        return self::SUCCESS;
    }
}
