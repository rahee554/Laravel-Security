<?php

namespace ArtflowStudio\Scanner\Commands;

use Illuminate\Console\Command;
use ArtflowStudio\Scanner\Scanners\LivewireScanner;
use ArtflowStudio\Scanner\Reports\ConsoleReport;

class ScanLivewireCommand extends Command
{
    protected $signature = 'scan:livewire {--json : Output as JSON}';
    protected $description = 'Scan Livewire components for security vulnerabilities';

    public function handle(LivewireScanner $scanner): int
    {
        $this->info('🔍 Scanning Livewire components...');
        
        if (!$scanner->isApplicable()) {
            $this->warn('Livewire is not installed in this project.');
            return self::FAILURE;
        }

        $result = $scanner->scan();

        if ($this->option('json')) {
            $this->line(json_encode($result->toArray(), JSON_PRETTY_PRINT));
        } else {
            $report = new ConsoleReport();
            $this->line($report->generate(['livewire' => $result]));
        }

        return self::SUCCESS;
    }
}
