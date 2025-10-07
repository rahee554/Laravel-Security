<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;

class ConsoleSecurityScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Console Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks Artisan commands for security vulnerabilities';
    }

    protected function execute(): void
    {
        $commandPath = base_path('app/Console/Commands');

        if (! is_dir($commandPath)) {
            return;
        }

        $files = $this->fileSystem->getPhpFiles(['app/Console/Commands'], []);
        $this->result->setFilesScanned(count($files));

        foreach ($files as $file) {
            $this->scanCommand($file);
        }
    }

    protected function scanCommand(string $file): void
    {
        $content = file_get_contents($file);

        if (str_contains($content, 'extends Command')) {
            $lines = explode("\n", $content);

            foreach ($lines as $lineNum => $line) {
                if (preg_match('/(exec|shell_exec|system)\s*\(/', $line)) {
                    $this->addVulnerability(
                        'Shell Command in Artisan Command',
                        VulnerabilitySeverity::HIGH,
                        'Artisan command uses shell execution. Ensure input is properly validated.',
                        $file,
                        $lineNum + 1,
                        trim($line),
                        'Use Symfony Process component with strict input validation.',
                        ['type' => 'shell_command']
                    );
                }
            }
        }
    }
}
