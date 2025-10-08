<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class FileSecurityScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'File Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks file upload and file operation security';
    }

    protected function execute(): void
    {
        $files = $this->getFilesToScan();
        $this->result->setFilesScanned(count($files));

        foreach ($files as $file) {
            $this->scanFile($file);
        }
    }

    protected function scanFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            if (preg_match('/file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)/', $line)) {
                $this->addVulnerability(
                    'File Inclusion via User Input',
                    VulnerabilitySeverity::CRITICAL,
                    'file_get_contents() with user input can lead to local file inclusion attacks.',
                    $file,
                    $lineNum + 1,
                    trim($line),
                    'Validate and sanitize file paths. Use whitelisting.',
                    ['type' => 'file_inclusion']
                );
            }
        }
    }
}
