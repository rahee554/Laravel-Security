<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class CsrfScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'CSRF Protection Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks for proper CSRF protection on forms and state-changing operations';
    }

    protected function execute(): void
    {
        $this->checkBladeFormsCsrf();
        $this->checkMiddlewareConfiguration();
    }

    protected function checkBladeFormsCsrf(): void
    {
        $scanPaths = $this->getConfig('scan_paths', ['resources/views']);
        $bladeFiles = $this->fileSystem->getBladeFiles($scanPaths, []);

        $this->result->setFilesScanned(count($bladeFiles));

        foreach ($bladeFiles as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNum => $line) {
                if (preg_match('/<form[^>]*method\s*=\s*["\']?(post|put|patch|delete)/i', $line)) {
                    // Check if @csrf is present in the next few lines
                    $formBlock = implode("\n", array_slice($lines, $lineNum, 20));

                    if (! str_contains($formBlock, '@csrf') && ! str_contains($formBlock, 'csrf_token()')) {
                        $this->addVulnerability(
                            'Form Missing CSRF Protection',
                            VulnerabilitySeverity::HIGH,
                            'HTML form with state-changing method lacks CSRF token. This allows CSRF attacks.',
                            $file,
                            $lineNum + 1,
                            trim($line),
                            'Add @csrf directive inside the form tag.',
                            ['type' => 'missing_csrf']
                        );
                    }
                }
            }
        }
    }

    protected function checkMiddlewareConfiguration(): void
    {
        $middlewarePath = base_path('app/Http/Middleware/VerifyCsrfToken.php');

        if (file_exists($middlewarePath)) {
            $content = file_get_contents($middlewarePath);

            // Check if $except array has entries
            if (preg_match('/protected\s+\$except\s*=\s*\[(.*?)\]/s', $content, $matches)) {
                if (! empty(trim($matches[1]))) {
                    $this->addVulnerability(
                        'CSRF Protection Disabled for Routes',
                        VulnerabilitySeverity::MEDIUM,
                        'Some routes are excluded from CSRF protection. Ensure these exclusions are intentional and secure.',
                        $middlewarePath,
                        null,
                        null,
                        'Only exclude routes that truly need to be excluded (e.g., webhooks with signature verification).',
                        ['type' => 'csrf_exceptions']
                    );
                }
            }
        }
    }
}
