<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class BladeStateScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Blade State Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects Blade templates with stateful issues';
    }

    protected function execute(): void
    {
        $bladeFiles = collect(File::allFiles(resource_path('views')))
            ->filter(fn ($file) => $file->getExtension() === 'php')
            ->map(fn ($file) => $file->getPathname())
            ->toArray();

        foreach ($bladeFiles as $file) {
            $this->scanBladeFile($file);
        }

        $this->result->setFilesScanned(count($bladeFiles));
    }

    protected function scanBladeFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for @php blocks with static variables
            if (preg_match('/@php/', $line)) {
                $phpBlockStart = $lineNumber;

                // Find the end of the @php block
                for ($i = $lineNumber; $i < count($lines); $i++) {
                    if (preg_match('/@endphp/', $lines[$i])) {
                        $phpBlock = implode("\n", array_slice($lines, $phpBlockStart, $i - $phpBlockStart + 1));

                        if (preg_match('/static\s+\$/', $phpBlock)) {
                            $this->addVulnerability(
                                'Static Variable in Blade @php Block',
                                VulnerabilitySeverity::MEDIUM,
                                'Static variables in @php blocks persist across requests in Octane.',
                                $file,
                                $lineNumber + 1,
                                '@php ... static $variable ...',
                                'Remove static variables from Blade. Move logic to controllers or view composers.',
                                []
                            );
                        }

                        // Check for heavy logic in @php blocks
                        if (preg_match('/->(?:get|all|count|pluck)\(\)/', $phpBlock)) {
                            $this->addVulnerability(
                                'Heavy Database Query in Blade @php',
                                VulnerabilitySeverity::HIGH,
                                '@php block contains database queries. This reduces performance and violates MVC.',
                                $file,
                                $lineNumber + 1,
                                'Database query in @php block',
                                'Move all database queries to controllers or view composers.',
                                []
                            );
                        }

                        break;
                    }
                }
            }

            // Check for @inject directive
            if (preg_match('/@inject\([\'"](\w+)[\'"]\s*,\s*[\'"]([^\'")]+)[\'"]\)/', $line, $matches)) {
                $this->addVulnerability(
                    '@inject Directive Usage',
                    VulnerabilitySeverity::MEDIUM,
                    '@inject resolves services on every render. In Octane, this can cache service instances incorrectly.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Inject dependencies in controller and pass to view, or use view composers.',
                    []
                );
            }

            // Check for global variables
            if (preg_match('/\$GLOBALS\[/', $line)) {
                $this->addVulnerability(
                    'Global Variable Usage in Blade',
                    VulnerabilitySeverity::HIGH,
                    'Using $GLOBALS in Blade templates can leak state between requests.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Pass data explicitly through controllers and view data instead of using globals.',
                    []
                );
            }

            // Check for heavy inline logic
            if (preg_match('/\{\{\s*.*(?:Model|DB)::(?:where|get|all|find)/', $line)) {
                $this->addVulnerability(
                    'Database Query in Blade Template',
                    VulnerabilitySeverity::HIGH,
                    'Blade template contains inline database queries. This violates MVC and reduces performance.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Move queries to controller and pass data to view.',
                    []
                );
            }

            // Check for Auth/Request/Session in Blade
            if (preg_match('/@(?:auth|guest)\s*\(\s*[\'"][^\'"]+[\'"]\s*\)/', $line)) {
                $this->addVulnerability(
                    'Auth Guard in Blade Directive',
                    VulnerabilitySeverity::LOW,
                    '@auth/@guest with specific guard may cache incorrectly in Octane if guard switches.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Verify guard context is always correct, or pass auth state from controller.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(resource_path('views'));
    }
}
