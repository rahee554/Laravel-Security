<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class AuthorizationScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Authorization Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks for proper authorization in controllers and routes';
    }

    protected function execute(): void
    {
        $controllers = $this->fileSystem->getControllerFiles();
        $this->result->setFilesScanned(count($controllers));

        foreach ($controllers as $file) {
            $this->scanController($file);
        }
    }

    protected function scanController(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            if (preg_match('/public function (update|destroy|delete|edit)\s*\(/', $line)) {
                $methodContent = $this->getMethodBlock($lines, $lineNum);

                if (! str_contains($methodContent, '$this->authorize') &&
                    ! str_contains($methodContent, 'Gate::') &&
                    ! str_contains($methodContent, '->can(')) {

                    preg_match('/public function (\w+)/', $line, $matches);
                    $method = $matches[1] ?? 'unknown';

                    $this->addVulnerability(
                        'Missing Authorization Check',
                        VulnerabilitySeverity::HIGH,
                        "Controller method '{$method}' lacks authorization check.",
                        $file,
                        $lineNum + 1,
                        trim($line),
                        "Add authorization: \$this->authorize('update', \$model);",
                        ['method' => $method]
                    );
                }
            }
        }
    }

    protected function getMethodBlock(array $lines, int $startIdx): string
    {
        $content = '';
        $braceCount = 0;
        for ($i = $startIdx; $i < count($lines) && $i < $startIdx + 30; $i++) {
            $content .= $lines[$i];
            $braceCount += substr_count($lines[$i], '{') - substr_count($lines[$i], '}');
            if ($braceCount === 0 && str_contains($lines[$i], '}')) {
                break;
            }
        }

        return $content;
    }
}
