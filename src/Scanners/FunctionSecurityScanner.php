<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class FunctionSecurityScanner extends AbstractScanner
{
    protected array $dangerousFunctions = [
        'eval', 'exec', 'system', 'shell_exec', 'passthru',
        'proc_open', 'popen', 'unserialize', 'assert', 'create_function',
    ];

    public function getName(): string
    {
        return 'Function Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects usage of dangerous PHP functions that can lead to code execution vulnerabilities';
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
            foreach ($this->dangerousFunctions as $function) {
                if (preg_match("/\\b{$function}\\s*\(/", $line)) {
                    $severity = $this->determineSeverity($function, $line);

                    $this->addVulnerability(
                        "Dangerous Function: {$function}()",
                        $severity,
                        "Usage of {$function}() detected. This function can lead to remote code execution if used with user input.",
                        $file,
                        $lineNum + 1,
                        trim($line),
                        $this->getRecommendation($function),
                        ['function' => $function, 'type' => 'dangerous_function']
                    );
                }
            }
        }
    }

    protected function determineSeverity(string $function, string $line): VulnerabilitySeverity
    {
        $criticalFunctions = ['eval', 'system', 'exec', 'shell_exec'];

        if (in_array($function, $criticalFunctions)) {
            return VulnerabilitySeverity::CRITICAL;
        }

        return VulnerabilitySeverity::HIGH;
    }

    protected function getRecommendation(string $function): string
    {
        return match ($function) {
            'eval' => 'Never use eval(). Refactor code to eliminate the need for dynamic code execution.',
            'unserialize' => 'Use JSON instead of serialize/unserialize, or validate data before unserializing.',
            'exec', 'system', 'shell_exec' => 'Avoid shell commands. If necessary, use Symfony Process component with strict input validation.',
            default => "Avoid using {$function}(). Look for safer alternatives.",
        };
    }
}
