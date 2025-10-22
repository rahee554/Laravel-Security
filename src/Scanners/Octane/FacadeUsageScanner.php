<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class FacadeUsageScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Facade Usage Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects incorrect facade usage in constructors and boot methods';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForFacadeIssues($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForFacadeIssues(string $file): void
    {
        $content = file_get_contents($file);

        // Find __construct and boot methods
        $this->scanMethod($file, $content, '__construct', 'Constructor');
        $this->scanMethod($file, $content, 'public function boot', 'boot() method');
    }

    protected function scanMethod(string $file, string $content, string $methodSignature, string $methodName): void
    {
        // Find method position
        $methodPos = stripos($content, $methodSignature);
        if ($methodPos === false) {
            return;
        }

        // Extract method body (simplified - find next method or closing brace)
        $methodStart = $methodPos;
        $braceCount = 0;
        $inMethod = false;
        $methodEnd = strlen($content);

        for ($i = $methodPos; $i < strlen($content); $i++) {
            if ($content[$i] === '{') {
                $braceCount++;
                $inMethod = true;
            } elseif ($content[$i] === '}') {
                $braceCount--;
                if ($inMethod && $braceCount === 0) {
                    $methodEnd = $i;
                    break;
                }
            }
        }

        $methodBody = substr($content, $methodStart, $methodEnd - $methodStart);

        // Risky facades in constructors/boot
        $riskyFacades = [
            'Auth::user()' => 'Auth::user() called in '.$methodName,
            'auth()->user()' => 'auth()->user() called in '.$methodName,
            'auth()->' => 'Auth helper called in '.$methodName,
            'request()' => 'request() helper called in '.$methodName,
            'Request::' => 'Request facade called in '.$methodName,
            'session()' => 'session() helper called in '.$methodName,
            'Session::' => 'Session facade called in '.$methodName,
            'Cookie::' => 'Cookie facade called in '.$methodName,
        ];

        foreach ($riskyFacades as $pattern => $issue) {
            if (stripos($methodBody, $pattern) !== false) {
                // Find line number
                $lineNumber = substr_count(substr($content, 0, $methodPos), "\n") + 1;

                $this->addVulnerability(
                    "Unsafe Facade Usage: {$issue}",
                    VulnerabilitySeverity::HIGH,
                    "Using {$pattern} in {$methodName} will capture request-scoped data at boot time. ".
                    'In Octane, constructors and boot() methods run once and are shared across requests, '.
                    'causing all users to see the same cached data.',
                    $file,
                    $lineNumber,
                    substr($methodSignature, 0, 50),
                    "Move {$pattern} calls to instance methods that are called per-request. ".
                    'Never call Auth, Request, Session facades in constructors or boot().',
                    ['facade' => $pattern, 'method' => $methodName]
                );
            }
        }
    }
}
