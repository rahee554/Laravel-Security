<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class MemoryLeakScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Memory Leak Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects patterns that can cause memory leaks in Octane';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app/Services',
            'app/Helpers',
            'app/Support',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForMemoryLeaks($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForMemoryLeaks(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Static arrays that grow
            if (preg_match('/static\s+\$(\w+)\s*=\s*\[/', $line, $matches)) {
                $arrayName = $matches[1];

                // Check if array is appended to
                if (preg_match("/\\{$arrayName}\s*\[\s*\]\s*=/", $content) ||
                    preg_match("/\\{$arrayName}\s*\[\s*['\"]?\w+['\"]?\s*\]\s*=/", $content)) {
                    $this->addVulnerability(
                        'Growing Static Array',
                        VulnerabilitySeverity::HIGH,
                        "Static array \${$arrayName} is modified at runtime. In Octane, this array will grow indefinitely and cause memory leaks.",
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        "Use instance properties instead of static arrays, or implement a clearing mechanism in Octane's 'tick' event.",
                        ['array_name' => $arrayName]
                    );
                }
            }

            // Static caches without clearing
            if (preg_match('/static\s+\$cache/', $line) && ! str_contains($content, 'static::$cache = []')) {
                $this->addVulnerability(
                    'Static Cache Without Clearing',
                    VulnerabilitySeverity::HIGH,
                    'Static cache property detected without a clearing mechanism. This will grow indefinitely in Octane.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Add a method to clear the cache: public static function clearCache(): void { static::$cache = []; } '.
                    'Call this in Octane\'s tick event or use Laravel\'s Cache facade instead.',
                    []
                );
            }

            // Properties that accumulate data
            if (preg_match('/(protected|private)\s+array\s+\$(\w+)/', $line, $matches)) {
                $propertyName = $matches[2];

                // Check if property is appended to (signs of accumulation)
                if (str_contains($content, "\$this->{$propertyName}[] =") ||
                    str_contains($content, "array_push(\$this->{$propertyName}")) {
                    $this->addVulnerability(
                        'Accumulating Instance Property',
                        VulnerabilitySeverity::MEDIUM,
                        "Property \${$propertyName} accumulates data. In Octane, verify this is cleared between requests if the class is a singleton.",
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'If this class is registered as a singleton, implement a reset method and call it in Octane events. '.
                        'Or convert the singleton to a scoped binding.',
                        ['property' => $propertyName]
                    );
                }
            }

            // Large file operations without cleanup
            if (preg_match('/file_get_contents|fopen|file\(/', $line) && ! str_contains($content, 'unlink')) {
                $this->addVulnerability(
                    'File Operation Without Cleanup',
                    VulnerabilitySeverity::LOW,
                    'File operation detected. Ensure temporary files are cleaned up to prevent disk space leaks.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use try-finally blocks to ensure cleanup: finally { @unlink($tempFile); }',
                    []
                );
            }

            // Infinite loops or long-running operations
            if (preg_match('/while\s*\(\s*true\s*\)/', $line)) {
                $this->addVulnerability(
                    'Infinite Loop Detected',
                    VulnerabilitySeverity::HIGH,
                    'Infinite while(true) loop found. This will block the Octane worker indefinitely.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Avoid infinite loops in web requests. Use queued jobs with proper timeout limits instead.',
                    []
                );
            }
        }
    }
}
