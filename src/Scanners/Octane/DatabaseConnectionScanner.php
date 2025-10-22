<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class DatabaseConnectionScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Database Connection Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects potential database connection leaks and long-running queries';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForDbIssues($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForDbIssues(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for manual DB::connection without proper cleanup
            if (preg_match('/DB::connection\s*\([\'"](\w+)[\'"]\)/', $line, $matches)) {
                // Check if disconnect() is called later
                if (! stripos($content, 'disconnect()')) {
                    $this->addVulnerability(
                        'Potential DB Connection Leak',
                        VulnerabilitySeverity::MEDIUM,
                        'Manual DB::connection() call found without corresponding disconnect(). '.
                        'In Octane, connections can leak if not properly closed.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Let Laravel manage connections automatically, or ensure disconnect() is called. '.
                        "Use try-finally blocks: try { DB::connection('x')->...; } finally { DB::disconnect('x'); }",
                        ['connection' => $matches[1] ?? 'unknown']
                    );
                }
            }

            // Check for DB inside loops (N+1 potential)
            if (preg_match('/(foreach|while|for)\s*\(/', $line)) {
                $contextStart = max(0, $lineNumber - 5);
                $contextEnd = min(count($lines), $lineNumber + 15);
                $loopContext = implode("\n", array_slice($lines, $contextStart, $contextEnd - $contextStart));

                if (preg_match('/DB::|->save\(\)|->update\(\)|->create\(\)|->delete\(\)/', $loopContext)) {
                    $this->addVulnerability(
                        'Database Query Inside Loop',
                        VulnerabilitySeverity::MEDIUM,
                        'Database operations detected inside a loop. This can cause N+1 query problems and memory issues in Octane.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use bulk operations: Model::insert(), updateOrCreate() with chunks, or eager loading. '.
                        'Consider using queued jobs for large batch operations.',
                        ['loop_type' => 'loop_with_db']
                    );
                }
            }
        }
    }
}
