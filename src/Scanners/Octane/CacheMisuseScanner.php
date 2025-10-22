<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;

class CacheMisuseScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Cache Misuse Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects caching patterns that may cause issues in Octane';
    }

    protected function execute(): void
    {
        $phpFiles = $this->fileSystem->getPhpFiles([
            'app',
        ]);

        foreach ($phpFiles as $file) {
            $this->scanFileForCacheIssues($file);
        }

        $this->result->setFilesScanned(count($phpFiles));
    }

    protected function scanFileForCacheIssues(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Cache::rememberForever without tenant context
            if (preg_match('/Cache::rememberForever\s*\(\s*[\'"]([^\'"]+)[\'"]/', $line, $matches)) {
                $cacheKey = $matches[1];

                // Check if key contains tenant or user context
                if (! preg_match('/tenant|user|{|:/', $cacheKey)) {
                    $this->addVulnerability(
                        'Cache Key Without Context',
                        VulnerabilitySeverity::HIGH,
                        "Cache key '{$cacheKey}' doesn't include tenant/user context. ".
                        'In multi-tenant apps, this will share data across all tenants.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        "Add tenant/user prefix to cache keys: Cache::rememberForever('tenant:'.tenant('id').\":{$cacheKey}\", ...)",
                        ['cache_key' => $cacheKey]
                    );
                }

                // Warning about rememberForever
                $this->addVulnerability(
                    'Cache::rememberForever Usage',
                    VulnerabilitySeverity::LOW,
                    'rememberForever() used. Ensure there is a way to invalidate this cache when data changes.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Consider using remember() with TTL instead, or implement cache invalidation logic.',
                    []
                );
            }

            // Cache used for runtime storage
            if (preg_match('/Cache::(put|set|add)\s*\([^)]*request\(/', $line)) {
                $this->addVulnerability(
                    'Caching Request Data',
                    VulnerabilitySeverity::MEDIUM,
                    'Storing request data in cache. Cache should not be used for per-request storage.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use session for user-specific data or database for persistence. Cache should be for computed/expensive operations.',
                    []
                );
            }

            // Same cache key used for different contexts
            if (preg_match('/Cache::(remember|get|put)\s*\(\s*[\'"](\w+)[\'"]/', $line, $matches)) {
                $key = $matches[2];

                // Very generic keys are suspicious
                if (in_array($key, ['data', 'items', 'list', 'users', 'records', 'result'])) {
                    $this->addVulnerability(
                        'Generic Cache Key',
                        VulnerabilitySeverity::MEDIUM,
                        "Cache key '{$key}' is too generic. This can cause collisions in multi-tenant or multi-context scenarios.",
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        "Use more specific cache keys: 'model_type:{$key}' or include context in the key.",
                        ['cache_key' => $key]
                    );
                }
            }

            // Cache inside loops
            if (preg_match('/(foreach|while|for)\s*\(/', $line)) {
                $contextStart = max(0, $lineNumber - 2);
                $contextEnd = min(count($lines), $lineNumber + 10);
                $loopContext = implode("\n", array_slice($lines, $contextStart, $contextEnd - $contextStart));

                if (preg_match('/Cache::(remember|get|put)/', $loopContext)) {
                    $this->addVulnerability(
                        'Cache Operations Inside Loop',
                        VulnerabilitySeverity::MEDIUM,
                        'Cache operations detected inside a loop. This can cause performance issues.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Cache all needed data before the loop, or use batch cache operations: Cache::many()',
                        []
                    );
                }
            }

            // No cache invalidation
            if (preg_match('/Cache::(remember|put|add)/', $line) && ! str_contains($content, 'Cache::forget')) {
                // Only warn once per file
                static $warnedFiles = [];
                if (! in_array($file, $warnedFiles)) {
                    $this->addVulnerability(
                        'No Cache Invalidation Found',
                        VulnerabilitySeverity::LOW,
                        'File uses Cache but doesn\'t contain any Cache::forget() calls. Verify cache invalidation is handled elsewhere.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Implement cache invalidation when underlying data changes: Cache::forget() or Cache::tags()->flush()',
                        []
                    );
                    $warnedFiles[] = $file;
                }
            }
        }
    }
}
