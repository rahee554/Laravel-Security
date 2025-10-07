<?php

namespace ArtflowStudio\Scanner\Services;

use ArtflowStudio\Scanner\DTOs\ScanResult;
use ArtflowStudio\Scanner\Fixers\CsrfFixerStrategy;
use ArtflowStudio\Scanner\Fixers\LivewireFixerStrategy;
use ArtflowStudio\Scanner\Fixers\SqlInjectionFixerStrategy;
use ArtflowStudio\Scanner\Fixers\XssFixerStrategy;
use Illuminate\Support\Facades\File;

class FixerService
{
    protected array $fixers = [];

    protected array $backupPaths = [];

    public function __construct()
    {
        $this->registerFixers();
    }

    /**
     * Register all available fixers
     */
    protected function registerFixers(): void
    {
        $this->fixers = [
            'livewire' => new LivewireFixerStrategy,
            'xss' => new XssFixerStrategy,
            'csrf' => new CsrfFixerStrategy,
            'sql-injection' => new SqlInjectionFixerStrategy,
        ];
    }

    /**
     * Count total fixable issues
     */
    public function countFixableIssues(array $results): int
    {
        $count = 0;

        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $fixable = $this->getFixableVulnerabilities($result);
                $count += count($fixable);
            }
        }

        return $count;
    }

    /**
     * Get vulnerabilities that can be auto-fixed
     */
    public function getFixableVulnerabilities(ScanResult $result): array
    {
        $fixable = [];

        foreach ($result->getVulnerabilities() as $vulnerability) {
            if ($this->canFix($vulnerability)) {
                $fixable[] = $vulnerability;
            }
        }

        return $fixable;
    }

    /**
     * Check if a vulnerability can be auto-fixed
     */
    protected function canFix($vulnerability): bool
    {
        $type = $vulnerability->metadata['type'] ?? null;

        // List of auto-fixable types
        $fixableTypes = [
            'missing_validation',
            'unescaped_output',
            'inline_handler',
            'missing_csrf',
            'raw_query',
        ];

        return in_array($type, $fixableTypes);
    }

    /**
     * Filter results by vulnerability type
     */
    public function filterByType(array $results, string $type): array
    {
        $filtered = [];

        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $vulnerabilities = array_filter(
                    $result->getVulnerabilities(),
                    fn ($v) => ($v->metadata['type'] ?? null) === $type
                );

                if (! empty($vulnerabilities)) {
                    $filtered[$scannerName] = $result;
                }
            }
        }

        return $filtered;
    }

    /**
     * Create backup of files before fixing
     */
    public function createBackup(): void
    {
        $backupDir = storage_path('scanner-backups/'.date('Y-m-d_H-i-s'));

        if (! File::exists($backupDir)) {
            File::makeDirectory($backupDir, 0755, true);
        }

        $this->backupPaths[] = $backupDir;
    }

    /**
     * Generate diff preview for changes
     */
    public function generateDiffPreview(ScanResult $result): array
    {
        $diffs = [];
        $fixableVulns = $this->getFixableVulnerabilities($result);

        foreach ($fixableVulns as $vulnerability) {
            $fixer = $this->getFixerForVulnerability($vulnerability);

            if ($fixer) {
                $diff = $fixer->previewFix($vulnerability);
                if ($diff) {
                    $diffs[] = $diff;
                }
            }
        }

        return $diffs;
    }

    /**
     * Fix vulnerabilities in a scan result
     */
    public function fixVulnerabilities(ScanResult $result, ?callable $progressCallback = null): array
    {
        $fixed = 0;
        $failed = 0;

        $fixableVulns = $this->getFixableVulnerabilities($result);

        foreach ($fixableVulns as $vulnerability) {
            try {
                if ($this->fixVulnerability($vulnerability)) {
                    $fixed++;
                } else {
                    $failed++;
                }
            } catch (\Exception $e) {
                $failed++;
            }

            if ($progressCallback) {
                $progressCallback();
            }
        }

        return [
            'fixed' => $fixed,
            'failed' => $failed,
        ];
    }

    /**
     * Fix a single vulnerability
     */
    protected function fixVulnerability($vulnerability): bool
    {
        $fixer = $this->getFixerForVulnerability($vulnerability);

        if (! $fixer) {
            return false;
        }

        return $fixer->fix($vulnerability);
    }

    /**
     * Get appropriate fixer for a vulnerability
     */
    protected function getFixerForVulnerability($vulnerability)
    {
        $type = $vulnerability->metadata['type'] ?? null;

        // Map vulnerability types to fixers
        $typeToFixer = [
            'missing_validation' => 'livewire',
            'unescaped_output' => 'xss',
            'inline_handler' => 'xss',
            'missing_csrf' => 'csrf',
            'raw_query' => 'sql-injection',
        ];

        $fixerName = $typeToFixer[$type] ?? null;

        return $fixerName && isset($this->fixers[$fixerName])
            ? $this->fixers[$fixerName]
            : null;
    }
}
