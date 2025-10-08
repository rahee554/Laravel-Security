<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\Analyzers\CodeAnalyzer;
use ArtflowStudio\LaravelSecurity\Contracts\ScannerInterface;
use ArtflowStudio\LaravelSecurity\DTOs\ScanResult;
use ArtflowStudio\LaravelSecurity\DTOs\Vulnerability;
use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Services\ComposerAnalyzerService;
use ArtflowStudio\LaravelSecurity\Services\FileSystemService;

abstract class AbstractScanner implements ScannerInterface
{
    protected FileSystemService $fileSystem;

    protected ComposerAnalyzerService $composer;

    protected CodeAnalyzer $codeAnalyzer;

    protected ScanResult $result;

    protected float $startTime;

    public function __construct()
    {
        $this->fileSystem = new FileSystemService;
        $this->composer = new ComposerAnalyzerService;
        $this->codeAnalyzer = new CodeAnalyzer;
    }

    /**
     * Run the scan
     */
    public function scan(): ScanResult
    {
        $this->startTime = microtime(true);
        $this->result = new ScanResult($this->getName(), $this->getDescription());

        $this->execute();

        $this->result->setScanTime(microtime(true) - $this->startTime);
        $this->result->sortBySeverity();

        return $this->result;
    }

    /**
     * Execute the scanning logic (to be implemented by child classes)
     */
    abstract protected function execute(): void;

    /**
     * Check if scanner is applicable for current project
     */
    public function isApplicable(): bool
    {
        return true;
    }

    /**
     * Get default severity level
     */
    public function getSeverityLevel(): string
    {
        return 'medium';
    }

    /**
     * Add vulnerability to results
     */
    protected function addVulnerability(
        string $title,
        VulnerabilitySeverity $severity,
        string $description,
        string $file,
        ?int $line = null,
        ?string $code = null,
        ?string $recommendation = null,
        array $metadata = []
    ): void {
        $vulnerability = Vulnerability::make(
            $title,
            $severity,
            $description,
            $this->fileSystem->getRelativePath($file),
            $line,
            $code,
            $recommendation,
            $metadata
        );

        $this->result->addVulnerability($vulnerability);
    }

    /**
     * Check if config option is enabled
     */
    protected function isConfigEnabled(string $key, bool $default = true): bool
    {
        return config("scanner.{$key}", $default);
    }

    /**
     * Get config value
     */
    protected function getConfig(string $key, mixed $default = null): mixed
    {
        return config("scanner.{$key}", $default);
    }

    /**
     * Get files to scan based on patterns
     */
    protected function getFilesToScan(array $patterns = ['*.php']): array
    {
        $scanPaths = $this->getConfig('scan_paths', ['app']);
        $excludePaths = $this->getConfig('exclude_paths', []);

        return $this->fileSystem->getPhpFiles($scanPaths, $excludePaths);
    }

    /**
     * Check if line contains pattern
     */
    protected function lineContainsPattern(string $line, array $patterns): bool
    {
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get code snippet around a line
     */
    protected function getCodeSnippet(string $filePath, int $line, int $context = 2): string
    {
        $lines = file($filePath);
        $start = max(0, $line - $context - 1);
        $end = min(count($lines), $line + $context);

        return implode('', array_slice($lines, $start, $end - $start));
    }
}
