<?php

namespace ArtflowStudio\Scanner\Contracts;

use ArtflowStudio\Scanner\DTOs\ScanResult;

interface ReportGeneratorInterface
{
    /**
     * Generate report from scan results
     */
    public function generate(array $results): string;

    /**
     * Save report to file
     */
    public function save(array $results, string $path): bool;

    /**
     * Get the file extension for this report type
     */
    public function getExtension(): string;
}
