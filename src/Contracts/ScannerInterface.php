<?php

namespace ArtflowStudio\Scanner\Contracts;

use ArtflowStudio\Scanner\DTOs\ScanResult;

interface ScannerInterface
{
    /**
     * Get the name of the scanner
     */
    public function getName(): string;

    /**
     * Get the description of the scanner
     */
    public function getDescription(): string;

    /**
     * Run the security scan
     */
    public function scan(): ScanResult;

    /**
     * Check if the scanner is applicable for the current project
     */
    public function isApplicable(): bool;

    /**
     * Get the severity level of this scanner's focus area
     */
    public function getSeverityLevel(): string;
}
