<?php

namespace ArtflowStudio\Scanner\DTOs;

class ScanResult
{
    /** @var Vulnerability[] */
    protected array $vulnerabilities = [];

    protected int $filesScanned = 0;

    protected float $scanTime = 0;

    protected array $metadata = [];

    public function __construct(
        protected string $scannerName,
        protected string $scannerDescription
    ) {}

    /**
     * Add a vulnerability to the results
     */
    public function addVulnerability(Vulnerability $vulnerability): self
    {
        $this->vulnerabilities[] = $vulnerability;

        return $this;
    }

    /**
     * Add multiple vulnerabilities
     */
    public function addVulnerabilities(array $vulnerabilities): self
    {
        foreach ($vulnerabilities as $vulnerability) {
            $this->addVulnerability($vulnerability);
        }

        return $this;
    }

    /**
     * Get all vulnerabilities
     */
    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    /**
     * Get vulnerabilities by severity
     */
    public function getVulnerabilitiesBySeverity(VulnerabilitySeverity $severity): array
    {
        return array_filter(
            $this->vulnerabilities,
            fn ($v) => $v->severity === $severity
        );
    }

    /**
     * Get count by severity
     */
    public function getCountBySeverity(): array
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($this->vulnerabilities as $vulnerability) {
            $counts[$vulnerability->severity->value]++;
        }

        return $counts;
    }

    /**
     * Get total vulnerability count
     */
    public function getTotalCount(): int
    {
        return count($this->vulnerabilities);
    }

    /**
     * Check if any vulnerabilities were found
     */
    public function hasVulnerabilities(): bool
    {
        return $this->getTotalCount() > 0;
    }

    /**
     * Set files scanned count
     */
    public function setFilesScanned(int $count): self
    {
        $this->filesScanned = $count;

        return $this;
    }

    /**
     * Get files scanned count
     */
    public function getFilesScanned(): int
    {
        return $this->filesScanned;
    }

    /**
     * Set scan time
     */
    public function setScanTime(float $time): self
    {
        $this->scanTime = $time;

        return $this;
    }

    /**
     * Get scan time
     */
    public function getScanTime(): float
    {
        return $this->scanTime;
    }

    /**
     * Set metadata
     */
    public function setMetadata(array $metadata): self
    {
        $this->metadata = $metadata;

        return $this;
    }

    /**
     * Get metadata
     */
    public function getMetadata(): array
    {
        return $this->metadata;
    }

    /**
     * Get scanner name
     */
    public function getScannerName(): string
    {
        return $this->scannerName;
    }

    /**
     * Get scanner description
     */
    public function getScannerDescription(): string
    {
        return $this->scannerDescription;
    }

    /**
     * Sort vulnerabilities by severity
     */
    public function sortBySeverity(): self
    {
        usort($this->vulnerabilities, function ($a, $b) {
            return $b->severity->getPriority() <=> $a->severity->getPriority();
        });

        return $this;
    }

    /**
     * Convert to array
     */
    public function toArray(): array
    {
        return [
            'scanner_name' => $this->scannerName,
            'scanner_description' => $this->scannerDescription,
            'total_vulnerabilities' => $this->getTotalCount(),
            'severity_counts' => $this->getCountBySeverity(),
            'files_scanned' => $this->filesScanned,
            'scan_time' => $this->scanTime,
            'vulnerabilities' => array_map(
                fn ($v) => $v->toArray(),
                $this->vulnerabilities
            ),
            'metadata' => $this->metadata,
        ];
    }
}
