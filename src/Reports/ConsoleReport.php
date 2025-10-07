<?php

namespace ArtflowStudio\Scanner\Reports;

use ArtflowStudio\Scanner\Contracts\ReportGeneratorInterface;
use ArtflowStudio\Scanner\DTOs\ScanResult;

class ConsoleReport implements ReportGeneratorInterface
{
    public function generate(array $results): string
    {
        $output = [];
        
        $output[] = $this->generateHeader();
        
        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $output[] = $this->generateScannerSection($result);
            }
        }
        
        $output[] = $this->generateSummary($results);
        
        return implode("\n", $output);
    }

    public function save(array $results, string $path): bool
    {
        $content = $this->generate($results);
        return file_put_contents($path, strip_tags($content)) !== false;
    }

    public function getExtension(): string
    {
        return 'txt';
    }

    protected function generateHeader(): string
    {
        return <<<HEADER
╔══════════════════════════════════════════════════════════════╗
║        Artflow Vulnerability Scanner v1.0.0                  ║
╚══════════════════════════════════════════════════════════════╝

HEADER;
    }

    protected function generateScannerSection(ScanResult $result): string
    {
        $output = [];
        
        $output[] = "\n🔍 {$result->getScannerName()}";
        $output[] = str_repeat("━", 70);
        $output[] = "{$result->getDescription()}\n";
        
        if (!$result->hasVulnerabilities()) {
            $output[] = "✅ No vulnerabilities found\n";
            return implode("\n", $output);
        }

        $output[] = "Found {$result->getTotalCount()} issue(s):\n";
        
        foreach ($result->getVulnerabilities() as $vulnerability) {
            $output[] = $this->formatVulnerability($vulnerability);
        }
        
        return implode("\n", $output);
    }

    protected function formatVulnerability($vulnerability): string
    {
        $emoji = $vulnerability->severity->getEmoji();
        $severity = strtoupper($vulnerability->severity->value);
        
        $output = [];
        $output[] = "\n{$emoji} [{$severity}] {$vulnerability->title}";
        $output[] = "  📁 File: {$vulnerability->getLocation()}";
        $output[] = "  📝 Issue: {$vulnerability->description}";
        
        if ($vulnerability->code) {
            $output[] = "  💻 Code: {$vulnerability->code}";
        }
        
        if ($vulnerability->recommendation) {
            $output[] = "  💡 Fix: {$vulnerability->recommendation}";
        }
        
        return implode("\n", $output);
    }

    protected function generateSummary(array $results): string
    {
        $totalCounts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        $totalVulnerabilities = 0;
        $totalFiles = 0;

        foreach ($results as $result) {
            if ($result instanceof ScanResult) {
                $counts = $result->getCountBySeverity();
                foreach ($counts as $severity => $count) {
                    $totalCounts[$severity] += $count;
                }
                $totalVulnerabilities += $result->getTotalCount();
                $totalFiles += $result->getFilesScanned();
            }
        }

        return <<<SUMMARY

╔══════════════════════════════════════════════════════════════╗
║                         SUMMARY                              ║
╚══════════════════════════════════════════════════════════════╝

Total Vulnerabilities: {$totalVulnerabilities}
Files Scanned: {$totalFiles}

Severity Breakdown:
  🔴 Critical: {$totalCounts['critical']}
  🟠 High:     {$totalCounts['high']}
  🟡 Medium:   {$totalCounts['medium']}
  🔵 Low:      {$totalCounts['low']}
  🟢 Info:     {$totalCounts['info']}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY;
    }
}
