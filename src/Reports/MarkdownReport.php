<?php

namespace ArtflowStudio\Scanner\Reports;

use ArtflowStudio\Scanner\Contracts\ReportGeneratorInterface;
use ArtflowStudio\Scanner\DTOs\ScanResult;

class MarkdownReport implements ReportGeneratorInterface
{
    public function generate(array $results): string
    {
        $md = "# 🔒 Security Vulnerability Scan Report\n\n";
        $md .= '**Generated:** '.date('Y-m-d H:i:s')."\n\n";
        $md .= "---\n\n";
        $md .= $this->generateSummary($results);
        $md .= "\n---\n\n";

        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $md .= $this->generateScannerSection($result);
            }
        }

        return $md;
    }

    public function save(array $results, string $path): bool
    {
        $content = $this->generate($results);

        return file_put_contents($path, $content) !== false;
    }

    public function getExtension(): string
    {
        return 'md';
    }

    protected function generateSummary(array $results): string
    {
        $totalCounts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
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

        return <<<MD
## 📊 Summary

| Metric | Count |
|--------|-------|
| **Total Vulnerabilities** | {$totalVulnerabilities} |
| **Files Scanned** | {$totalFiles} |
| 🔴 Critical | {$totalCounts['critical']} |
| 🟠 High | {$totalCounts['high']} |
| 🟡 Medium | {$totalCounts['medium']} |
| 🔵 Low | {$totalCounts['low']} |
| 🟢 Info | {$totalCounts['info']} |

MD;
    }

    protected function generateScannerSection(ScanResult $result): string
    {
        $md = "## 🔍 {$result->getScannerName()}\n\n";
        $md .= "*{$result->getScannerDescription()}*\n\n";

        if (! $result->hasVulnerabilities()) {
            $md .= "✅ **No vulnerabilities found**\n\n";

            return $md;
        }

        $md .= "**Found {$result->getTotalCount()} issue(s):**\n\n";

        foreach ($result->getVulnerabilities() as $vulnerability) {
            $emoji = $vulnerability->severity->getEmoji();
            $severity = strtoupper($vulnerability->severity->value);

            $md .= "### {$emoji} [{$severity}] {$vulnerability->title}\n\n";
            $md .= "- **File:** `{$vulnerability->getLocation()}`\n";
            $md .= "- **Issue:** {$vulnerability->description}\n";

            if ($vulnerability->code) {
                $md .= "- **Code:**\n  ```php\n  {$vulnerability->code}\n  ```\n";
            }

            if ($vulnerability->recommendation) {
                $md .= "- **💡 Recommendation:** {$vulnerability->recommendation}\n";
            }

            $md .= "\n";
        }

        return $md;
    }
}
