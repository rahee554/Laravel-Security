<?php

namespace ArtflowStudio\Scanner\Reports;

use ArtflowStudio\Scanner\Contracts\ReportGeneratorInterface;
use ArtflowStudio\Scanner\DTOs\ScanResult;

class HtmlReport implements ReportGeneratorInterface
{
    public function generate(array $results): string
    {
        $html = $this->generateHeader();
        $html .= $this->generateSummary($results);

        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $html .= $this->generateScannerSection($result);
            }
        }

        $html .= $this->generateFooter();

        return $html;
    }

    public function save(array $results, string $path): bool
    {
        $content = $this->generate($results);

        return file_put_contents($path, $content) !== false;
    }

    public function getExtension(): string
    {
        return 'html';
    }

    protected function generateHeader(): string
    {
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Scan Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #3490dc; padding-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0; }
        .summary-card { background: #f9f9f9; padding: 15px; border-radius: 5px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; font-size: 14px; color: #666; }
        .summary-card .count { font-size: 32px; font-weight: bold; margin: 0; }
        .critical { color: #e3342f; }
        .high { color: #f6993f; }
        .medium { color: #ffed4e; }
        .low { color: #3490dc; }
        .info { color: #38c172; }
        .scanner-section { margin: 30px 0; border: 1px solid #ddd; border-radius: 5px; overflow: hidden; }
        .scanner-header { background: #3490dc; color: white; padding: 15px; }
        .vulnerability { border-bottom: 1px solid #eee; padding: 15px; }
        .vulnerability:last-child { border-bottom: none; }
        .vulnerability-title { font-weight: bold; margin-bottom: 5px; }
        .vulnerability-meta { font-size: 13px; color: #666; margin: 5px 0; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .badge-critical { background: #e3342f; color: white; }
        .badge-high { background: #f6993f; color: white; }
        .badge-medium { background: #ffed4e; color: #333; }
        .badge-low { background: #3490dc; color: white; }
        .badge-info { background: #38c172; color: white; }
        .recommendation { background: #f0f9ff; border-left: 3px solid #3490dc; padding: 10px; margin: 10px 0; font-size: 13px; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 Security Vulnerability Scan Report</h1>
        <p style="color: #666;">Generated on: {$this->getDateTime()}</p>
HTML;
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

        return <<<HTML
        <div class="summary">
            <div class="summary-card">
                <h3>Total Issues</h3>
                <p class="count">{$totalVulnerabilities}</p>
            </div>
            <div class="summary-card">
                <h3>Files Scanned</h3>
                <p class="count">{$totalFiles}</p>
            </div>
            <div class="summary-card">
                <h3>🔴 Critical</h3>
                <p class="count critical">{$totalCounts['critical']}</p>
            </div>
            <div class="summary-card">
                <h3>🟠 High</h3>
                <p class="count high">{$totalCounts['high']}</p>
            </div>
            <div class="summary-card">
                <h3>🟡 Medium</h3>
                <p class="count medium">{$totalCounts['medium']}</p>
            </div>
            <div class="summary-card">
                <h3>🔵 Low</h3>
                <p class="count low">{$totalCounts['low']}</p>
            </div>
        </div>
HTML;
    }

    protected function generateScannerSection(ScanResult $result): string
    {
        $html = <<<HTML
        <div class="scanner-section">
            <div class="scanner-header">
                <h2 style="margin: 0;">{$result->getScannerName()}</h2>
                <p style="margin: 5px 0 0 0; opacity: 0.9;">{$result->getScannerDescription()}</p>
            </div>
            <div>
HTML;

        if (! $result->hasVulnerabilities()) {
            $html .= '<div class="vulnerability" style="color: #38c172; font-weight: bold;">✅ No vulnerabilities found</div>';
        } else {
            foreach ($result->getVulnerabilities() as $vulnerability) {
                $severityClass = "badge-{$vulnerability->severity->value}";
                $severity = strtoupper($vulnerability->severity->value);

                $html .= <<<HTML
                <div class="vulnerability">
                    <div class="vulnerability-title">
                        <span class="badge {$severityClass}">{$severity}</span>
                        {$vulnerability->title}
                    </div>
                    <div class="vulnerability-meta">📁 {$vulnerability->getLocation()}</div>
                    <div class="vulnerability-meta">{$vulnerability->description}</div>
HTML;

                if ($vulnerability->code) {
                    $html .= '<div class="vulnerability-meta"><code>'.htmlspecialchars($vulnerability->code).'</code></div>';
                }

                if ($vulnerability->recommendation) {
                    $html .= "<div class=\"recommendation\">💡 <strong>Recommendation:</strong> {$vulnerability->recommendation}</div>";
                }

                $html .= '</div>';
            }
        }

        $html .= '</div></div>';

        return $html;
    }

    protected function generateFooter(): string
    {
        return <<<'HTML'
    </div>
</body>
</html>
HTML;
    }

    protected function getDateTime(): string
    {
        return date('Y-m-d H:i:s');
    }
}
