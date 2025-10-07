<?php

namespace ArtflowStudio\Scanner\Reports;

use ArtflowStudio\Scanner\Contracts\ReportGeneratorInterface;
use ArtflowStudio\Scanner\DTOs\ScanResult;

class JsonReport implements ReportGeneratorInterface
{
    public function generate(array $results): string
    {
        $data = [
            'scan_date' => date('Y-m-d H:i:s'),
            'scanner_version' => '1.0.0',
            'summary' => $this->generateSummary($results),
            'results' => [],
        ];

        foreach ($results as $scannerName => $result) {
            if ($result instanceof ScanResult) {
                $data['results'][$scannerName] = $result->toArray();
            }
        }

        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function save(array $results, string $path): bool
    {
        $content = $this->generate($results);

        return file_put_contents($path, $content) !== false;
    }

    public function getExtension(): string
    {
        return 'json';
    }

    protected function generateSummary(array $results): array
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

        return [
            'total_vulnerabilities' => $totalVulnerabilities,
            'total_files_scanned' => $totalFiles,
            'severity_counts' => $totalCounts,
        ];
    }
}
