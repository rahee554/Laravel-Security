<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class PerformanceKillerScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Performance Killer Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects performance-killing patterns like sleep(), Model::all(), and unpaginated queries';
    }

    protected function execute(): void
    {
        $paths = ['app/Http/Controllers', 'app/Services', 'app/Livewire', 'app/Jobs'];

        $allFiles = [];
        foreach ($paths as $path) {
            if (File::exists(base_path($path))) {
                $allFiles = array_merge($allFiles, $this->fileSystem->getPhpFiles([$path]));
            }
        }

        foreach ($allFiles as $file) {
            $this->scanForPerformanceIssues($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForPerformanceIssues(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for sleep() or usleep()
            if (preg_match('/\b(?:sleep|usleep)\(/', $line)) {
                $this->addVulnerability(
                    'sleep() or usleep() Usage',
                    VulnerabilitySeverity::CRITICAL,
                    'sleep() blocks the entire Octane worker, preventing it from handling other requests. '.
                    'This dramatically reduces throughput.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use queued jobs for delayed execution, or implement non-blocking alternatives. '.
                    'Never sleep in request handlers.',
                    []
                );
            }

            // Check for Model::all() without chunking
            if (preg_match('/\w+::all\(\)/', $line) && ! preg_match('/->(?:take|limit|chunk|paginate)/', $line)) {
                $this->addVulnerability(
                    'Model::all() Without Limits',
                    VulnerabilitySeverity::HIGH,
                    'Calling ::all() loads entire table into memory. This causes memory exhaustion on large tables.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use ->paginate(), ->chunk(), ->lazy(), or add ->take() limit. Never load all records.',
                    []
                );
            }

            // Check for Model::get() in loops (N+1)
            if (preg_match('/->get\(\)/', $line)) {
                $contextLines = array_slice($lines, max(0, $lineNumber - 3), 7);
                $context = implode("\n", $contextLines);

                if (preg_match('/\b(?:foreach|for|while)\s*\(/', $context)) {
                    $this->addVulnerability(
                        'Query in Loop (N+1)',
                        VulnerabilitySeverity::HIGH,
                        'Executing queries inside loops causes N+1 problem. This multiplies database hits.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use eager loading: Model::with("relation")->get() or load relationships before loop.',
                        []
                    );
                }
            }

            // Check for DB::select without limit
            if (preg_match('/DB::select\([\'"]SELECT\s+\*\s+FROM/', $line) && ! preg_match('/LIMIT|TOP/', $line)) {
                $this->addVulnerability(
                    'SELECT * Without LIMIT',
                    VulnerabilitySeverity::HIGH,
                    'Raw SELECT * query without LIMIT can return massive result sets.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Add LIMIT clause or use query builder with ->take() or ->paginate().',
                    []
                );
            }

            // Check for count() on collections (should use query count)
            if (preg_match('/\$\w+->(?:get|all)\(\)->count\(\)/', $line)) {
                $this->addVulnerability(
                    'Collection count() Instead of Query count()',
                    VulnerabilitySeverity::MEDIUM,
                    'Loading all records to count them is inefficient. Database should count.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use ->count() directly on query: Model::where(...)->count() instead of ->get()->count().',
                    []
                );
            }

            // Check for multiple save() calls instead of bulk insert
            if (preg_match('/->save\(\)/', $line)) {
                $contextLines = array_slice($lines, max(0, $lineNumber - 3), 7);
                $context = implode("\n", $contextLines);

                if (preg_match('/\b(?:foreach|for|while)\s*\(/', $context)) {
                    $this->addVulnerability(
                        'Individual save() in Loop',
                        VulnerabilitySeverity::HIGH,
                        'Calling save() in a loop creates one query per iteration. Use bulk operations.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use Model::insert($array) or Model::upsert() for bulk operations.',
                        []
                    );
                }
            }

            // Check for file_get_contents on large files
            if (preg_match('/file_get_contents\(/', $line)) {
                $this->addVulnerability(
                    'file_get_contents() Usage',
                    VulnerabilitySeverity::MEDIUM,
                    'file_get_contents() loads entire file into memory. Dangerous for large files.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use Storage::readStream() for large files, or chunk read with fopen/fgets.',
                    []
                );
            }

            // Check for response()->download() without streaming
            if (preg_match('/response\(\)->download\(/', $line) && ! preg_match('/Storage::readStream|streamDownload/', $content)) {
                $this->addVulnerability(
                    'Non-Streaming File Download',
                    VulnerabilitySeverity::MEDIUM,
                    'Downloading large files without streaming loads entire file into memory.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use Storage::download() or response()->streamDownload() for large files.',
                    []
                );
            }

            // Check for implode on large arrays (potential memory issue)
            if (preg_match('/implode\([^,]+,\s*\$\w+->(?:pluck|get)/', $line)) {
                $this->addVulnerability(
                    'implode() on Large Query Result',
                    VulnerabilitySeverity::LOW,
                    'Using implode() on query results can consume excessive memory if result set is large.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Consider chunking data or using database aggregation functions.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Http/Controllers')) ||
               File::exists(base_path('app/Services')) ||
               File::exists(base_path('app/Livewire')) ||
               File::exists(base_path('app/Jobs'));
    }
}
