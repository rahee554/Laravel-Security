<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class JobStateScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Job State Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects queued jobs with stateful issues';
    }

    protected function execute(): void
    {
        if (! File::exists(base_path('app/Jobs'))) {
            return;
        }

        $jobFiles = $this->fileSystem->getPhpFiles(['app/Jobs']);

        foreach ($jobFiles as $file) {
            $this->scanJobFile($file);
        }

        $this->result->setFilesScanned(count($jobFiles));
    }

    protected function scanJobFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        $hasQueue = str_contains($content, 'ShouldQueue');
        $hasUnique = str_contains($content, 'ShouldBeUnique');
        $inConstructor = false;

        // Check for static properties and constructor issues
        foreach ($lines as $lineNumber => $line) {
            // Track constructor
            if (preg_match('/(?:public|protected)\s+function\s+__construct\(/', $line)) {
                $inConstructor = true;
            } elseif ($inConstructor && preg_match('/^\s*}\s*$/', $line)) {
                $inConstructor = false;
            }

            if (preg_match('/(?:public|protected|private)\s+static\s+\$/', $line)) {
                $this->addVulnerability(
                    'Static Property in Job Class',
                    VulnerabilitySeverity::HIGH,
                    'Static properties in job classes persist across job executions in Octane.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use instance properties instead. Static state will leak between jobs.',
                    []
                );
            }

            // Check for Auth::user() in constructor
            if ($inConstructor && preg_match('/Auth::(?:user|id|check)/', $line)) {
                $this->addVulnerability(
                    'Auth Access in Job Constructor',
                    VulnerabilitySeverity::CRITICAL,
                    'Job constructor accesses Auth. This captures the auth state when job is dispatched, '.
                    'which may be stale when job executes. In Octane, this can leak between users.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Pass user ID explicitly to constructor: new MyJob($request->user()->id). '.
                    'Fetch fresh user data in handle() method.',
                    []
                );
            }

            // Check for request() in constructor
            if ($inConstructor && preg_match('/request\(\)/', $line)) {
                $this->addVulnerability(
                    'Request Access in Job Constructor',
                    VulnerabilitySeverity::HIGH,
                    'Job constructor accesses request(). Request will be different when job executes.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Extract needed request data explicitly and pass to constructor.',
                    []
                );
            }

            // Check for storing models in properties (outside __construct)
            if (preg_match('/public\s+\$\w+;\s*$/', $line)) {
                $this->addVulnerability(
                    'Public Property in Job',
                    VulnerabilitySeverity::LOW,
                    'Job has public properties. Verify these are serializable and don\'t hold large objects.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Consider using constructor property promotion and ensure properties are serializable.',
                    []
                );
            }
        }

        // Check handle() method for issues
        if (preg_match('/public function handle\s*\(\s*\)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $handlePos = $matches[0][1];
            $handleMethod = $this->extractMethod($content, $handlePos);

            // Check for storing data in $this->property inside handle()
            if (preg_match('/\$this->(\w+)\s*=/', $handleMethod)) {
                $lineNumber = substr_count(substr($content, 0, $handlePos), "\n") + 1;

                $this->addVulnerability(
                    'State Storage in Job handle() Method',
                    VulnerabilitySeverity::MEDIUM,
                    'Job handle() method stores data in instance properties. This can cause memory issues in Octane.',
                    $file,
                    $lineNumber,
                    'public function handle()',
                    'Use local variables instead of instance properties inside handle(). Keep jobs stateless.',
                    []
                );
            }
        }

        // Check if long-running job doesn't use queues
        if (! $hasQueue && (
            str_contains($content, 'sleep(') ||
            str_contains($content, 'usleep(') ||
            str_contains($content, 'foreach') ||
            str_contains($content, 'while')
        )) {
            $this->addVulnerability(
                'Potentially Long-Running Job Not Queued',
                VulnerabilitySeverity::MEDIUM,
                'Job contains loops or sleep statements but doesn\'t implement ShouldQueue. '.
                'Long-running jobs should be queued in Octane.',
                $file,
                null,
                'class ...Job',
                'Implement ShouldQueue interface: class MyJob implements ShouldQueue',
                []
            );
        }

        // Check if job should be unique
        if ($hasQueue && ! $hasUnique && str_contains($content, 'dispatch')) {
            $this->addVulnerability(
                'Job May Need Uniqueness Constraint',
                VulnerabilitySeverity::LOW,
                'Queued job doesn\'t implement ShouldBeUnique. Consider if duplicate jobs should be prevented.',
                $file,
                null,
                'class ...Job implements ShouldQueue',
                'If duplicates should be prevented, implement: class MyJob implements ShouldQueue, ShouldBeUnique',
                []
            );
        }
    }

    protected function extractMethod(string $content, int $methodPos): string
    {
        $braceCount = 0;
        $inMethod = false;
        $methodEnd = strlen($content);

        for ($i = $methodPos; $i < strlen($content); $i++) {
            if ($content[$i] === '{') {
                $braceCount++;
                $inMethod = true;
            } elseif ($content[$i] === '}') {
                $braceCount--;
                if ($inMethod && $braceCount === 0) {
                    $methodEnd = $i;
                    break;
                }
            }
        }

        return substr($content, $methodPos, $methodEnd - $methodPos);
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Jobs'));
    }
}
