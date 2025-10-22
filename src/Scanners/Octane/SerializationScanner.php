<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class SerializationScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Serialization Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects serialization of Eloquent models and closures that can cause issues';
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
            $this->scanForSerializationIssues($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForSerializationIssues(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for serialize() on potential models
            if (preg_match('/serialize\(\s*\$\w+\s*\)/', $line)) {
                $this->addVulnerability(
                    'serialize() on Object',
                    VulnerabilitySeverity::HIGH,
                    'Serializing objects (especially Eloquent models) can cause issues in Octane. '.
                    'Models contain PDO connections that cannot be serialized.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use $model->toArray() or $model->toJson() instead. For queues, pass model ID and refetch.',
                    []
                );
            }

            // Check for json_encode on models
            if (preg_match('/json_encode\(\s*\$\w+(?:->(?:get|all|find))/', $line)) {
                $this->addVulnerability(
                    'json_encode() on Model Query',
                    VulnerabilitySeverity::MEDIUM,
                    'Encoding query results directly can cause issues with model relationships and connections.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use $models->toJson() or Model::query()->get()->toArray() for proper serialization.',
                    []
                );
            }

            // Check for storing closures in cache
            if (preg_match('/Cache::(?:put|forever|set)\(.*(?:function|fn)\s*\(/', $line)) {
                $this->addVulnerability(
                    'Caching Closure',
                    VulnerabilitySeverity::CRITICAL,
                    'Closures cannot be serialized and cached. This will fail in production.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Cache the result of the closure, not the closure itself. Or use Cache::remember() properly.',
                    []
                );
            }

            // Check for storing objects in session
            if (preg_match('/session\(\)->put\([^,]+,\s*\$\w+\s*\)/', $line) && preg_match('/new\s+\w+/', $content)) {
                $this->addVulnerability(
                    'Storing Object in Session',
                    VulnerabilitySeverity::HIGH,
                    'Storing objects in session can cause serialization issues, especially with Eloquent models.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Store only primitive values or IDs in session. Refetch models when needed.',
                    []
                );
            }

            // Check for __sleep() or __wakeup() methods (serialization magic methods)
            if (preg_match('/(?:public|protected|private)\s+function\s+__(?:sleep|wakeup)\(/', $line)) {
                $this->addVulnerability(
                    'Serialization Magic Methods',
                    VulnerabilitySeverity::MEDIUM,
                    '__sleep() or __wakeup() detected. Ensure these handle Octane worker persistence correctly.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Verify magic methods do not assume fresh process state. Test thoroughly in Octane.',
                    []
                );
            }

            // Check for var_export on objects
            if (preg_match('/var_export\(\s*\$\w+/', $line)) {
                $this->addVulnerability(
                    'var_export() on Variable',
                    VulnerabilitySeverity::LOW,
                    'var_export() may not work correctly on complex objects or models.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use json_encode() or toArray() for safe serialization.',
                    []
                );
            }

            // Check for unserialize() which is dangerous
            if (preg_match('/unserialize\(/', $line)) {
                $this->addVulnerability(
                    'unserialize() Usage',
                    VulnerabilitySeverity::HIGH,
                    'unserialize() is dangerous and can lead to code execution vulnerabilities if used on untrusted data.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use json_decode() instead. Never unserialize untrusted data.',
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
