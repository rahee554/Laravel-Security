<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class ContainerLoopScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Container Resolution in Loop Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects container resolution (app(), resolve()) inside loops causing performance issues';
    }

    protected function execute(): void
    {
        $paths = ['app/Http/Controllers', 'app/Services', 'app/Livewire'];

        $allFiles = [];
        foreach ($paths as $path) {
            if (File::exists(base_path($path))) {
                $allFiles = array_merge($allFiles, $this->fileSystem->getPhpFiles([$path]));
            }
        }

        foreach ($allFiles as $file) {
            $this->scanForContainerInLoops($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForContainerInLoops(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        $inLoop = false;
        $loopDepth = 0;

        foreach ($lines as $lineNumber => $line) {
            // Detect loop starts
            if (preg_match('/\b(?:foreach|for|while)\s*\(/', $line)) {
                $inLoop = true;
                $loopDepth++;
            }

            // Detect loop ends (simplified - counts closing braces)
            if ($inLoop && preg_match('/^\s*}\s*$/', $line)) {
                $loopDepth--;
                if ($loopDepth === 0) {
                    $inLoop = false;
                }
            }

            // If we're in a loop, check for container resolution
            if ($inLoop) {
                // Check for app() helper
                if (preg_match('/\bapp\([\'"][\w\\\\]+[\'"]\)/', $line)) {
                    $this->addVulnerability(
                        'Container Resolution in Loop',
                        VulnerabilitySeverity::HIGH,
                        'app() is being called inside a loop. This resolves from container on every iteration, '.
                        'causing significant performance degradation.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Resolve service once before the loop: $service = app(MyService::class); then use $service in loop.',
                        []
                    );
                }

                // Check for resolve() helper
                if (preg_match('/\bresolve\([\'"][\w\\\\]+[\'"]\)/', $line)) {
                    $this->addVulnerability(
                        'resolve() in Loop',
                        VulnerabilitySeverity::HIGH,
                        'resolve() is being called inside a loop. Resolve once before the loop.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Move resolve() call outside the loop.',
                        []
                    );
                }

                // Check for $this->container->make() or ->get()
                if (preg_match('/\$(?:this->)?container->(?:make|get)\(/', $line)) {
                    $this->addVulnerability(
                        'Container make/get in Loop',
                        VulnerabilitySeverity::HIGH,
                        'Container resolution inside loop causes repeated service instantiation.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Resolve service once before loop.',
                        []
                    );
                }

                // Check for new Model() in loop (N+1 prevention)
                if (preg_match('/new\s+\w+\((?:.*\$\w+)?\)/', $line) && preg_match('/Model|Eloquent/', $content)) {
                    $this->addVulnerability(
                        'Model Instantiation in Loop',
                        VulnerabilitySeverity::MEDIUM,
                        'Instantiating models in a loop can cause performance issues. Consider bulk operations.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Use bulk operations like insert(), upsert() or eager load relationships.',
                        []
                    );
                }

                // Check for config() in loop
                if (preg_match('/\bconfig\([\'"]/', $line)) {
                    $this->addVulnerability(
                        'config() in Loop',
                        VulnerabilitySeverity::LOW,
                        'Calling config() repeatedly in a loop is inefficient. Cache the value before the loop.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Store config value in variable before loop: $value = config("key"); then use $value in loop.',
                        []
                    );
                }
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Http/Controllers')) ||
               File::exists(base_path('app/Services')) ||
               File::exists(base_path('app/Livewire'));
    }
}
