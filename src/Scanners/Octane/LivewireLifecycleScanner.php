<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class LivewireLifecycleScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Livewire Lifecycle Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects issues in Livewire mount(), hydrate(), and dehydrate() methods';
    }

    protected function execute(): void
    {
        if (! File::exists(base_path('app/Livewire'))) {
            return;
        }

        $livewireFiles = $this->fileSystem->getPhpFiles(['app/Livewire']);

        foreach ($livewireFiles as $file) {
            $this->scanLivewireComponent($file);
        }

        $this->result->setFilesScanned(count($livewireFiles));
    }

    protected function scanLivewireComponent(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        $inMountMethod = false;
        $inHydrateMethod = false;
        $inDehydrateMethod = false;

        foreach ($lines as $lineNumber => $line) {
            // Track lifecycle methods
            if (preg_match('/(?:public|protected)\s+function\s+mount\(/', $line)) {
                $inMountMethod = true;
            } elseif (preg_match('/(?:public|protected)\s+function\s+hydrate\(/', $line)) {
                $inHydrateMethod = true;
            } elseif (preg_match('/(?:public|protected)\s+function\s+dehydrate\(/', $line)) {
                $inDehydrateMethod = true;
            } elseif (preg_match('/^\s*}\s*$/', $line) && ($inMountMethod || $inHydrateMethod || $inDehydrateMethod)) {
                $inMountMethod = false;
                $inHydrateMethod = false;
                $inDehydrateMethod = false;
            }

            // Check mount() for heavy operations
            if ($inMountMethod) {
                if (preg_match('/->(?:get|all|paginate|count)\(\)/', $line)) {
                    $this->addVulnerability(
                        'Heavy Query in mount()',
                        VulnerabilitySeverity::HIGH,
                        'Livewire mount() method contains database query. This executes on every component load.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Move heavy queries to render() or computed properties for better performance.',
                        []
                    );
                }

                if (preg_match('/Cache::remember/', $line)) {
                    $this->addVulnerability(
                        'Caching in mount()',
                        VulnerabilitySeverity::MEDIUM,
                        'mount() method uses caching. Consider if this is request-specific data.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Ensure cache keys include user context if data is user-specific.',
                        []
                    );
                }
            }

            // Check hydrate() for state mutation
            if ($inHydrateMethod) {
                if (preg_match('/\$this->\w+\s*=/', $line)) {
                    $this->addVulnerability(
                        'Property Assignment in hydrate()',
                        VulnerabilitySeverity::MEDIUM,
                        'hydrate() is mutating component state. This can cause inconsistent state in Octane.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'hydrate() should only restore transient state, not mutate properties directly.',
                        []
                    );
                }

                if (preg_match('/Auth::(?:user|id)/', $line)) {
                    $this->addVulnerability(
                        'Auth in hydrate()',
                        VulnerabilitySeverity::HIGH,
                        'hydrate() accesses Auth. If stored in property, can leak between users.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Always re-fetch Auth data on each request, do not store in component properties.',
                        []
                    );
                }
            }

            // Check dehydrate() for non-serializable data
            if ($inDehydrateMethod) {
                if (preg_match('/\$this->\w+\s*=\s*(?:new|function|fn)/', $line)) {
                    $this->addVulnerability(
                        'Non-Serializable Data in dehydrate()',
                        VulnerabilitySeverity::MEDIUM,
                        'dehydrate() is storing closures or objects. These cannot be serialized properly.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Only store serializable data (strings, arrays, numbers). Unset closures/objects.',
                        []
                    );
                }
            }

            // Check for static properties in Livewire components (anywhere in file)
            if (preg_match('/(?:private|protected|public)\s+static\s+\$/', $line)) {
                $this->addVulnerability(
                    'Static Property in Livewire Component',
                    VulnerabilitySeverity::CRITICAL,
                    'Livewire component has static property. This persists across requests and causes data leaks.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Never use static properties in Livewire components. Use instance properties only.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Livewire'));
    }
}
