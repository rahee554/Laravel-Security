<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class LivewireOctaneScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Livewire Octane Compatibility Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects Livewire components with Octane-incompatible patterns';
    }

    protected function execute(): void
    {
        if (! $this->isApplicable()) {
            return;
        }

        $livewireFiles = $this->fileSystem->getPhpFiles(['app/Livewire']);
        if (empty($livewireFiles) && File::exists(base_path('app/Http/Livewire'))) {
            $livewireFiles = $this->fileSystem->getPhpFiles(['app/Http/Livewire']);
        }

        foreach ($livewireFiles as $file) {
            $this->scanLivewireComponent($file);
        }

        $this->result->setFilesScanned(count($livewireFiles));
    }

    protected function scanLivewireComponent(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        // Check for heavy queries in render()
        if (preg_match('/public function render\s*\(\s*\)/', $content, $matches, PREG_OFFSET_CAPTURE)) {
            $renderPos = $matches[0][1];
            $renderMethod = $this->extractMethod($content, $renderPos);

            // Check for queries without pagination
            if (preg_match('/(::all\(\)|::get\(\)|->get\(\))/', $renderMethod) && ! stripos($renderMethod, 'paginate')) {
                $lineNumber = substr_count(substr($content, 0, $renderPos), "\n") + 1;

                $this->addVulnerability(
                    'Heavy Query in Livewire render()',
                    VulnerabilitySeverity::MEDIUM,
                    'Livewire render() method contains ->get() or ::all() without pagination. '.
                    'In Octane, this executes on every render and can cause memory issues.',
                    $file,
                    $lineNumber,
                    'public function render()',
                    'Use ->paginate() or ->limit() to prevent loading all records. Consider computing data in mount() or cached properties.',
                    ['method' => 'render']
                );
            }
        }

        // Check for static properties
        foreach ($lines as $lineNumber => $line) {
            if (preg_match('/(?:public|protected|private)\s+static\s+\$/', $line)) {
                $this->addVulnerability(
                    'Static Property in Livewire Component',
                    VulnerabilitySeverity::HIGH,
                    'Static properties in Livewire components persist across requests in Octane, causing data leaks between users.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Convert to instance property. Use $this->property instead of static::$property',
                    []
                );
            }

            // Check for storing entire models
            if (preg_match('/public\s+(\w+)\s+\$(\w+)/', $line, $matches)) {
                $type = $matches[1];
                $propertyName = $matches[2];

                if (in_array($type, ['Model', 'User', 'Collection']) || str_ends_with($type, 'Model')) {
                    $this->addVulnerability(
                        'Storing Model in Livewire Property',
                        VulnerabilitySeverity::MEDIUM,
                        "Livewire property \${$propertyName} stores a model instance. This increases component state size and can cause memory issues.",
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        "Store only the model ID: public int \${$propertyName}Id; then load the model when needed: \$this->{$propertyName} = Model::find(\$this->{$propertyName}Id)",
                        ['property' => $propertyName, 'type' => $type]
                    );
                }
            }

            // Check for emit (deprecated in favor of dispatch)
            if (preg_match('/\$this->emit\(/', $line)) {
                $this->addVulnerability(
                    'Using Deprecated emit() in Livewire',
                    VulnerabilitySeverity::LOW,
                    'emit() is deprecated in Livewire 3. Use dispatch() for better performance.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Replace $this->emit() with $this->dispatch()',
                    []
                );
            }
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
        return File::exists(base_path('app/Livewire')) || File::exists(base_path('app/Http/Livewire'));
    }
}
