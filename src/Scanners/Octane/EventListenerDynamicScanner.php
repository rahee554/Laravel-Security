<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class EventListenerDynamicScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Dynamic Event Listener Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects Event::listen() calls outside service providers that stack on every request';
    }

    protected function execute(): void
    {
        $paths = ['app/Http/Controllers', 'app/Http/Middleware', 'app/Livewire', 'routes'];

        $allFiles = [];
        foreach ($paths as $path) {
            if (File::exists(base_path($path))) {
                $allFiles = array_merge($allFiles, $this->fileSystem->getPhpFiles([$path]));
            }
        }

        foreach ($allFiles as $file) {
            $this->scanForDynamicListeners($file);
        }

        $this->result->setFilesScanned(count($allFiles));
    }

    protected function scanForDynamicListeners(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNumber => $line) {
            // Check for Event::listen() calls
            if (preg_match('/Event::listen\(/', $line)) {
                $this->addVulnerability(
                    'Dynamic Event Listener Outside Provider',
                    VulnerabilitySeverity::CRITICAL,
                    'Event::listen() is being called dynamically. In Octane, this listener will be registered '.
                    'on EVERY REQUEST and stack infinitely, causing memory leaks and duplicate event handling.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Move Event::listen() to EventServiceProvider or a service provider boot() method. '.
                    'Never call Event::listen() in controllers, middleware, or route files.',
                    []
                );
            }

            // Check for $events->listen() calls
            if (preg_match('/\$events->listen\(/', $line)) {
                $this->addVulnerability(
                    'Dynamic Event Listener Registration',
                    VulnerabilitySeverity::CRITICAL,
                    '$events->listen() is being called dynamically. This listener stacks on every request in Octane.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Move listener registration to a service provider boot() method.',
                    []
                );
            }

            // Check for app('events')->listen() calls
            if (preg_match('/app\([\'"]events[\'"]\)->listen\(/', $line)) {
                $this->addVulnerability(
                    'Dynamic Event Listener via Container',
                    VulnerabilitySeverity::CRITICAL,
                    'Resolving events from container and registering listeners dynamically. This stacks infinitely.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Move listener registration to EventServiceProvider.',
                    []
                );
            }

            // Check for Queue::before() and Queue::after() outside providers
            if (preg_match('/Queue::(?:before|after|looping|failing)\(/', $line)) {
                $this->addVulnerability(
                    'Dynamic Queue Hook Registration',
                    VulnerabilitySeverity::HIGH,
                    'Queue hooks (before, after, looping, failing) are being registered dynamically. '.
                    'These will stack on every request in Octane.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Move Queue hook registration to AppServiceProvider boot() method.',
                    []
                );
            }
        }
    }

    public function isApplicable(): bool
    {
        return File::exists(base_path('app/Http/Controllers')) ||
               File::exists(base_path('app/Http/Middleware')) ||
               File::exists(base_path('app/Livewire')) ||
               File::exists(base_path('routes'));
    }
}
