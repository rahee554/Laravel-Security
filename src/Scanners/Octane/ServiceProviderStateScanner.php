<?php

namespace ArtflowStudio\LaravelSecurity\Scanners\Octane;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;
use ArtflowStudio\LaravelSecurity\Scanners\AbstractScanner;
use Illuminate\Support\Facades\File;

class ServiceProviderStateScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Service Provider State Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects service providers storing request-scoped state that persists across requests';
    }

    protected function execute(): void
    {
        if (! File::exists(base_path('app/Providers'))) {
            return;
        }

        $providerFiles = $this->fileSystem->getPhpFiles(['app/Providers']);

        foreach ($providerFiles as $file) {
            $this->scanServiceProvider($file);
        }

        $this->result->setFilesScanned(count($providerFiles));
    }

    protected function scanServiceProvider(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        // Check for class properties that might store state
        $hasProperties = false;
        $propertyLines = [];

        foreach ($lines as $lineNumber => $line) {
            // Detect class properties
            if (preg_match('/(?:private|protected|public)\s+(?:static\s+)?\$(\w+)/', $line, $matches)) {
                $hasProperties = true;
                $propertyLines[$matches[1]] = $lineNumber + 1;
            }

            // Check boot() method for state storage
            if (preg_match('/public function boot\s*\(/', $line)) {
                $this->checkBootMethod($file, $content, $lineNumber + 1);
            }

            // Check register() method for state storage
            if (preg_match('/public function register\s*\(/', $line)) {
                $this->checkRegisterMethod($file, $content, $lineNumber + 1);
            }

            // Detect app()->instance() with potentially mutable values
            if (preg_match('/app\(\)->instance\(/', $line)) {
                $this->addVulnerability(
                    'Using app()->instance() in Service Provider',
                    VulnerabilitySeverity::HIGH,
                    'app()->instance() registers a singleton instance. In Octane, this instance persists across all requests and can leak state between users.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Use app()->scoped() for request-scoped instances, or ensure the instance is immutable and stateless.',
                    []
                );
            }

            // Detect storing Auth::user() or request() in provider
            if (str_contains($line, '->') && (
                preg_match('/Auth::user\(\)/', $line) ||
                preg_match('/auth\(\)->user\(\)/', $line) ||
                preg_match('/request\(\)/', $line) ||
                preg_match('/session\(\)/', $line)
            )) {
                if (str_contains($line, '$this->') || str_contains($line, 'self::$') || str_contains($line, 'static::$')) {
                    $this->addVulnerability(
                        'Storing Request-Scoped Data in Provider Property',
                        VulnerabilitySeverity::CRITICAL,
                        'Service provider is storing request-scoped data (Auth::user(), request(), session()) in a class property. '.
                        'Providers run once in Octane, so this data will be shared across ALL requests.',
                        $file,
                        $lineNumber + 1,
                        trim($line),
                        'Never store request-scoped data in provider properties. Pass these values as parameters to services or use dependency injection.',
                        []
                    );
                }
            }

            // Detect storing config or tenant data
            if (preg_match('/\$this->(\w+)\s*=.*(?:config\(|tenant\(|Tenant::)/', $line)) {
                $this->addVulnerability(
                    'Storing Config/Tenant Data in Provider Property',
                    VulnerabilitySeverity::HIGH,
                    'Provider is storing config or tenant data in a property. In Octane, this persists across requests and can cause tenant data leaks.',
                    $file,
                    $lineNumber + 1,
                    trim($line),
                    'Fetch config/tenant data per-request in your services, not in provider boot/register methods.',
                    []
                );
            }
        }
    }

    protected function checkBootMethod(string $file, string $content, int $lineNumber): void
    {
        // Extract boot method body
        $methodBody = $this->extractMethod($content, strpos($content, 'public function boot'));

        // Check for risky patterns in boot()
        if (str_contains($methodBody, '$this->') && (
            str_contains($methodBody, 'Auth::') ||
            str_contains($methodBody, 'request()') ||
            str_contains($methodBody, 'session()')
        )) {
            $this->addVulnerability(
                'boot() Method Storing Request Data',
                VulnerabilitySeverity::CRITICAL,
                'The boot() method stores request-scoped data. boot() runs ONCE per worker in Octane, not per request.',
                $file,
                $lineNumber,
                'public function boot()',
                'Move request-scoped logic to middleware or controller. boot() should only register services and bindings.',
                []
            );
        }
    }

    protected function checkRegisterMethod(string $file, string $content, int $lineNumber): void
    {
        $methodBody = $this->extractMethod($content, strpos($content, 'public function register'));

        if (str_contains($methodBody, '$this->') && (
            str_contains($methodBody, 'Auth::') ||
            str_contains($methodBody, 'request()') ||
            str_contains($methodBody, 'session()')
        )) {
            $this->addVulnerability(
                'register() Method Storing Request Data',
                VulnerabilitySeverity::CRITICAL,
                'The register() method stores request-scoped data. register() runs ONCE per worker in Octane.',
                $file,
                $lineNumber,
                'public function register()',
                'Move request-scoped logic out of register(). Only use register() for service container bindings.',
                []
            );
        }
    }

    protected function extractMethod(string $content, int $methodPos): string
    {
        if ($methodPos === false) {
            return '';
        }

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
        return File::exists(base_path('app/Providers'));
    }
}
