<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;

class LivewireScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Livewire Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Scans Livewire components for security vulnerabilities including public property exposure, missing authorization, and validation issues';
    }

    public function isApplicable(): bool
    {
        return $this->composer->hasLivewire();
    }

    protected function execute(): void
    {
        $files = $this->fileSystem->getLivewireFiles();
        $this->result->setFilesScanned(count($files));

        foreach ($files as $file) {
            $this->scanFile($file);
        }
    }

    protected function scanFile(string $file): void
    {
        $content = file_get_contents($file);
        $ast = $this->codeAnalyzer->parseFile($file);

        if ($ast === null) {
            return;
        }

        // Check if it's a Livewire component
        if (! $this->isLivewireComponent($content)) {
            return;
        }

        $this->checkPublicProperties($file, $ast, $content);
        $this->checkMissingValidation($file, $content);
        $this->checkMissingAuthorization($file, $content);
        $this->checkMassAssignment($file, $content);
        $this->checkFileUploadSecurity($file, $content);
        $this->checkEventListenerSecurity($file, $ast);
    }

    protected function isLivewireComponent(string $content): bool
    {
        return str_contains($content, 'use Livewire\Component') ||
               str_contains($content, 'extends Component');
    }

    protected function checkPublicProperties(string $file, array $ast, string $content): void
    {
        if (! $this->isConfigEnabled('livewire.check_public_properties')) {
            return;
        }

        $publicProperties = $this->codeAnalyzer->findPublicProperties($ast);
        $protectedProps = $this->getConfig('livewire.protected_properties', []);

        foreach ($publicProperties as $property) {
            $propName = $property['name'];

            // Check if property name suggests it should be protected
            foreach ($protectedProps as $protected) {
                if (stripos($propName, $protected) !== false) {
                    $this->addVulnerability(
                        'Sensitive Public Property Exposed',
                        VulnerabilitySeverity::CRITICAL,
                        "Public property '{$propName}' may expose sensitive data. Public properties in Livewire can be manipulated by users.",
                        $file,
                        $property['line'],
                        null,
                        "Change to protected property or add validation rules. Use protected \${$propName} and create a setter method with proper validation.",
                        ['property' => $propName, 'type' => 'sensitive_data']
                    );
                }
            }

            // Check if property has validation rules
            if (! $this->hasValidationRules($content, $propName)) {
                $this->addVulnerability(
                    'Public Property Without Validation',
                    VulnerabilitySeverity::HIGH,
                    "Public property '{$propName}' lacks validation rules. Users can manipulate this property with any value.",
                    $file,
                    $property['line'],
                    null,
                    'Add validation rules in the rules() method or use Wire:model with validation.',
                    ['property' => $propName, 'type' => 'missing_validation']
                );
            }
        }
    }

    protected function hasValidationRules(string $content, string $property): bool
    {
        // Check if property is mentioned in rules() method
        if (preg_match("/['\"]".preg_quote($property, '/')."['\"]\\s*=>\\s*['\"][^'\"]+['\"]/", $content)) {
            return true;
        }

        // Check for #[Rule] attribute
        if (str_contains($content, '#[Rule') && str_contains($content, "public \${$property}")) {
            return true;
        }

        return false;
    }

    protected function checkMissingValidation(string $file, string $content): void
    {
        if (! $this->isConfigEnabled('livewire.check_validation')) {
            return;
        }

        // Find methods that update data but don't call validate()
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            // Look for methods that modify data
            if (preg_match('/public function (save|update|store|create|delete|submit)\s*\(/', $line)) {
                $methodStartLine = $lineNum + 1;

                // Check if validate() or authorize() is called in the method
                $methodContent = $this->extractMethodContent($content, $methodStartLine);

                if (! str_contains($methodContent, '$this->validate(') &&
                    ! str_contains($methodContent, '$this->authorize(')) {

                    preg_match('/public function (\w+)\s*\(/', $line, $matches);
                    $methodName = $matches[1] ?? 'unknown';

                    $this->addVulnerability(
                        'Method Without Validation or Authorization',
                        VulnerabilitySeverity::HIGH,
                        "Method '{$methodName}()' performs data operations without validation or authorization checks.",
                        $file,
                        $methodStartLine,
                        trim($line),
                        'Add $this->validate() or $this->authorize() before performing data operations.',
                        ['method' => $methodName]
                    );
                }
            }
        }
    }

    protected function checkMissingAuthorization(string $file, string $content): void
    {
        if (! $this->isConfigEnabled('livewire.check_authorization')) {
            return;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            // Check for methods that should have authorization
            if (preg_match('/public function (delete|destroy|update|edit)\s*\(/', $line)) {
                $methodStartLine = $lineNum + 1;
                $methodContent = $this->extractMethodContent($content, $methodStartLine);

                if (! str_contains($methodContent, '$this->authorize(') &&
                    ! str_contains($methodContent, 'Gate::') &&
                    ! str_contains($methodContent, '->can(')) {

                    preg_match('/public function (\w+)\s*\(/', $line, $matches);
                    $methodName = $matches[1] ?? 'unknown';

                    $this->addVulnerability(
                        'Missing Authorization Check',
                        VulnerabilitySeverity::CRITICAL,
                        "Method '{$methodName}()' lacks authorization checks. Any user can execute this action.",
                        $file,
                        $methodStartLine,
                        trim($line),
                        "Add authorization using \$this->authorize('action', \$model) or Gate::authorize().",
                        ['method' => $methodName, 'type' => 'authorization']
                    );
                }
            }
        }
    }

    protected function checkMassAssignment(string $file, string $content): void
    {
        if (! $this->isConfigEnabled('livewire.check_mass_assignment')) {
            return;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            // Look for direct model updates from properties
            if (preg_match('/\$\w+->update\s*\(\s*\$this->all\(\)/', $line) ||
                preg_match('/\$\w+->fill\s*\(\s*\$this->all\(\)/', $line)) {

                $this->addVulnerability(
                    'Potential Mass Assignment Vulnerability',
                    VulnerabilitySeverity::HIGH,
                    'Using $this->all() with update() or fill() can lead to mass assignment vulnerabilities.',
                    $file,
                    $lineNum + 1,
                    trim($line),
                    'Explicitly specify which fields to update or ensure your model has $fillable/$guarded properly set.',
                    ['type' => 'mass_assignment']
                );
            }
        }
    }

    protected function checkFileUploadSecurity(string $file, string $content): void
    {
        if (! str_contains($content, 'WithFileUploads')) {
            return;
        }

        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            // Check if file uploads have validation
            if (preg_match('/public \$(\w+);.*\/\*\*.*@var.*UploadedFile/', $line)) {
                $nextLines = implode("\n", array_slice($lines, $lineNum, 10));

                if (! str_contains($nextLines, 'mimes:') && ! str_contains($nextLines, 'image')) {
                    $this->addVulnerability(
                        'File Upload Without MIME Type Validation',
                        VulnerabilitySeverity::HIGH,
                        'File upload property lacks MIME type validation, which could allow malicious file uploads.',
                        $file,
                        $lineNum + 1,
                        trim($line),
                        "Add validation rules: 'propertyName' => 'required|file|mimes:pdf,doc,docx|max:10240'",
                        ['type' => 'file_upload']
                    );
                }
            }
        }
    }

    protected function checkEventListenerSecurity(string $file, array $ast): void
    {
        $content = file_get_contents($file);

        // Check for event listeners
        if (preg_match_all('/protected \$listeners\s*=\s*\[(.*?)\]/s', $content, $matches)) {
            foreach ($matches[1] as $listenerBlock) {
                // Parse listener methods
                preg_match_all('/[\'"](\w+)[\'"]/', $listenerBlock, $methods);

                foreach ($methods[1] as $method) {
                    // Check if the method has authorization
                    if (preg_match("/public function {$method}\s*\(/", $content, $methodMatch, PREG_OFFSET_CAPTURE)) {
                        $position = $methodMatch[0][1];
                        $lineNum = substr_count(substr($content, 0, $position), "\n") + 1;

                        $methodContent = $this->extractMethodContent($content, $lineNum);

                        if (! str_contains($methodContent, 'authorize')) {
                            $this->addVulnerability(
                                'Event Listener Without Authorization',
                                VulnerabilitySeverity::MEDIUM,
                                "Event listener '{$method}' can be triggered from the frontend without authorization checks.",
                                $file,
                                $lineNum,
                                null,
                                'Add authorization checks within the listener method.',
                                ['method' => $method, 'type' => 'event_listener']
                            );
                        }
                    }
                }
            }
        }
    }

    protected function extractMethodContent(string $content, int $startLine): string
    {
        $lines = explode("\n", $content);
        $startIdx = $startLine - 1;
        $braceCount = 0;
        $methodContent = '';
        $started = false;

        for ($i = $startIdx; $i < count($lines); $i++) {
            $line = $lines[$i];
            $methodContent .= $line."\n";

            $braceCount += substr_count($line, '{') - substr_count($line, '}');

            if (str_contains($line, '{')) {
                $started = true;
            }

            if ($started && $braceCount === 0) {
                break;
            }
        }

        return $methodContent;
    }
}
