<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class XssScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'XSS (Cross-Site Scripting) Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects potential XSS vulnerabilities in Blade templates and JavaScript code';
    }

    protected function execute(): void
    {
        $scanPaths = $this->getConfig('scan_paths', ['app', 'resources/views']);
        $excludePaths = $this->getConfig('exclude_paths', []);

        // Scan Blade files
        $bladeFiles = $this->fileSystem->getBladeFiles($scanPaths, $excludePaths);

        // Scan PHP files for echo/print statements
        $phpFiles = $this->fileSystem->getPhpFiles($scanPaths, $excludePaths);

        $this->result->setFilesScanned(count($bladeFiles) + count($phpFiles));

        foreach ($bladeFiles as $file) {
            $this->scanBladeFile($file);
        }

        foreach ($phpFiles as $file) {
            $this->scanPhpFile($file);
        }
    }

    protected function scanBladeFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            $this->checkRawOutput($file, $line, $lineNum + 1);
            $this->checkJavaScriptInjection($file, $line, $lineNum + 1);
            $this->checkUrlInjection($file, $line, $lineNum + 1);
            $this->checkInlineJavaScript($file, $line, $lineNum + 1);
        }
    }

    protected function scanPhpFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            $this->checkUnsafeEcho($file, $line, $lineNum + 1);
        }
    }

    protected function checkRawOutput(string $file, string $line, int $lineNum): void
    {
        if (! $this->isConfigEnabled('xss.check_blade_raw_output')) {
            return;
        }

        // Check for {!! !!} unescaped output
        if (preg_match('/\{!!\s*\$/', $line)) {
            // Check if it's outputting user-controllable data
            if ($this->containsUserData($line)) {
                $this->addVulnerability(
                    'Unescaped Output of User Data',
                    VulnerabilitySeverity::CRITICAL,
                    'Raw Blade output {!! !!} is used with user-controllable data. This allows XSS attacks.',
                    $file,
                    $lineNum,
                    trim($line),
                    'Use {{ $variable }} for automatic escaping, or use {!! Purifier::clean($variable) !!} for HTML content.',
                    ['type' => 'unescaped_output']
                );
            } else {
                $this->addVulnerability(
                    'Unescaped Blade Output',
                    VulnerabilitySeverity::MEDIUM,
                    'Raw Blade output {!! !!} detected. Verify that this data is safe and does not contain user input.',
                    $file,
                    $lineNum,
                    trim($line),
                    'If possible, use {{ $variable }} for automatic escaping.',
                    ['type' => 'unescaped_output_warning']
                );
            }
        }
    }

    protected function checkJavaScriptInjection(string $file, string $line, int $lineNum): void
    {
        if (! $this->isConfigEnabled('xss.check_javascript_injection')) {
            return;
        }

        // Check for variables in JavaScript context
        if (preg_match('/<script[^>]*>.*?\{\{\s*\$/', $line)) {
            $this->addVulnerability(
                'Blade Variable in JavaScript Context',
                VulnerabilitySeverity::HIGH,
                'Blade variable output inside <script> tag. This can lead to XSS if not properly escaped.',
                $file,
                $lineNum,
                trim($line),
                'Use @json() directive: let data = @json($variable); or encode for JavaScript: {{ json_encode($variable) }}',
                ['type' => 'js_injection']
            );
        }

        // Check for inline event handlers with variables
        if (preg_match('/on\w+\s*=\s*["\'].*?\{\{/', $line)) {
            $this->addVulnerability(
                'Variable in Inline Event Handler',
                VulnerabilitySeverity::HIGH,
                'Blade variable in inline event handler (onclick, onload, etc.). This is vulnerable to XSS.',
                $file,
                $lineNum,
                trim($line),
                'Move JavaScript to external file and pass data via data attributes or @json().',
                ['type' => 'inline_handler']
            );
        }
    }

    protected function checkUrlInjection(string $file, string $line, int $lineNum): void
    {
        if (! $this->isConfigEnabled('xss.check_url_injection')) {
            return;
        }

        // Check for unescaped URLs
        if (preg_match('/href\s*=\s*["\']?\{\{\s*\$/', $line) ||
            preg_match('/src\s*=\s*["\']?\{\{\s*\$/', $line)) {

            $this->addVulnerability(
                'Potential URL Injection',
                VulnerabilitySeverity::MEDIUM,
                'Variable used directly in href or src attribute. Validate URLs to prevent javascript: protocol injection.',
                $file,
                $lineNum,
                trim($line),
                'Use url() helper or validate the URL: href="{{ url($link) }}" or validate with starts_with($url, [\'http://\', \'https://\'])',
                ['type' => 'url_injection']
            );
        }

        // Check for javascript: protocol
        if (stripos($line, 'javascript:') !== false && preg_match('/\{\{.*?\}\}/', $line)) {
            $this->addVulnerability(
                'JavaScript Protocol with Variable',
                VulnerabilitySeverity::CRITICAL,
                'Using javascript: protocol with Blade variables. This is a serious XSS vulnerability.',
                $file,
                $lineNum,
                trim($line),
                'Never use javascript: protocol with dynamic data. Use proper event listeners instead.',
                ['type' => 'js_protocol']
            );
        }
    }

    protected function checkInlineJavaScript(string $file, string $line, int $lineNum): void
    {
        // Check for potentially dangerous inline JavaScript patterns
        if (preg_match('/document\.write\s*\(.*?\{\{/', $line)) {
            $this->addVulnerability(
                'document.write() with Blade Variable',
                VulnerabilitySeverity::HIGH,
                'Using document.write() with Blade variables can lead to XSS.',
                $file,
                $lineNum,
                trim($line),
                'Avoid document.write(). Use DOM manipulation or @json() for safe data passing.',
                ['type' => 'document_write']
            );
        }

        // Check for eval with variables
        if (preg_match('/eval\s*\(.*?\{\{/', $line)) {
            $this->addVulnerability(
                'eval() with Blade Variable',
                VulnerabilitySeverity::CRITICAL,
                'Using eval() with Blade variables. This is extremely dangerous and allows arbitrary code execution.',
                $file,
                $lineNum,
                trim($line),
                'Never use eval() with user data. Refactor to use safe alternatives.',
                ['type' => 'eval_usage']
            );
        }
    }

    protected function checkUnsafeEcho(string $file, string $line, int $lineNum): void
    {
        // Check for echo/print with Request data
        if (preg_match('/(echo|print)\s+.*?\$request->/', $line) ||
            preg_match('/(echo|print)\s+.*?Request::/', $line)) {

            $this->addVulnerability(
                'Direct Echo of Request Data',
                VulnerabilitySeverity::HIGH,
                'Directly echoing request data without escaping. Use e() helper or Blade templates.',
                $file,
                $lineNum,
                trim($line),
                'Use: echo e($request->input(\'field\')); or return to a Blade view.',
                ['type' => 'unsafe_echo']
            );
        }
    }

    protected function containsUserData(string $line): bool
    {
        $userDataIndicators = [
            '$request',
            'Request::',
            '$input',
            '->input',
            '$_GET',
            '$_POST',
            '$_REQUEST',
            '$user->',
            '->comment',
            '->description',
            '->body',
            '->content',
        ];

        foreach ($userDataIndicators as $indicator) {
            if (stripos($line, $indicator) !== false) {
                return true;
            }
        }

        return false;
    }
}
