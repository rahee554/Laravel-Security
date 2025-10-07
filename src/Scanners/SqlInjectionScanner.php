<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;

class SqlInjectionScanner extends AbstractScanner
{
    protected array $dangerousMethods = [
        'DB::raw',
        '::raw',
        'whereRaw',
        'selectRaw',
        'orderByRaw',
        'havingRaw',
        'orWhereRaw',
        'orHavingRaw',
        'groupByRaw',
    ];

    public function getName(): string
    {
        return 'SQL Injection Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects potential SQL injection vulnerabilities in raw queries and database operations';
    }

    protected function execute(): void
    {
        $files = $this->getFilesToScan();
        $this->result->setFilesScanned(count($files));

        foreach ($files as $file) {
            $this->scanFile($file);
        }
    }

    protected function scanFile(string $file): void
    {
        $content = file_get_contents($file);
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            $this->checkRawQueries($file, $line, $lineNum + 1);
            $this->checkVariableInterpolation($file, $line, $lineNum + 1);
            $this->checkUnsafeWhereConditions($file, $line, $lineNum + 1);
        }
    }

    protected function checkRawQueries(string $file, string $line, int $lineNum): void
    {
        if (!$this->isConfigEnabled('sql_injection.check_raw_queries')) {
            return;
        }

        foreach ($this->dangerousMethods as $method) {
            if (stripos($line, $method) !== false) {
                // Check if using variable concatenation or interpolation
                if ($this->hasVariableInterpolation($line)) {
                    $severity = $this->determineInjectionSeverity($line);
                    
                    $this->addVulnerability(
                        'Potential SQL Injection via Raw Query',
                        $severity,
                        "Raw SQL query with variable interpolation detected. This could lead to SQL injection if user input is not properly sanitized.",
                        $file,
                        $lineNum,
                        trim($line),
                        "Use parameter binding instead: {$method}('query WHERE column = ?', [\$value])",
                        ['method' => $method, 'type' => 'raw_query']
                    );
                }
            }
        }
    }

    protected function checkVariableInterpolation(string $file, string $line, int $lineNum): void
    {
        // Check for string concatenation in queries
        if (preg_match('/DB::(?:select|insert|update|delete|statement)\s*\(\s*["\'].*?\$/', $line)) {
            $this->addVulnerability(
                'SQL Query with Variable Interpolation',
                VulnerabilitySeverity::CRITICAL,
                'Direct variable interpolation in SQL query detected. This is a critical SQL injection vulnerability.',
                $file,
                $lineNum,
                trim($line),
                'Use parameterized queries with placeholders: DB::select("SELECT * FROM users WHERE id = ?", [$id])',
                ['type' => 'variable_interpolation']
            );
        }

        // Check for concatenation
        if (preg_match('/DB::\w+\s*\(\s*["\'].*?[\'"]\s*\.\s*\$/', $line)) {
            $this->addVulnerability(
                'SQL Query with String Concatenation',
                VulnerabilitySeverity::CRITICAL,
                'String concatenation with variables in SQL query. This is highly vulnerable to SQL injection.',
                $file,
                $lineNum,
                trim($line),
                'Use parameterized queries instead of string concatenation.',
                ['type' => 'string_concatenation']
            );
        }
    }

    protected function checkUnsafeWhereConditions(string $file, string $line, int $lineNum): void
    {
        // Check for Request::input() directly in where clauses
        if (preg_match('/->where\s*\(\s*[^,]+,\s*Request::(?:input|get|post|query)\s*\(/', $line)) {
            $this->addVulnerability(
                'Unvalidated User Input in WHERE Clause',
                VulnerabilitySeverity::HIGH,
                'Using raw request input in WHERE clause without validation. While Eloquent provides protection, validated input is best practice.',
                $file,
                $lineNum,
                trim($line),
                'Validate request input before using in queries: $validated = $request->validated();',
                ['type' => 'unvalidated_input']
            );
        }

        // Check for \$_GET, \$_POST, \$_REQUEST usage
        if (preg_match('/\$_(GET|POST|REQUEST)\s*\[/', $line) && 
            preg_match('/(where|select|DB::)/', $line)) {
            $this->addVulnerability(
                'Superglobal Used in Database Query',
                VulnerabilitySeverity::CRITICAL,
                'Direct use of PHP superglobals ($_GET, $_POST, $_REQUEST) in database queries. This is extremely dangerous.',
                $file,
                $lineNum,
                trim($line),
                'Never use superglobals directly. Use Laravel\'s Request object with validation.',
                ['type' => 'superglobal_usage']
            );
        }
    }

    protected function hasVariableInterpolation(string $line): bool
    {
        // Check for various forms of variable interpolation
        return preg_match('/["\'].*?\$\w+/', $line) ||  // "$variable"
               preg_match('/["\'].*?\{.*?\$/', $line) ||  // "{$variable}"
               preg_match('/[\'"]\s*\.\s*\$/', $line) ||  // "string" . $variable
               preg_match('/\$\w+\s*\.\s*["\']/', $line); // $variable . "string"
    }

    protected function determineInjectionSeverity(string $line): VulnerabilitySeverity
    {
        // Check if there's any indication of sanitization
        if (stripos($line, 'intval') !== false ||
            stripos($line, 'floatval') !== false ||
            stripos($line, '(int)') !== false) {
            return VulnerabilitySeverity::MEDIUM;
        }

        // Check if Request facade is used (slightly less severe as Laravel provides some protection)
        if (stripos($line, 'Request::') !== false || stripos($line, '$request->') !== false) {
            return VulnerabilitySeverity::HIGH;
        }

        // Direct superglobals or unknown variables
        return VulnerabilitySeverity::CRITICAL;
    }
}
