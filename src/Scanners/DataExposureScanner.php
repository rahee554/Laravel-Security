<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;

class DataExposureScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Data Exposure Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects sensitive data exposure through debug mode, logs, API responses, and configuration';
    }

    protected function execute(): void
    {
        $this->checkDebugMode();
        $this->checkEnvironmentFile();
        $this->checkSensitiveLogging();
        $this->checkModelHiddenFields();
        $this->checkApiResponseLeakage();
    }

    protected function checkDebugMode(): void
    {
        if (!$this->isConfigEnabled('data_exposure.check_debug_mode')) {
            return;
        }

        $envPath = base_path('.env');
        
        if (file_exists($envPath)) {
            $envContent = file_get_contents($envPath);
            
            if (preg_match('/^APP_DEBUG\s*=\s*true/m', $envContent)) {
                $this->addVulnerability(
                    'Debug Mode Enabled',
                    VulnerabilitySeverity::CRITICAL,
                    'APP_DEBUG is set to true. This exposes sensitive information like stack traces, environment variables, and database queries in production.',
                    $envPath,
                    null,
                    'APP_DEBUG=true',
                    'Set APP_DEBUG=false in production environments.',
                    ['type' => 'debug_mode']
                );
            }
        }
    }

    protected function checkEnvironmentFile(): void
    {
        $envPath = base_path('.env');
        
        if (file_exists($envPath)) {
            $envContent = file_get_contents($envPath);
            $lines = explode("\n", $envContent);
            
            foreach ($lines as $lineNum => $line) {
                // Check for hardcoded secrets
                if (preg_match('/(PASSWORD|SECRET|KEY|TOKEN).*=.*[\'"]?[\w\-]{8,}/', $line) && 
                    !str_contains($line, 'null') &&
                    !str_contains($line, 'your-')) {
                    
                    // This is expected in .env, but check if it looks like default
                    if (str_contains($line, 'password') || str_contains($line, '123456')) {
                        $this->addVulnerability(
                            'Weak or Default Credentials in Environment',
                            VulnerabilitySeverity::HIGH,
                            'Possible default or weak credentials detected in .env file.',
                            $envPath,
                            $lineNum + 1,
                            preg_replace('/=.*/', '=***', $line),
                            'Use strong, randomly generated credentials.',
                            ['type' => 'weak_credentials']
                        );
                    }
                }
            }
        }

        // Check if .env.example has actual secrets
        $envExamplePath = base_path('.env.example');
        if (file_exists($envExamplePath)) {
            $content = file_get_contents($envExamplePath);
            
            if (preg_match('/(SECRET|TOKEN|PASSWORD).*=.{20,}/', $content)) {
                $this->addVulnerability(
                    'Potential Secrets in .env.example',
                    VulnerabilitySeverity::MEDIUM,
                    '.env.example file may contain actual secrets instead of placeholders.',
                    $envExamplePath,
                    null,
                    null,
                    'Use placeholder values in .env.example, not actual secrets.',
                    ['type' => 'env_example_secrets']
                );
            }
        }
    }

    protected function checkSensitiveLogging(): void
    {
        $files = $this->getFilesToScan();
        $sensitiveKeywords = $this->getConfig('data_exposure.sensitive_keywords', [
            'password', 'secret', 'token', 'api_key'
        ]);

        foreach ($files as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNum => $line) {
                // Check for logging statements with sensitive data
                if (preg_match('/Log::|logger\(\)|\$this->logger/', $line)) {
                    foreach ($sensitiveKeywords as $keyword) {
                        if (stripos($line, $keyword) !== false) {
                            $this->addVulnerability(
                                'Potential Sensitive Data Logging',
                                VulnerabilitySeverity::HIGH,
                                "Logging statement may contain sensitive data ({$keyword}). Logs can expose passwords, tokens, and other secrets.",
                                $file,
                                $lineNum + 1,
                                trim($line),
                                "Avoid logging sensitive data. If necessary, redact it: Log::info('Action', ['password' => '***']);",
                                ['keyword' => $keyword, 'type' => 'sensitive_logging']
                            );
                        }
                    }
                }
            }
        }
    }

    protected function checkModelHiddenFields(): void
    {
        $modelFiles = $this->fileSystem->getModelFiles();

        foreach ($modelFiles as $file) {
            $content = file_get_contents($file);

            // Check if model has $hidden property
            if (!preg_match('/protected\s+\$hidden\s*=/', $content) &&
                !preg_match('/protected\s+\$visible\s*=/', $content)) {
                
                // Check if model has sensitive-looking fields
                if (preg_match('/(password|token|secret|api_key|private_key)/i', $content)) {
                    $this->addVulnerability(
                        'Model Missing $hidden Property',
                        VulnerabilitySeverity::MEDIUM,
                        'Model appears to have sensitive fields but lacks $hidden property to prevent accidental exposure.',
                        $file,
                        null,
                        null,
                        "Add protected \$hidden = ['password', 'remember_token', 'api_key']; to your model.",
                        ['type' => 'missing_hidden']
                    );
                }
            }
        }
    }

    protected function checkApiResponseLeakage(): void
    {
        if (!$this->isConfigEnabled('data_exposure.check_api_responses')) {
            return;
        }

        $controllerFiles = $this->fileSystem->getControllerFiles();

        foreach ($controllerFiles as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNum => $line) {
                // Check for returning entire models in API responses
                if (preg_match('/return\s+.*?User::all\(\)|->all\(\)|->get\(\)/', $line) &&
                    str_contains($content, 'namespace App\Http\Controllers\Api')) {
                    
                    $this->addVulnerability(
                        'Potential API Response Data Leakage',
                        VulnerabilitySeverity::MEDIUM,
                        'Returning entire model collections in API responses may expose sensitive fields.',
                        $file,
                        $lineNum + 1,
                        trim($line),
                        'Use API Resources to control what data is returned: return UserResource::collection(User::all());',
                        ['type' => 'api_leakage']
                    );
                }
            }
        }
    }
}
