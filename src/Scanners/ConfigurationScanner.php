<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class ConfigurationScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Configuration Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks application configuration for security issues';
    }

    protected function execute(): void
    {
        $this->checkAppKey();
        $this->checkCorsConfiguration();
    }

    protected function checkAppKey(): void
    {
        $envPath = base_path('.env');
        if (file_exists($envPath)) {
            $content = file_get_contents($envPath);
            if (str_contains($content, 'APP_KEY=') && ! preg_match('/APP_KEY=base64:[A-Za-z0-9+\/=]{40,}/', $content)) {
                $this->addVulnerability(
                    'Missing or Invalid APP_KEY',
                    VulnerabilitySeverity::CRITICAL,
                    'APP_KEY is not set or invalid. This compromises encryption security.',
                    $envPath,
                    null,
                    null,
                    'Run: php artisan key:generate',
                    ['type' => 'app_key']
                );
            }
        }
    }

    protected function checkCorsConfiguration(): void
    {
        $corsPath = base_path('config/cors.php');
        if (file_exists($corsPath)) {
            $content = file_get_contents($corsPath);
            if (str_contains($content, "'allowed_origins' => ['*']")) {
                $this->addVulnerability(
                    'Permissive CORS Configuration',
                    VulnerabilitySeverity::MEDIUM,
                    'CORS allows all origins (*). This may expose your API to unwanted domains.',
                    $corsPath,
                    null,
                    null,
                    'Specify allowed origins explicitly.',
                    ['type' => 'cors']
                );
            }
        }
    }
}
