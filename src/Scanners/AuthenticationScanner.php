<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class AuthenticationScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Authentication Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks authentication configuration and password security';
    }

    protected function execute(): void
    {
        $this->checkPasswordValidation();
        $this->checkSessionConfiguration();
    }

    protected function checkPasswordValidation(): void
    {
        // Check for password validation rules in User model or registration controller
        $files = array_merge(
            $this->fileSystem->getModelFiles(),
            $this->fileSystem->getControllerFiles()
        );

        foreach ($files as $file) {
            $content = file_get_contents($file);
            if (str_contains($content, 'password') && str_contains($content, 'rules')) {
                if (! preg_match('/password.*min:\d+/', $content)) {
                    $this->addVulnerability(
                        'Weak Password Requirements',
                        VulnerabilitySeverity::MEDIUM,
                        'Password validation lacks minimum length requirement.',
                        $file,
                        null,
                        null,
                        "Add minimum password length: 'password' => 'required|min:8|confirmed'",
                        ['type' => 'password_validation']
                    );
                }
            }
        }
    }

    protected function checkSessionConfiguration(): void
    {
        $sessionPath = base_path('config/session.php');
        if (file_exists($sessionPath)) {
            $content = file_get_contents($sessionPath);
            if (! str_contains($content, "'secure' => true") && ! str_contains($content, "'secure' => env(")) {
                $this->addVulnerability(
                    'Session Cookies Not Secure',
                    VulnerabilitySeverity::MEDIUM,
                    'Session cookies should be marked as secure in production.',
                    $sessionPath,
                    null,
                    null,
                    "Set 'secure' => env('SESSION_SECURE_COOKIE', true) in config/session.php",
                    ['type' => 'session_security']
                );
            }
        }
    }
}
