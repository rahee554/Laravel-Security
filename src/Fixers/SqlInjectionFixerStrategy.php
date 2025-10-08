<?php

namespace ArtflowStudio\LaravelSecurity\Fixers;

class SqlInjectionFixerStrategy extends AbstractFixer
{
    public function canHandle($vulnerability): bool
    {
        return ($vulnerability->metadata['type'] ?? null) === 'raw_query';
    }

    public function fix($vulnerability): bool
    {
        // Add comment warning about SQL injection risk
        return $this->addSecurityComment($vulnerability);
    }

    public function previewFix($vulnerability): ?array
    {
        return [
            'file' => $vulnerability->file,
            'line' => $vulnerability->line,
            'old' => trim($vulnerability->code),
            'new' => trim($vulnerability->code).' // WARNING: Potential SQL injection risk',
        ];
    }

    protected function addSecurityComment($vulnerability): bool
    {
        $indent = $this->getIndentation($vulnerability->code);
        $comment = "{$indent}// WARNING: Use parameter binding to prevent SQL injection";

        return $this->insertAfterLine(
            $vulnerability->file,
            $vulnerability->line - 1,
            $comment
        );
    }
}
