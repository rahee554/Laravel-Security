<?php

namespace ArtflowStudio\LaravelSecurity\Fixers;

class CsrfFixerStrategy extends AbstractFixer
{
    public function canHandle($vulnerability): bool
    {
        return ($vulnerability->metadata['type'] ?? null) === 'missing_csrf';
    }

    public function fix($vulnerability): bool
    {
        // Add @csrf directive to forms
        return $this->addCsrfToken($vulnerability);
    }

    public function previewFix($vulnerability): ?array
    {
        return [
            'file' => $vulnerability->file,
            'line' => $vulnerability->line,
            'old' => '<form',
            'new' => '<form (with @csrf token added)',
        ];
    }

    protected function addCsrfToken($vulnerability): bool
    {
        $lines = $this->getLines($vulnerability->file);
        $lineNum = $vulnerability->line - 1;

        if (! isset($lines[$lineNum])) {
            return false;
        }

        // Get indentation from next line
        $indent = isset($lines[$lineNum + 1])
            ? $this->getIndentation($lines[$lineNum + 1])
            : '    ';

        $csrfLine = $indent.'@csrf';

        return $this->insertAfterLine(
            $vulnerability->file,
            $vulnerability->line,
            $csrfLine
        );
    }
}
