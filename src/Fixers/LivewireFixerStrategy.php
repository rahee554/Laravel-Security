<?php

namespace ArtflowStudio\LaravelSecurity\Fixers;

class LivewireFixerStrategy extends AbstractFixer
{
    public function canHandle($vulnerability): bool
    {
        return ($vulnerability->metadata['type'] ?? null) === 'missing_validation';
    }

    public function fix($vulnerability): bool
    {
        // For now, just add a comment suggesting manual fix
        // Full automation would require AST manipulation
        return $this->addValidationComment($vulnerability);
    }

    public function previewFix($vulnerability): ?array
    {
        $property = $vulnerability->metadata['property'] ?? 'property';

        return [
            'file' => $vulnerability->file,
            'line' => $vulnerability->line,
            'old' => "public \${$property};",
            'new' => "public \${$property}; // TODO: Add validation in rules() method",
        ];
    }

    protected function addValidationComment($vulnerability): bool
    {
        $property = $vulnerability->metadata['property'] ?? 'property';
        $indent = '    ';

        $comment = "{$indent}// TODO: Add validation for '{$property}' in rules() method";

        return $this->insertAfterLine(
            $vulnerability->file,
            $vulnerability->line,
            $comment
        );
    }
}
