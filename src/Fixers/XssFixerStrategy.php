<?php

namespace ArtflowStudio\LaravelSecurity\Fixers;

class XssFixerStrategy extends AbstractFixer
{
    public function canHandle($vulnerability): bool
    {
        $fixableTypes = ['unescaped_output', 'inline_handler', 'js_injection'];
        $type = $vulnerability->metadata['type'] ?? null;

        return in_array($type, $fixableTypes);
    }

    public function fix($vulnerability): bool
    {
        $type = $vulnerability->metadata['type'] ?? null;

        return match ($type) {
            'unescaped_output' => $this->fixUnescapedOutput($vulnerability),
            'inline_handler' => $this->fixInlineHandler($vulnerability),
            default => false,
        };
    }

    public function previewFix($vulnerability): ?array
    {
        $type = $vulnerability->metadata['type'] ?? null;
        $oldLine = $vulnerability->code;

        $newLine = match ($type) {
            'unescaped_output' => $this->generateEscapedOutput($oldLine),
            'inline_handler' => $this->generateSafeHandler($oldLine),
            default => null,
        };

        if (! $newLine) {
            return null;
        }

        return [
            'file' => $vulnerability->file,
            'line' => $vulnerability->line,
            'old' => trim($oldLine),
            'new' => trim($newLine),
        ];
    }

    protected function fixUnescapedOutput($vulnerability): bool
    {
        $oldLine = $vulnerability->code;
        $newLine = $this->generateEscapedOutput($oldLine);

        if (! $newLine) {
            return false;
        }

        return $this->replaceInFile(
            $vulnerability->file,
            trim($oldLine),
            trim($newLine)
        );
    }

    protected function generateEscapedOutput(string $line): ?string
    {
        // Convert {!! $var !!} to {{ $var }}
        if (preg_match('/\{!!\s*(\$\w+.*?)\s*!!\}/', $line, $matches)) {
            $variable = $matches[1];

            return str_replace(
                "{!! {$variable} !!}",
                "{{ {$variable} }}",
                $line
            );
        }

        return null;
    }

    protected function fixInlineHandler($vulnerability): bool
    {
        // For inline handlers, we'll add a comment suggesting to move to external JS
        $oldLine = $vulnerability->code;
        $indent = $this->getIndentation($oldLine);

        $comment = $indent.'{{-- TODO: Move this event handler to external JavaScript for security --}}';

        return $this->insertAfterLine(
            $vulnerability->file,
            $vulnerability->line - 1,
            $comment
        );
    }

    protected function generateSafeHandler(string $line): string
    {
        return $line.' {{-- WARNING: Inline event handlers with Blade variables are a security risk --}}';
    }
}
