<?php

namespace ArtflowStudio\LaravelSecurity\Fixers;

use ArtflowStudio\LaravelSecurity\Contracts\FixerStrategyInterface;
use Illuminate\Support\Facades\File;

abstract class AbstractFixer implements FixerStrategyInterface
{
    /**
     * Read file content
     */
    protected function readFile(string $path): string
    {
        return File::get(base_path($path));
    }

    /**
     * Write content to file
     */
    protected function writeFile(string $path, string $content): bool
    {
        return File::put(base_path($path), $content) !== false;
    }

    /**
     * Get lines from file
     */
    protected function getLines(string $path): array
    {
        return explode("\n", $this->readFile($path));
    }

    /**
     * Replace line in file
     */
    protected function replaceLine(string $path, int $lineNum, string $newContent): bool
    {
        $lines = $this->getLines($path);

        if (! isset($lines[$lineNum - 1])) {
            return false;
        }

        $lines[$lineNum - 1] = $newContent;

        return $this->writeFile($path, implode("\n", $lines));
    }

    /**
     * Replace content in file
     */
    protected function replaceInFile(string $path, string $search, string $replace): bool
    {
        $content = $this->readFile($path);
        $newContent = str_replace($search, $replace, $content);

        if ($content === $newContent) {
            return false;
        }

        return $this->writeFile($path, $newContent);
    }

    /**
     * Insert line after specific line
     */
    protected function insertAfterLine(string $path, int $lineNum, string $content): bool
    {
        $lines = $this->getLines($path);

        if (! isset($lines[$lineNum - 1])) {
            return false;
        }

        array_splice($lines, $lineNum, 0, [$content]);

        return $this->writeFile($path, implode("\n", $lines));
    }

    /**
     * Get indentation from a line
     */
    protected function getIndentation(string $line): string
    {
        preg_match('/^(\s+)/', $line, $matches);

        return $matches[1] ?? '';
    }
}
