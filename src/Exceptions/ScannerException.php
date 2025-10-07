<?php

namespace ArtflowStudio\Scanner\Exceptions;

use Exception;

class ScannerException extends Exception
{
    public static function scannerNotFound(string $name): self
    {
        return new self("Scanner '{$name}' not found.");
    }

    public static function invalidConfiguration(string $message): self
    {
        return new self("Invalid configuration: {$message}");
    }

    public static function fileNotReadable(string $path): self
    {
        return new self("File not readable: {$path}");
    }

    public static function directoryNotFound(string $path): self
    {
        return new self("Directory not found: {$path}");
    }
}
