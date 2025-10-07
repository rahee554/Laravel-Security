<?php

namespace ArtflowStudio\Scanner\Services;

use Illuminate\Support\Facades\File;
use Symfony\Component\Finder\Finder;

class FileSystemService
{
    /**
     * Get all PHP files in the given paths
     */
    public function getPhpFiles(array $paths, array $excludePaths = []): array
    {
        $files = [];

        foreach ($paths as $path) {
            $fullPath = base_path($path);

            if (! File::exists($fullPath)) {
                continue;
            }

            $finder = new Finder;
            $finder->files()
                ->in($fullPath)
                ->name('*.php')
                ->ignoreDotFiles(true);

            foreach ($excludePaths as $exclude) {
                $finder->notPath($exclude);
            }

            foreach ($finder as $file) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }

    /**
     * Get all Blade files in the given paths
     */
    public function getBladeFiles(array $paths, array $excludePaths = []): array
    {
        $files = [];

        foreach ($paths as $path) {
            $fullPath = base_path($path);

            if (! File::exists($fullPath)) {
                continue;
            }

            $finder = new Finder;
            $finder->files()
                ->in($fullPath)
                ->name('*.blade.php')
                ->ignoreDotFiles(true);

            foreach ($excludePaths as $exclude) {
                $finder->notPath($exclude);
            }

            foreach ($finder as $file) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }

    /**
     * Get Livewire component files
     */
    public function getLivewireFiles(): array
    {
        $paths = [
            base_path('app/Http/Livewire'),
            base_path('app/Livewire'),
        ];

        $files = [];

        foreach ($paths as $path) {
            if (! File::exists($path)) {
                continue;
            }

            $finder = new Finder;
            $finder->files()
                ->in($path)
                ->name('*.php')
                ->ignoreDotFiles(true);

            foreach ($finder as $file) {
                $files[] = $file->getRealPath();
            }
        }

        return $files;
    }

    /**
     * Get model files
     */
    public function getModelFiles(): array
    {
        $path = base_path('app/Models');

        if (! File::exists($path)) {
            return [];
        }

        $finder = new Finder;
        $finder->files()
            ->in($path)
            ->name('*.php')
            ->ignoreDotFiles(true);

        $files = [];
        foreach ($finder as $file) {
            $files[] = $file->getRealPath();
        }

        return $files;
    }

    /**
     * Get controller files
     */
    public function getControllerFiles(): array
    {
        $path = base_path('app/Http/Controllers');

        if (! File::exists($path)) {
            return [];
        }

        $finder = new Finder;
        $finder->files()
            ->in($path)
            ->name('*.php')
            ->ignoreDotFiles(true);

        $files = [];
        foreach ($finder as $file) {
            $files[] = $file->getRealPath();
        }

        return $files;
    }

    /**
     * Read file contents
     */
    public function readFile(string $path): string
    {
        return File::get($path);
    }

    /**
     * Check if file exists
     */
    public function fileExists(string $path): bool
    {
        return File::exists($path);
    }

    /**
     * Get relative path from base path
     */
    public function getRelativePath(string $path): string
    {
        return str_replace(base_path().DIRECTORY_SEPARATOR, '', $path);
    }

    /**
     * Get all files in a given path (generic method)
     */
    public function getFiles(string $path, string $pattern = '*.php'): array
    {
        if (! File::exists($path)) {
            return [];
        }

        if (! File::isDirectory($path)) {
            return [$path];
        }

        $finder = new Finder;
        $finder->files()
            ->in($path)
            ->name($pattern)
            ->ignoreDotFiles(true);

        $files = [];
        foreach ($finder as $file) {
            $files[] = $file->getRealPath();
        }

        return $files;
    }
}
