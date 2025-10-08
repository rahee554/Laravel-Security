<?php

namespace ArtflowStudio\LaravelSecurity\Scanners;

use ArtflowStudio\LaravelSecurity\DTOs\VulnerabilitySeverity;

class PerformanceScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Performance & Scalability Scanner';
    }

    public function getDescription(): string
    {
        return 'Detects N+1 queries, memory issues, slow render times, and performance bottlenecks';
    }

    public function isApplicable(): bool
    {
        return true; // Always applicable
    }

    protected function execute(): void
    {
        $this->checkNPlusOneQueries();
        $this->checkEagerLoadingMissing();
        $this->checkLivewirePolling();
        $this->checkLargeCollections();
        $this->checkQueryCaching();
        $this->checkSessionConfiguration();
    }

    protected function checkNPlusOneQueries(): void
    {
        $files = array_merge(
            $this->fileSystem->getFiles(app_path('Http/Controllers')),
            $this->fileSystem->getLivewireFiles(),
            $this->fileSystem->getFiles(app_path('Models'))
        );

        foreach ($files as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                // Detect potential N+1 in Blade: @foreach without eager loading
                if (preg_match('/@foreach\s*\(\s*\$(\w+)\s+as/', $line, $matches)) {
                    $variable = $matches[1];

                    // Check if next few lines access relationships
                    for ($i = 1; $i <= 5; $i++) {
                        $nextLine = $lines[$lineNumber + $i] ?? '';

                        if (preg_match('/\$\w+->(\w+)/', $nextLine, $relMatches)) {
                            $relationship = $relMatches[1];

                            // Common relationship names
                            if (in_array($relationship, ['user', 'posts', 'comments', 'author', 'category', 'tags', 'items'])) {
                                $this->addVulnerability(
                                    'Potential N+1 Query in View',
                                    VulnerabilitySeverity::HIGH,
                                    "Loop over \${$variable} accesses relationship '{$relationship}'. This may cause N+1 query problem.",
                                    $file,
                                    $lineNumber + 1,
                                    $line,
                                    "Use eager loading: \${$variable}->with('{$relationship}')->get()",
                                    ['type' => 'n_plus_one_view', 'variable' => $variable, 'relationship' => $relationship]
                                );
                                break;
                            }
                        }
                    }
                }

                // Detect Model::all() without constraints
                if (preg_match('/(\w+)::all\(\)/', $line) && ! str_contains($content, '->take(') && ! str_contains($content, '->limit(')) {
                    $this->addVulnerability(
                        'Model::all() Without Limit',
                        VulnerabilitySeverity::MEDIUM,
                        'Using Model::all() can load thousands of records into memory. This may cause performance issues.',
                        $file,
                        $lineNumber + 1,
                        $line,
                        'Use pagination or add limit: Model::limit(100)->get() or Model::paginate()',
                        ['type' => 'model_all_no_limit']
                    );
                }

                // Detect get() without eager loading before foreach
                if (preg_match('/\$(\w+)\s*=.*->get\(\)/', $line, $matches)) {
                    $variable = $matches[1];

                    // Check if variable is used in foreach in next 20 lines
                    for ($i = 1; $i <= 20; $i++) {
                        $nextLine = $lines[$lineNumber + $i] ?? '';

                        if (preg_match("/foreach\s*\(\s*\\\${$variable}\s+as/", $nextLine)) {
                            // Check if with() was used
                            if (! str_contains($line, '->with(')) {
                                $this->addVulnerability(
                                    'Query Without Eager Loading Before Loop',
                                    VulnerabilitySeverity::HIGH,
                                    "Variable \${$variable} is queried without eager loading, then looped. This may cause N+1 queries.",
                                    $file,
                                    $lineNumber + 1,
                                    $line,
                                    'Add eager loading: ->with([\'relationship\'])->get()',
                                    ['type' => 'no_eager_loading', 'variable' => $variable]
                                );
                            }
                            break;
                        }
                    }
                }

                // Detect queries inside loops
                if (preg_match('/foreach|while|for\s*\(/', $line)) {
                    for ($i = 1; $i <= 10; $i++) {
                        $nextLine = $lines[$lineNumber + $i] ?? '';

                        if (preg_match('/::find\(|::where\(|->find\(|->where\(/', $nextLine)) {
                            $this->addVulnerability(
                                'Database Query Inside Loop',
                                VulnerabilitySeverity::CRITICAL,
                                'Database query detected inside a loop. This is a classic N+1 query problem.',
                                $file,
                                $lineNumber + $i + 1,
                                $nextLine,
                                'Move query outside loop and use eager loading or whereIn()',
                                ['type' => 'query_in_loop']
                            );
                            break;
                        }
                    }
                }
            }
        }
    }

    protected function checkEagerLoadingMissing(): void
    {
        $modelFiles = $this->fileSystem->getFiles(app_path('Models'));

        foreach ($modelFiles as $file) {
            $content = file_get_contents($file);

            // Check if model has relationships but no $with property
            $hasRelationships = preg_match('/(hasMany|hasOne|belongsTo|belongsToMany|morphMany|morphTo)\(/', $content);
            $hasEagerLoading = str_contains($content, 'protected $with');

            if ($hasRelationships && ! $hasEagerLoading) {
                $this->addVulnerability(
                    'Model Has Relationships Without Default Eager Loading',
                    VulnerabilitySeverity::INFO,
                    'Model defines relationships but does not specify default eager loading. Consider adding $with property for commonly used relationships.',
                    $file,
                    null,
                    null,
                    'Add: protected $with = [\'commonlyUsedRelationship\'];',
                    ['type' => 'no_default_eager_loading']
                );
            }
        }
    }

    protected function checkLivewirePolling(): void
    {
        $viewFiles = $this->fileSystem->getFiles(resource_path('views'));

        foreach ($viewFiles as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                // Detect wire:poll with short intervals
                if (preg_match('/wire:poll\.(\d+)(ms|s)?/', $line, $matches)) {
                    $interval = (int) $matches[1];
                    $unit = $matches[2] ?? 's';

                    $intervalMs = $unit === 's' ? $interval * 1000 : $interval;

                    if ($intervalMs < 5000) { // Less than 5 seconds
                        $this->addVulnerability(
                            'Aggressive Livewire Polling',
                            VulnerabilitySeverity::HIGH,
                            "wire:poll.{$interval}{$unit} is too aggressive. Polling every {$intervalMs}ms can overload the server.",
                            $file,
                            $lineNumber + 1,
                            $line,
                            'Increase polling interval to at least 5 seconds: wire:poll.5s',
                            ['type' => 'aggressive_polling', 'interval' => $intervalMs]
                        );
                    }
                }

                // Detect wire:poll without interval (default 2s)
                if (preg_match('/wire:poll(?!\.)/', $line) && ! preg_match('/wire:poll\./', $line)) {
                    $this->addVulnerability(
                        'Livewire Polling Without Interval',
                        VulnerabilitySeverity::MEDIUM,
                        'wire:poll without interval defaults to 2 seconds, which may be too aggressive for some use cases.',
                        $file,
                        $lineNumber + 1,
                        $line,
                        'Specify interval explicitly: wire:poll.10s',
                        ['type' => 'polling_no_interval']
                    );
                }
            }
        }
    }

    protected function checkLargeCollections(): void
    {
        $files = array_merge(
            $this->fileSystem->getFiles(app_path('Http/Controllers')),
            $this->fileSystem->getLivewireFiles()
        );

        foreach ($files as $file) {
            $content = file_get_contents($file);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                // Detect pluck() on large result sets
                if (preg_match('/->pluck\(/', $line) && ! str_contains($line, '->take(') && ! str_contains($line, '->limit(')) {
                    $this->addVulnerability(
                        'Pluck Without Limit',
                        VulnerabilitySeverity::MEDIUM,
                        'Using pluck() without limit can load large amounts of data into memory.',
                        $file,
                        $lineNumber + 1,
                        $line,
                        'Add limit before pluck: ->limit(1000)->pluck() or use cursor()',
                        ['type' => 'pluck_no_limit']
                    );
                }

                // Detect toArray() on large collections
                if (preg_match('/->toArray\(\)/', $line) && preg_match('/::all\(\)/', $line)) {
                    $this->addVulnerability(
                        'toArray() on Model::all()',
                        VulnerabilitySeverity::MEDIUM,
                        'Converting Model::all()->toArray() can consume large amounts of memory.',
                        $file,
                        $lineNumber + 1,
                        $line,
                        'Use pagination or limit: Model::paginate()->toArray()',
                        ['type' => 'to_array_all']
                    );
                }

                // Detect chunk() usage (good practice)
                if (str_contains($line, '->chunk(') || str_contains($line, '->chunkById(')) {
                    // This is good! No vulnerability
                }
            }
        }
    }

    protected function checkQueryCaching(): void
    {
        $cacheConfig = config_path('cache.php');

        if (! file_exists($cacheConfig)) {
            return;
        }

        $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

        $content = file_get_contents($cacheConfig);

        // Check if cache driver is 'file' in production
        if (config('app.env') === 'production' && str_contains($content, "'default' => env('CACHE_DRIVER', 'file')")) {
            $this->addVulnerability(
                'File Cache Driver in Production',
                VulnerabilitySeverity::MEDIUM,
                'Using file cache driver in production can be slow. Consider using Redis or Memcached.',
                $cacheConfig,
                null,
                null,
                'Set CACHE_DRIVER=redis in .env and install predis/predis',
                ['type' => 'file_cache_in_production']
            );
        }

        // Check if query caching is used
        $modelFiles = $this->fileSystem->getFiles(app_path('Models'));
        $controllerFiles = $this->fileSystem->getFiles(app_path('Http/Controllers'));

        $usesQueryCache = false;

        foreach (array_merge($modelFiles, $controllerFiles) as $file) {
            $content = file_get_contents($file);

            if (str_contains($content, '->remember(') || str_contains($content, '->rememberForever(')) {
                $usesQueryCache = true;
                break;
            }
        }

        if (! $usesQueryCache) {
            $this->addVulnerability(
                'No Query Caching Detected',
                VulnerabilitySeverity::INFO,
                'Application does not appear to use query caching. Consider caching frequently accessed queries.',
                app_path(),
                null,
                null,
                'Use cache: Model::remember(60)->get() or Cache::remember()',
                ['type' => 'no_query_caching']
            );
        }
    }

    protected function checkSessionConfiguration(): void
    {
        $sessionConfig = config_path('session.php');

        if (! file_exists($sessionConfig)) {
            return;
        }

        $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

        $content = file_get_contents($sessionConfig);

        // Check if session driver is 'file' in production with high traffic
        if (config('app.env') === 'production' && str_contains($content, "'driver' => env('SESSION_DRIVER', 'file')")) {
            $this->addVulnerability(
                'File Session Driver in Production',
                VulnerabilitySeverity::MEDIUM,
                'Using file session driver in production can cause performance issues with high traffic.',
                $sessionConfig,
                null,
                null,
                'Set SESSION_DRIVER=redis or SESSION_DRIVER=database in .env',
                ['type' => 'file_session_in_production']
            );
        }

        // Check session lifetime
        if (preg_match("/'lifetime'\s*=>\s*(\d+)/", $content, $matches)) {
            $lifetime = (int) $matches[1];

            if ($lifetime > 10080) { // More than 1 week
                $this->addVulnerability(
                    'Excessive Session Lifetime',
                    VulnerabilitySeverity::LOW,
                    "Session lifetime is set to {$lifetime} minutes (>1 week). Long sessions can accumulate and affect performance.",
                    $sessionConfig,
                    null,
                    null,
                    'Reduce session lifetime to 120 minutes (2 hours) or less',
                    ['type' => 'excessive_session_lifetime', 'value' => $lifetime]
                );
            }
        }
    }
}
