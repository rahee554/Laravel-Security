<?php

namespace ArtflowStudio\Scanner\Tests;

use ArtflowStudio\Scanner\ScannerServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();
    }

    protected function getPackageProviders($app)
    {
        return [
            ScannerServiceProvider::class,
        ];
    }

    protected function getEnvironmentSetUp($app)
    {
        config()->set('scanner.scan_paths', ['app']);
        config()->set('scanner.exclude_paths', ['vendor', 'tests']);
    }
}
