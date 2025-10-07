<?php

namespace ArtflowStudio\Scanner\Tests;

use Orchestra\Testbench\TestCase as Orchestra;
use ArtflowStudio\Scanner\ScannerServiceProvider;

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
