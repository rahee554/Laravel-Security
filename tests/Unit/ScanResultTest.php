<?php

namespace ArtflowStudio\Scanner\Tests\Unit;

use ArtflowStudio\Scanner\Tests\TestCase;
use ArtflowStudio\Scanner\DTOs\ScanResult;
use ArtflowStudio\Scanner\DTOs\Vulnerability;
use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;

class ScanResultTest extends TestCase
{
    /** @test */
    public function it_can_create_a_scan_result()
    {
        $result = new ScanResult('Test Scanner', 'Test Description');

        $this->assertEquals('Test Scanner', $result->getScannerName());
        $this->assertEquals('Test Description', $result->getScannerDescription());
        $this->assertFalse($result->hasVulnerabilities());
    }

    /** @test */
    public function it_can_add_vulnerabilities()
    {
        $result = new ScanResult('Test Scanner', 'Test Description');

        $vulnerability = Vulnerability::make(
            'Test',
            VulnerabilitySeverity::HIGH,
            'Description',
            '/path/file.php'
        );

        $result->addVulnerability($vulnerability);

        $this->assertTrue($result->hasVulnerabilities());
        $this->assertEquals(1, $result->getTotalCount());
    }

    /** @test */
    public function it_can_count_by_severity()
    {
        $result = new ScanResult('Test Scanner', 'Test Description');

        $result->addVulnerability(Vulnerability::make('Test1', VulnerabilitySeverity::CRITICAL, 'Desc', 'file.php'));
        $result->addVulnerability(Vulnerability::make('Test2', VulnerabilitySeverity::CRITICAL, 'Desc', 'file.php'));
        $result->addVulnerability(Vulnerability::make('Test3', VulnerabilitySeverity::HIGH, 'Desc', 'file.php'));
        $result->addVulnerability(Vulnerability::make('Test4', VulnerabilitySeverity::MEDIUM, 'Desc', 'file.php'));

        $counts = $result->getCountBySeverity();

        $this->assertEquals(2, $counts['critical']);
        $this->assertEquals(1, $counts['high']);
        $this->assertEquals(1, $counts['medium']);
        $this->assertEquals(0, $counts['low']);
        $this->assertEquals(0, $counts['info']);
    }

    /** @test */
    public function it_can_sort_vulnerabilities_by_severity()
    {
        $result = new ScanResult('Test Scanner', 'Test Description');

        $result->addVulnerability(Vulnerability::make('Low', VulnerabilitySeverity::LOW, 'Desc', 'file.php'));
        $result->addVulnerability(Vulnerability::make('Critical', VulnerabilitySeverity::CRITICAL, 'Desc', 'file.php'));
        $result->addVulnerability(Vulnerability::make('Medium', VulnerabilitySeverity::MEDIUM, 'Desc', 'file.php'));

        $result->sortBySeverity();

        $vulnerabilities = $result->getVulnerabilities();

        $this->assertEquals('Critical', $vulnerabilities[0]->title);
        $this->assertEquals('Medium', $vulnerabilities[1]->title);
        $this->assertEquals('Low', $vulnerabilities[2]->title);
    }
}
