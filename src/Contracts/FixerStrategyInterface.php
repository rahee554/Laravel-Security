<?php

namespace ArtflowStudio\Scanner\Contracts;

interface FixerStrategyInterface
{
    /**
     * Fix a vulnerability
     */
    public function fix($vulnerability): bool;

    /**
     * Preview the fix without applying it
     */
    public function previewFix($vulnerability): ?array;

    /**
     * Check if this fixer can handle the vulnerability
     */
    public function canHandle($vulnerability): bool;
}
