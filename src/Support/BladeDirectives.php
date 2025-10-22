<?php

namespace ArtflowStudio\LaravelSecurity\Support;

use Illuminate\Support\Facades\Blade;

class BladeDirectives
{
    /**
     * Register all custom Blade directives
     *
     * @return void
     */
    public static function register(): void
    {
        /**
         * @afConsoleSecurity - Inject console security JavaScript
         * 
         * Usage: @afConsoleSecurity in your layout's <head> tag
         */
        Blade::directive('afConsoleSecurity', function () {
            return <<<'HTML'
<?php
// Console Security Configuration
$afSecurityConfig = [
    'enabled' => config('console-security.enabled', true),
    'sizeThreshold' => config('console-security.detection.size_threshold', 160),
    'timingThreshold' => config('console-security.detection.timing_threshold', 120),
    'loopIterations' => config('console-security.detection.loop_iterations', 100000),
    'renewalInterval' => config('console-security.detection.renewal_check_interval', 30) * 1000, // Convert to ms
    'blockedUrl' => url('/blocked'),
    'handshakeUrl' => url('/_security/handshake'),
];
?>

<?php if ($afSecurityConfig['enabled']): ?>
<!-- Laravel Security - Console Protection Module v2.0.0 -->
<meta name="csrf-token" content="<?php echo e(csrf_token()); ?>">
<script>
    // Inject configuration
    window.AF_SECURITY_SIZE_THRESHOLD = <?php echo json_encode($afSecurityConfig['sizeThreshold']); ?>;
    window.AF_SECURITY_TIMING_THRESHOLD = <?php echo json_encode($afSecurityConfig['timingThreshold']); ?>;
    window.AF_SECURITY_LOOP_ITERATIONS = <?php echo json_encode($afSecurityConfig['loopIterations']); ?>;
    window.AF_SECURITY_RENEWAL_INTERVAL = <?php echo json_encode($afSecurityConfig['renewalInterval']); ?>;
    window.AF_SECURITY_BLOCKED_URL = <?php echo json_encode($afSecurityConfig['blockedUrl']); ?>;
    window.AF_SECURITY_HANDSHAKE_URL = <?php echo json_encode($afSecurityConfig['handshakeUrl']); ?>;
</script>
<script src="<?php echo e(asset('vendor/laravel-security/js/console-security.js')); ?>" defer></script>
<?php endif; ?>
HTML;
        });

        /**
         * @afSecurityStatus - Show current security status (for debugging)
         * 
         * Usage: @afSecurityStatus
         */
        Blade::directive('afSecurityStatus', function () {
            return <<<'HTML'
<?php
if (config('app.debug') && config('console-security.dev_mode', false)) {
    $metadata = \ArtflowStudio\LaravelSecurity\Support\SecurityToken::metadata();
    echo '<div style="position:fixed;bottom:10px;right:10px;background:rgba(0,0,0,0.8);color:#0f0;padding:10px;border-radius:8px;font-family:monospace;font-size:11px;z-index:99999;">';
    echo '<strong>🛡️ Security Status</strong><br>';
    echo 'Token: ' . ($metadata['token'] ? 'Active' : 'None') . '<br>';
    echo 'Remaining: ' . $metadata['remaining_seconds'] . 's<br>';
    echo 'Expires: ' . ($metadata['is_expiring'] ? 'Soon' : 'OK') . '<br>';
    echo 'Age: ' . ($metadata['age_seconds'] ?? 0) . 's<br>';
    echo '</div>';
}
?>
HTML;
        });

        /**
         * @afSecurityBadge - Show "Protected by Laravel Security" badge
         * 
         * Usage: @afSecurityBadge (usually in footer)
         */
        Blade::directive('afSecurityBadge', function ($expression) {
            $color = $expression ?: "'#667eea'";
            
            return <<<HTML
<?php if (config('console-security.enabled', true)): ?>
<div style="display:inline-flex;align-items:center;gap:6px;font-size:12px;color:{$color};opacity:0.7;">
    <svg style="width:14px;height:14px;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
    </svg>
    <span>Protected by Laravel Security</span>
</div>
<?php endif; ?>
HTML;
        });

        /**
         * @requiresHandshake - Mark a section that requires valid handshake
         * 
         * Usage: @requiresHandshake ... @endrequiresHandshake
         */
        Blade::directive('requiresHandshake', function () {
            return '<?php if (\ArtflowStudio\LaravelSecurity\Support\SecurityToken::verify(request()->cookie(config("console-security.cookie.name", "af_handshake"))) ?? false): ?>';
        });

        Blade::directive('endrequiresHandshake', function () {
            return '<?php endif; ?>';
        });

        /**
         * @securityToken - Output current security token (for AJAX requests)
         * 
         * Usage: <input type="hidden" name="security_token" value="@securityToken">
         */
        Blade::directive('securityToken', function () {
            return '<?php echo e(\ArtflowStudio\LaravelSecurity\Support\SecurityToken::metadata()["token"] ?? ""); ?>';
        });
    }
}
