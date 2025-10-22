<?php

namespace ArtflowStudio\LaravelSecurity\Traits;

use ArtflowStudio\LaravelSecurity\Support\SecurityToken;
use Illuminate\Support\Facades\Log;

/**
 * WithConsoleSecurity Trait
 * 
 * Automatically protects Livewire components from console tampering
 * and data manipulation. Use this trait in any Livewire component
 * that handles sensitive data.
 * 
 * Usage:
 * ```php
 * use ArtflowStudio\LaravelSecurity\Traits\WithConsoleSecurity;
 * 
 * class MyComponent extends Component
 * {
 *     use WithConsoleSecurity;
 * }
 * ```
 */
trait WithConsoleSecurity
{
    /**
     * Boot the trait
     */
    public function bootWithConsoleSecurity(): void
    {
        // Validate token on component mount
        if (config('console-security.enabled', true)) {
            $this->validateSecurityToken();
        }
    }

    /**
     * Validate security token before processing Livewire requests
     * 
     * @return void
     * @throws \Illuminate\Http\Exceptions\HttpResponseException
     */
    protected function validateSecurityToken(): void
    {
        $cookieName = config('console-security.cookie.name', 'af_handshake');
        $token = request()->cookie($cookieName);

        // No token? Redirect to loader
        if (!$token) {
            $this->handleInvalidToken('Missing security token');
            return;
        }

        // Validate token
        if (!SecurityToken::verify($token)) {
            $this->handleInvalidToken('Invalid or expired security token');
            return;
        }

        // Check if token needs renewal
        if (SecurityToken::isExpiring($token)) {
            $this->handleTokenRenewal();
        }
    }

    /**
     * Handle invalid token (block request or redirect)
     * 
     * @param string $reason
     * @return void
     */
    protected function handleInvalidToken(string $reason): void
    {
        // Log the attempt
        if (config('console-security.logging.log_blocked', true)) {
            Log::warning('[Console Security] Livewire request blocked', [
                'component' => static::class,
                'reason' => $reason,
                'ip' => request()->ip(),
                'user_agent' => request()->userAgent(),
            ]);
        }

        // For AJAX/Livewire requests, return error response
        if (request()->header('X-Livewire')) {
            abort(419, 'Security token invalid. Please reload the page.');
        }

        // For regular requests, redirect to loader
        redirect()->route('console-security.loader', ['return' => url()->current()])->send();
        exit;
    }

    /**
     * Handle token renewal for long-running sessions
     * 
     * @return void
     */
    protected function handleTokenRenewal(): void
    {
        try {
            $newToken = SecurityToken::renew();

            // Emit event to client to update cookie
            $this->dispatch('security-token-renewed', [
                'expires_at' => $newToken['expires_at'],
                'expires_in' => $newToken['expires_at'] - now()->timestamp,
            ]);

            // Log renewal
            if (config('console-security.logging.log_renewals', false)) {
                Log::info('[Console Security] Token renewed in Livewire component', [
                    'component' => static::class,
                    'ip' => request()->ip(),
                ]);
            }

        } catch (\Exception $e) {
            Log::error('[Console Security] Token renewal failed in Livewire', [
                'component' => static::class,
                'error' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Validate component property modifications
     * Called before updating any public property
     * 
     * @param string $property
     * @param mixed $value
     * @return void
     */
    public function updatingWithConsoleSecurity(string $property, mixed $value): void
    {
        if (!config('console-security.livewire.validate_updates', true)) {
            return;
        }

        // Check for suspicious property modifications
        if ($this->isSuspiciousPropertyUpdate($property, $value)) {
            Log::warning('[Console Security] Suspicious property update blocked', [
                'component' => static::class,
                'property' => $property,
                'value' => $value,
                'ip' => request()->ip(),
            ]);

            // Block the update
            abort(403, 'Suspicious property modification detected');
        }
    }

    /**
     * Detect suspicious property updates
     * 
     * @param string $property
     * @param mixed $value
     * @return bool
     */
    protected function isSuspiciousPropertyUpdate(string $property, mixed $value): bool
    {
        // Check for SQL injection attempts
        if (is_string($value)) {
            $suspiciousPatterns = [
                '/union\s+select/i',
                '/drop\s+table/i',
                '/delete\s+from/i',
                '/insert\s+into/i',
                '/<script/i',
                '/javascript:/i',
                '/on\w+\s*=/i', // Event handlers like onclick=
            ];

            foreach ($suspiciousPatterns as $pattern) {
                if (preg_match($pattern, $value)) {
                    return true;
                }
            }
        }

        // Check for excessively large values (possible buffer overflow)
        if (is_string($value) && strlen($value) > 100000) {
            return true;
        }

        // Check for array/object injection
        if (is_array($value) && count($value) > 1000) {
            return true;
        }

        return false;
    }

    /**
     * Rate limit Livewire actions to prevent abuse
     * 
     * @param string $action
     * @param int $maxAttempts
     * @param int $decayMinutes
     * @return bool
     */
    protected function rateLimitLivewireAction(string $action, int $maxAttempts = 60, int $decayMinutes = 1): bool
    {
        $key = sprintf(
            'livewire-security:%s:%s:%s',
            static::class,
            $action,
            request()->ip()
        );

        if (cache()->has($key)) {
            $attempts = cache()->get($key);

            if ($attempts >= $maxAttempts) {
                Log::warning('[Console Security] Rate limit exceeded for Livewire action', [
                    'component' => static::class,
                    'action' => $action,
                    'attempts' => $attempts,
                    'ip' => request()->ip(),
                ]);

                return false;
            }

            cache()->put($key, $attempts + 1, now()->addMinutes($decayMinutes));
        } else {
            cache()->put($key, 1, now()->addMinutes($decayMinutes));
        }

        return true;
    }

    /**
     * Validate Livewire method call before execution
     * 
     * @param string $method
     * @return void
     */
    protected function validateLivewireMethodCall(string $method): void
    {
        // Check rate limit
        if (!$this->rateLimitLivewireAction($method)) {
            abort(429, 'Too many requests. Please slow down.');
        }

        // Validate method exists and is public
        if (!method_exists($this, $method)) {
            Log::warning('[Console Security] Attempt to call non-existent method', [
                'component' => static::class,
                'method' => $method,
                'ip' => request()->ip(),
            ]);

            abort(404, 'Method not found');
        }

        // Check if method is protected/private (shouldn't be callable via Livewire)
        $reflection = new \ReflectionMethod($this, $method);
        if (!$reflection->isPublic()) {
            Log::error('[Console Security] Attempt to call non-public method', [
                'component' => static::class,
                'method' => $method,
                'ip' => request()->ip(),
            ]);

            abort(403, 'Access denied');
        }
    }

    /**
     * Get security metadata for debugging
     * 
     * @return array
     */
    public function getSecurityMetadata(): array
    {
        return [
            'component' => static::class,
            'token_valid' => SecurityToken::verify(request()->cookie(config('console-security.cookie.name', 'af_handshake'))),
            'token_expiring' => SecurityToken::isExpiring(),
            'token_metadata' => SecurityToken::metadata(),
            'protected' => true,
        ];
    }
}
