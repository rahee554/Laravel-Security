<?php

namespace ArtflowStudio\LaravelSecurity\Support;

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Illuminate\Encryption\Encrypter;

class SecurityToken
{
    /**
     * Token lifetime in minutes
     */
    protected static int $lifetime = 5;

    /**
     * Grace period in seconds before token considered expired
     */
    protected static int $gracePeriod = 60;

    /**
     * Auto-renewal threshold in seconds (renew when this much time left)
     */
    protected static int $renewalThreshold = 60;

    /**
     * Generate a new security token and bind it to the session
     *
     * @return array ['token' => string, 'encrypted' => string, 'expires_at' => int]
     */
    public static function generate(): array
    {
        $token = (string) Str::uuid();
        $expiresAt = now()->addMinutes(static::$lifetime)->timestamp;

        // Store token in session with expiration
        Session::put('_security_token', $token);
        Session::put('_security_token_expires_at', $expiresAt);
        Session::put('_security_token_created_at', now()->timestamp);

        // Encrypt token for cookie
        $encrypted = encrypt([
            'token' => $token,
            'expires_at' => $expiresAt,
            'session_id' => Session::getId(),
            'user_agent' => request()->userAgent(),
            'ip' => request()->ip(),
        ]);

        return [
            'token' => $token,
            'encrypted' => $encrypted,
            'expires_at' => $expiresAt,
        ];
    }

    /**
     * Verify a token from cookie against session
     *
     * @param string $encryptedToken
     * @return bool
     */
    public static function verify(string $encryptedToken): bool
    {
        try {
            // Decrypt token
            $data = decrypt($encryptedToken);

            // Validate structure
            if (!isset($data['token'], $data['expires_at'], $data['session_id'])) {
                return false;
            }

            // Check if expired
            if (now()->timestamp > $data['expires_at'] + static::$gracePeriod) {
                return false;
            }

            // Verify session binding
            if ($data['session_id'] !== Session::getId()) {
                return false;
            }

            // Verify token matches session
            $sessionToken = Session::get('_security_token');
            if (!$sessionToken || !hash_equals($sessionToken, $data['token'])) {
                return false;
            }

            // Verify session hasn't expired
            $sessionExpiry = Session::get('_security_token_expires_at');
            if (!$sessionExpiry || now()->timestamp > $sessionExpiry + static::$gracePeriod) {
                return false;
            }

            // Additional fingerprint validation (optional but recommended)
            if (config('console-security.token.fingerprint_validation', true)) {
                // Verify user agent hasn't changed (prevents session hijacking)
                if (isset($data['user_agent']) && $data['user_agent'] !== request()->userAgent()) {
                    return false;
                }

                // Verify IP hasn't changed (strict mode - may cause issues with mobile networks)
                if (config('console-security.token.strict_ip_check', false)) {
                    if (isset($data['ip']) && $data['ip'] !== request()->ip()) {
                        return false;
                    }
                }
            }

            return true;

        } catch (\Exception $e) {
            // Log decryption errors (could indicate tampering)
            if (config('console-security.logging.enabled', true)) {
                logger()->warning('SecurityToken verification failed', [
                    'error' => $e->getMessage(),
                    'ip' => request()->ip(),
                    'user_agent' => request()->userAgent(),
                ]);
            }
            return false;
        }
    }

    /**
     * Renew an existing token (creates new token, invalidates old one)
     *
     * @return array ['token' => string, 'encrypted' => string, 'expires_at' => int]
     */
    public static function renew(): array
    {
        // Invalidate old token
        static::revoke();

        // Generate new token
        return static::generate();
    }

    /**
     * Check if token is expiring soon and needs renewal
     *
     * @param string|null $encryptedToken
     * @return bool
     */
    public static function isExpiring(?string $encryptedToken = null): bool
    {
        // Check session expiry if no token provided
        if (!$encryptedToken) {
            $expiresAt = Session::get('_security_token_expires_at');
            if (!$expiresAt) {
                return true; // No token = needs generation
            }

            $timeLeft = $expiresAt - now()->timestamp;
            return $timeLeft <= static::$renewalThreshold;
        }

        // Check encrypted token expiry
        try {
            $data = decrypt($encryptedToken);
            if (!isset($data['expires_at'])) {
                return true;
            }

            $timeLeft = $data['expires_at'] - now()->timestamp;
            return $timeLeft <= static::$renewalThreshold;

        } catch (\Exception $e) {
            return true; // Invalid token = needs renewal
        }
    }

    /**
     * Revoke current session token
     *
     * @return void
     */
    public static function revoke(): void
    {
        Session::forget('_security_token');
        Session::forget('_security_token_expires_at');
        Session::forget('_security_token_created_at');
    }

    /**
     * Get remaining time for current token in seconds
     *
     * @return int
     */
    public static function remainingTime(): int
    {
        $expiresAt = Session::get('_security_token_expires_at');
        if (!$expiresAt) {
            return 0;
        }

        $remaining = $expiresAt - now()->timestamp;
        return max(0, $remaining);
    }

    /**
     * Get token metadata (creation time, expiry, age)
     *
     * @return array
     */
    public static function metadata(): array
    {
        return [
            'token' => Session::get('_security_token'),
            'created_at' => Session::get('_security_token_created_at'),
            'expires_at' => Session::get('_security_token_expires_at'),
            'age_seconds' => Session::get('_security_token_created_at') 
                ? now()->timestamp - Session::get('_security_token_created_at') 
                : null,
            'remaining_seconds' => static::remainingTime(),
            'is_expiring' => static::isExpiring(),
        ];
    }

    /**
     * Set token lifetime in minutes
     *
     * @param int $minutes
     * @return void
     */
    public static function setLifetime(int $minutes): void
    {
        static::$lifetime = $minutes;
    }

    /**
     * Set grace period in seconds
     *
     * @param int $seconds
     * @return void
     */
    public static function setGracePeriod(int $seconds): void
    {
        static::$gracePeriod = $seconds;
    }

    /**
     * Set renewal threshold in seconds
     *
     * @param int $seconds
     * @return void
     */
    public static function setRenewalThreshold(int $seconds): void
    {
        static::$renewalThreshold = $seconds;
    }

    /**
     * Check if token rotation is needed (for long-lived sessions)
     *
     * @return bool
     */
    public static function needsRotation(): bool
    {
        $createdAt = Session::get('_security_token_created_at');
        if (!$createdAt) {
            return true;
        }

        $age = now()->timestamp - $createdAt;
        $rotationInterval = config('console-security.token.rotation_interval', 240); // 4 minutes default

        return $age >= $rotationInterval;
    }

    /**
     * Validate token and auto-renew if needed
     *
     * @param string $encryptedToken
     * @return array ['valid' => bool, 'renewed' => bool, 'token' => array|null]
     */
    public static function validateAndRenew(string $encryptedToken): array
    {
        // First verify token is valid
        if (!static::verify($encryptedToken)) {
            return [
                'valid' => false,
                'renewed' => false,
                'token' => null,
            ];
        }

        // Check if renewal needed
        if (static::isExpiring($encryptedToken) || static::needsRotation()) {
            $newToken = static::renew();

            return [
                'valid' => true,
                'renewed' => true,
                'token' => $newToken,
            ];
        }

        return [
            'valid' => true,
            'renewed' => false,
            'token' => null,
        ];
    }
}
