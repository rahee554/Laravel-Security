<?php

namespace ArtflowStudio\LaravelSecurity\Http\Controllers;

use ArtflowStudio\LaravelSecurity\Support\SecurityToken;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\RateLimiter;

class HandshakeController extends Controller
{
    /**
     * Initial handshake - verify browser is legitimate and set security token
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function verify(Request $request): JsonResponse
    {
        // Rate limiting to prevent brute force
        $key = 'handshake-verify:' . $request->ip();
        $maxAttempts = config('console-security.rate_limiting.handshake_attempts', 30);
        $decayMinutes = config('console-security.rate_limiting.handshake_decay', 1);

        if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
            return response()->json([
                'ok' => false,
                'error' => 'Too many handshake attempts. Please try again later.',
                'retry_after' => RateLimiter::availableIn($key),
            ], 429);
        }

        RateLimiter::hit($key, $decayMinutes * 60);

        try {
            // Generate new security token
            $tokenData = SecurityToken::generate();

            // Log successful handshake if logging enabled
            if (config('console-security.logging.enabled', true)) {
                logger()->info('Security handshake successful', [
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                    'expires_at' => $tokenData['expires_at'],
                ]);
            }

            // Return success with cookie
            return response()->json([
                'ok' => true,
                'expires_at' => $tokenData['expires_at'],
                'expires_in' => $tokenData['expires_at'] - now()->timestamp,
                'message' => 'Handshake successful',
            ])->cookie(
                config('console-security.cookie.name', 'af_handshake'),
                $tokenData['encrypted'],
                config('console-security.cookie.lifetime', 5),
                '/',
                null,
                config('console-security.cookie.secure', true),
                true, // HttpOnly
                false, // Raw
                config('console-security.cookie.same_site', 'lax')
            );

        } catch (\Exception $e) {
            // Log error
            if (config('console-security.logging.enabled', true)) {
                logger()->error('Security handshake failed', [
                    'error' => $e->getMessage(),
                    'ip' => $request->ip(),
                    'user_agent' => $request->userAgent(),
                ]);
            }

            return response()->json([
                'ok' => false,
                'error' => 'Handshake failed. Please try again.',
            ], 500);
        }
    }

    /**
     * Renew existing token before expiration (prevents 419 errors)
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function renew(Request $request): JsonResponse
    {
        // Rate limiting for renewals
        $key = 'handshake-renew:' . $request->ip();
        $maxAttempts = config('console-security.rate_limiting.renewal_attempts', 60);
        $decayMinutes = config('console-security.rate_limiting.renewal_decay', 1);

        if (RateLimiter::tooManyAttempts($key, $maxAttempts)) {
            return response()->json([
                'ok' => false,
                'error' => 'Too many renewal attempts.',
                'retry_after' => RateLimiter::availableIn($key),
            ], 429);
        }

        RateLimiter::hit($key, $decayMinutes * 60);

        try {
            // Get current token from cookie
            $currentToken = $request->cookie(config('console-security.cookie.name', 'af_handshake'));

            // Verify current token is still valid
            if (!$currentToken || !SecurityToken::verify($currentToken)) {
                return response()->json([
                    'ok' => false,
                    'error' => 'Invalid or expired token. Please reload the page.',
                    'action' => 'reload',
                ], 401);
            }

            // Renew token
            $tokenData = SecurityToken::renew();

            // Log renewal if logging enabled
            if (config('console-security.logging.log_renewals', false)) {
                logger()->info('Security token renewed', [
                    'ip' => $request->ip(),
                    'expires_at' => $tokenData['expires_at'],
                ]);
            }

            return response()->json([
                'ok' => true,
                'renewed' => true,
                'expires_at' => $tokenData['expires_at'],
                'expires_in' => $tokenData['expires_at'] - now()->timestamp,
                'message' => 'Token renewed successfully',
            ])->cookie(
                config('console-security.cookie.name', 'af_handshake'),
                $tokenData['encrypted'],
                config('console-security.cookie.lifetime', 5),
                '/',
                null,
                config('console-security.cookie.secure', true),
                true, // HttpOnly
                false, // Raw
                config('console-security.cookie.same_site', 'lax')
            );

        } catch (\Exception $e) {
            // Log error
            if (config('console-security.logging.enabled', true)) {
                logger()->error('Token renewal failed', [
                    'error' => $e->getMessage(),
                    'ip' => $request->ip(),
                ]);
            }

            return response()->json([
                'ok' => false,
                'error' => 'Renewal failed. Please reload the page.',
                'action' => 'reload',
            ], 500);
        }
    }

    /**
     * Check current token status (for debugging/monitoring)
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function status(Request $request): JsonResponse
    {
        $token = $request->cookie(config('console-security.cookie.name', 'af_handshake'));

        if (!$token) {
            return response()->json([
                'valid' => false,
                'message' => 'No token present',
            ]);
        }

        $isValid = SecurityToken::verify($token);
        $isExpiring = SecurityToken::isExpiring($token);
        $metadata = SecurityToken::metadata();

        return response()->json([
            'valid' => $isValid,
            'is_expiring' => $isExpiring,
            'metadata' => $metadata,
            'message' => $isValid ? 'Token is valid' : 'Token is invalid or expired',
        ]);
    }

    /**
     * Revoke current token (logout/invalidate)
     *
     * @param Request $request
     * @return JsonResponse
     */
    public function revoke(Request $request): JsonResponse
    {
        try {
            SecurityToken::revoke();

            // Log revocation if logging enabled
            if (config('console-security.logging.enabled', true)) {
                logger()->info('Security token revoked', [
                    'ip' => $request->ip(),
                ]);
            }

            return response()->json([
                'ok' => true,
                'message' => 'Token revoked successfully',
            ])->cookie(
                config('console-security.cookie.name', 'af_handshake'),
                '', // Empty value
                -1, // Expired
                '/',
                null,
                config('console-security.cookie.secure', true),
                true,
                false,
                config('console-security.cookie.same_site', 'lax')
            );

        } catch (\Exception $e) {
            return response()->json([
                'ok' => false,
                'error' => 'Revocation failed',
            ], 500);
        }
    }
}
