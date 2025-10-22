<?php

namespace ArtflowStudio\LaravelSecurity\Http\Middleware;

use ArtflowStudio\LaravelSecurity\Support\SecurityToken;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class ConsoleStrictMiddleware
{
    /**
     * Handle an incoming request
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next): mixed
    {
        // Skip if console security is disabled
        if (!config('console-security.enabled', true)) {
            return $next($request);
        }

        // Detect view-source requests - ALWAYS show loader for these
        if ($this->isViewSourceRequest($request)) {
            return $this->returnLoader($request);
        }

        // Skip for excluded paths
        if ($this->isExcludedPath($request)) {
            return $next($request);
        }

        // Skip for whitelisted IPs
        if ($this->isWhitelistedIp($request)) {
            return $next($request);
        }

        // Skip for whitelisted user agents (bots, crawlers, testing tools)
        if ($this->isWhitelistedUserAgent($request)) {
            return $next($request);
        }

        // Get security token from cookie
        $token = $request->cookie(config('console-security.cookie.name', 'af_handshake'));

        // No token? Show loader view
        if (!$token) {
            return $this->returnLoader($request);
        }

        // Validate and auto-renew token
        $result = SecurityToken::validateAndRenew($token);

        // Token invalid? Show loader view
        if (!$result['valid']) {
            // Log blocked attempt
            if (config('console-security.logging.log_blocked', true)) {
                logger()->warning('Console security blocked request - invalid token', [
                    'ip' => $request->ip(),
                    'path' => $request->path(),
                    'user_agent' => $request->userAgent(),
                ]);
            }

            return $this->returnLoader($request);
        }

        // Token was renewed? Set new cookie in response
        if ($result['renewed']) {
            $response = $next($request);

            // Log renewal if enabled
            if (config('console-security.logging.log_renewals', false)) {
                logger()->info('Console security auto-renewed token', [
                    'ip' => $request->ip(),
                    'path' => $request->path(),
                ]);
            }

            // Attach new cookie to response
            return $response->cookie(
                config('console-security.cookie.name', 'af_handshake'),
                $result['token']['encrypted'],
                config('console-security.cookie.lifetime', 5),
                '/',
                null,
                config('console-security.cookie.secure', true),
                true, // HttpOnly
                false, // Raw
                config('console-security.cookie.same_site', 'lax')
            );
        }

        // Token valid and not renewed - proceed normally
        return $next($request);
    }

    /**
     * Detect view-source requests
     * Browser sends Purpose: prefetch header or the URL starts with view-source:
     *
     * @param Request $request
     * @return bool
     */
    protected function isViewSourceRequest(Request $request): bool
    {
        // Check for Purpose: prefetch header (used by view-source in some browsers)
        if ($request->header('Purpose') === 'prefetch') {
            return true;
        }

        // Check for Sec-Purpose header
        if ($request->header('Sec-Purpose') === 'prefetch') {
            return true;
        }

        // Check if user agent indicates view-source (some browsers)
        $userAgent = $request->userAgent();
        if ($userAgent && Str::contains($userAgent, 'view-source', true)) {
            return true;
        }

        // Check referer for view-source:
        $referer = $request->header('Referer');
        if ($referer && Str::startsWith($referer, 'view-source:')) {
            return true;
        }

        return false;
    }

    /**
     * Check if current path is excluded from protection
     *
     * @param Request $request
     * @return bool
     */
    protected function isExcludedPath(Request $request): bool
    {
        $excludedPaths = config('console-security.excluded_paths', [
            '_security/*',
            'blocked',
            'loader',
            'api/*',
            'livewire/*',
            'assets/*',
            'vendor/*',
        ]);

        $currentPath = $request->path();

        foreach ($excludedPaths as $pattern) {
            if (Str::is($pattern, $currentPath)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if IP is whitelisted (admin/dev IPs)
     *
     * @param Request $request
     * @return bool
     */
    protected function isWhitelistedIp(Request $request): bool
    {
        $whitelist = config('console-security.whitelist.ips', []);

        if (empty($whitelist)) {
            return false;
        }

        $clientIp = $request->ip();

        // Support CIDR notation
        foreach ($whitelist as $ip) {
            if ($this->ipMatches($clientIp, $ip)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user agent is whitelisted (SEO bots, testing tools)
     *
     * @param Request $request
     * @return bool
     */
    protected function isWhitelistedUserAgent(Request $request): bool
    {
        $whitelist = config('console-security.whitelist.user_agents', [
            'Googlebot',
            'Bingbot',
            'Lighthouse',
            'PageSpeed',
        ]);

        if (empty($whitelist)) {
            return false;
        }

        $userAgent = $request->userAgent();

        foreach ($whitelist as $pattern) {
            if (Str::contains($userAgent, $pattern, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return the loader view with cache-control headers
     *
     * @param Request $request
     * @return \Illuminate\Http\Response
     */
    protected function returnLoader(Request $request): \Illuminate\Http\Response
    {
        $loaderView = config('console-security.responses.loader_view', 'laravel-security::loader');

        return response()
            ->view($loaderView, [
                'previousUrl' => $request->fullUrl(),
                'csrfToken' => csrf_token(),
            ])
            ->header('Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0')
            ->header('Pragma', 'no-cache')
            ->header('Expires', 'Sat, 01 Jan 2000 00:00:00 GMT');
    }

    /**
     * Check if IP matches pattern (supports CIDR notation)
     *
     * @param string $clientIp
     * @param string $pattern
     * @return bool
     */
    protected function ipMatches(string $clientIp, string $pattern): bool
    {
        // Exact match
        if ($clientIp === $pattern) {
            return true;
        }

        // CIDR notation support
        if (Str::contains($pattern, '/')) {
            [$subnet, $bits] = explode('/', $pattern);

            // Convert to long
            $clientLong = ip2long($clientIp);
            $subnetLong = ip2long($subnet);

            if ($clientLong === false || $subnetLong === false) {
                return false;
            }

            // Create mask
            $mask = -1 << (32 - (int)$bits);

            // Compare
            return ($clientLong & $mask) === ($subnetLong & $mask);
        }

        // Wildcard match (e.g., 192.168.*.*)
        if (Str::contains($pattern, '*')) {
            $regex = '/^' . str_replace(['.', '*'], ['\.', '\d+'], $pattern) . '$/';
            return preg_match($regex, $clientIp) === 1;
        }

        return false;
    }
}
