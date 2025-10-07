<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;
use Illuminate\Support\Facades\Route;

class RateLimitScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Rate Limiting Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks if routes have proper rate limiting to prevent brute-force and DoS attacks';
    }

    protected function execute(): void
    {
        $this->checkRouteRateLimiting();
        $this->checkApiRateLimiting();
        $this->checkAuthenticationRateLimiting();
    }

    protected function checkRouteRateLimiting(): void
    {
        if (!$this->isConfigEnabled('rate_limit.check_routes')) {
            return;
        }

        $routes = Route::getRoutes();
        $this->result->setFilesScanned(count($routes));

        foreach ($routes as $route) {
            $middleware = $route->middleware();
            $uri = $route->uri();
            $methods = $route->methods();

            // Skip GET requests to non-sensitive endpoints
            if (in_array('GET', $methods) && !$this->isSensitiveEndpoint($uri)) {
                continue;
            }

            // Check if throttle middleware is applied
            if (!$this->hasThrottleMiddleware($middleware)) {
                $severity = $this->determineSeverity($uri, $methods);
                
                $this->addVulnerability(
                    'Route Without Rate Limiting',
                    $severity,
                    "Route '{$uri}' lacks rate limiting. This can be exploited for brute-force or DoS attacks.",
                    $route->getActionName(),
                    null,
                    implode(', ', $methods) . ' ' . $uri,
                    "Add throttle middleware: Route::middleware(['throttle:60,1'])->...",
                    [
                        'uri' => $uri,
                        'methods' => $methods,
                        'type' => 'missing_throttle'
                    ]
                );
            }
        }
    }

    protected function checkApiRateLimiting(): void
    {
        if (!$this->isConfigEnabled('rate_limit.check_api_routes')) {
            return;
        }

        $routes = Route::getRoutes();

        foreach ($routes as $route) {
            $uri = $route->uri();
            
            // Check API routes
            if (str_starts_with($uri, 'api/')) {
                $middleware = $route->middleware();
                
                if (!$this->hasThrottleMiddleware($middleware)) {
                    $this->addVulnerability(
                        'API Route Without Rate Limiting',
                        VulnerabilitySeverity::HIGH,
                        "API route '{$uri}' lacks rate limiting. APIs are common targets for abuse.",
                        $route->getActionName(),
                        null,
                        implode(', ', $route->methods()) . ' ' . $uri,
                        "Apply rate limiting: Route::middleware(['throttle:api'])->...",
                        ['uri' => $uri, 'type' => 'api_throttle']
                    );
                }
            }
        }
    }

    protected function checkAuthenticationRateLimiting(): void
    {
        if (!$this->isConfigEnabled('rate_limit.check_auth_routes')) {
            return;
        }

        $authPatterns = $this->getConfig('rate_limit.required_on_patterns', [
            '/login',
            '/register',
            '/password/reset',
            '/password/email',
        ]);

        $routes = Route::getRoutes();

        foreach ($routes as $route) {
            $uri = $route->uri();
            
            foreach ($authPatterns as $pattern) {
                if (str_contains($uri, trim($pattern, '/'))) {
                    $middleware = $route->middleware();
                    
                    if (!$this->hasThrottleMiddleware($middleware)) {
                        $this->addVulnerability(
                            'Authentication Route Without Rate Limiting',
                            VulnerabilitySeverity::CRITICAL,
                            "Authentication route '{$uri}' lacks rate limiting. This allows brute-force attacks on user accounts.",
                            $route->getActionName(),
                            null,
                            implode(', ', $route->methods()) . ' ' . $uri,
                            "Add strict rate limiting: Route::middleware(['throttle:5,1'])->... for login attempts",
                            ['uri' => $uri, 'type' => 'auth_throttle']
                        );
                    }
                }
            }
        }
    }

    protected function hasThrottleMiddleware(array $middleware): bool
    {
        foreach ($middleware as $m) {
            if (is_string($m) && (str_starts_with($m, 'throttle') || $m === 'throttle')) {
                return true;
            }
        }

        return false;
    }

    protected function isSensitiveEndpoint(string $uri): bool
    {
        $sensitivePatterns = [
            'login',
            'register',
            'password',
            'auth',
            'admin',
            'api',
            'webhook',
            'payment',
            'checkout',
        ];

        foreach ($sensitivePatterns as $pattern) {
            if (str_contains($uri, $pattern)) {
                return true;
            }
        }

        return false;
    }

    protected function determineSeverity(string $uri, array $methods): VulnerabilitySeverity
    {
        // POST, PUT, DELETE without rate limiting are more severe
        if (array_intersect($methods, ['POST', 'PUT', 'DELETE', 'PATCH'])) {
            if ($this->isSensitiveEndpoint($uri)) {
                return VulnerabilitySeverity::CRITICAL;
            }
            return VulnerabilitySeverity::HIGH;
        }

        return VulnerabilitySeverity::MEDIUM;
    }
}
