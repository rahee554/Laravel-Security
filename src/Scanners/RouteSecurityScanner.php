<?php

namespace ArtflowStudio\Scanner\Scanners;

use ArtflowStudio\Scanner\DTOs\VulnerabilitySeverity;
use Illuminate\Support\Facades\Route;

class RouteSecurityScanner extends AbstractScanner
{
    public function getName(): string
    {
        return 'Route & Endpoint Security Scanner';
    }

    public function getDescription(): string
    {
        return 'Checks route closures, middleware, authorization, rate limiting, and endpoint security';
    }

    public function isApplicable(): bool
    {
        return true; // Always applicable
    }

    protected function execute(): void
    {
        $this->checkRouteClosures();
        $this->checkMiddlewareConfiguration();
        $this->checkSensitiveRoutes();
        $this->checkRouteParameterValidation();
        $this->checkApiRoutes();
    }

    protected function checkRouteClosures(): void
    {
        $routeFiles = [
            base_path('routes/web.php'),
            base_path('routes/api.php'),
            base_path('routes/console.php'),
            base_path('routes/tenant.php'),
            base_path('routes/auth.php'),
            base_path('routes/accountflow.php'),
        ];

        foreach ($routeFiles as $routeFile) {
            if (! file_exists($routeFile)) {
                continue;
            }

            $this->result->setFilesScanned($this->result->getFilesScanned() + 1);

            $content = file_get_contents($routeFile);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                // Detect route closures: Route::get('/path', function()
                if (preg_match('/Route::(get|post|put|patch|delete|any|match|resource)\s*\([^,]+,\s*function\s*\(/i', $line)) {
                    $this->addVulnerability(
                        'Route Closure Detected',
                        VulnerabilitySeverity::MEDIUM,
                        'Route uses closure instead of controller action. This prevents route caching and may impact performance.',
                        $routeFile,
                        $lineNumber + 1,
                        $line,
                        'Convert closure to controller action: Route::get(\'/path\', [Controller::class, \'method\'])',
                        ['type' => 'route_closure']
                    );
                }
            }
        }
    }

    protected function checkMiddlewareConfiguration(): void
    {
        $routes = Route::getRoutes();
        $adminPatterns = ['admin', 'dashboard', 'manage', 'control-panel', 'backend'];
        $authPatterns = ['login', 'register', 'password', 'reset', 'verify'];

        foreach ($routes as $route) {
            $uri = $route->uri();
            $middleware = $route->middleware();
            $middlewareStr = implode(',', $middleware);

            // Check admin routes
            foreach ($adminPatterns as $pattern) {
                if (str_contains($uri, $pattern) && ! str_contains($middlewareStr, 'auth')) {
                    $this->addVulnerability(
                        'Admin Route Without Authentication',
                        VulnerabilitySeverity::CRITICAL,
                        "Route '{$uri}' appears to be an admin route but lacks 'auth' middleware.",
                        $this->getRouteDefinitionFile($uri),
                        null,
                        null,
                        "Add auth middleware: Route::middleware(['auth'])->group(...)",
                        ['type' => 'missing_auth_middleware', 'route' => $uri]
                    );
                }

                if (str_contains($uri, $pattern) && ! $this->hasRoleMiddleware($middleware)) {
                    $this->addVulnerability(
                        'Admin Route Without Role Check',
                        VulnerabilitySeverity::HIGH,
                        "Route '{$uri}' appears to be an admin route but lacks role/permission middleware.",
                        $this->getRouteDefinitionFile($uri),
                        null,
                        null,
                        "Add role middleware: Route::middleware(['auth', 'role:admin'])->group(...)",
                        ['type' => 'missing_role_middleware', 'route' => $uri]
                    );
                }
            }

            // Check auth routes
            foreach ($authPatterns as $pattern) {
                if (str_contains($uri, $pattern) && ! $this->hasRateLimiting($middleware)) {
                    $this->addVulnerability(
                        'Authentication Route Without Rate Limiting',
                        VulnerabilitySeverity::HIGH,
                        "Route '{$uri}' handles authentication but lacks rate limiting. Vulnerable to brute force attacks.",
                        $this->getRouteDefinitionFile($uri),
                        null,
                        null,
                        "Add throttle middleware: Route::middleware(['throttle:5,1'])->group(...)",
                        ['type' => 'missing_rate_limiting', 'route' => $uri]
                    );
                }
            }

            // Check POST/PUT/DELETE routes for CSRF
            $methods = $route->methods();
            if (in_array('POST', $methods) || in_array('PUT', $methods) || in_array('DELETE', $methods)) {
                if (! str_contains($middlewareStr, 'web') && ! str_contains($middlewareStr, 'VerifyCsrfToken')) {
                    $this->addVulnerability(
                        'State-Changing Route Without CSRF Protection',
                        VulnerabilitySeverity::HIGH,
                        "Route '{$uri}' accepts state-changing methods but may lack CSRF protection.",
                        $this->getRouteDefinitionFile($uri),
                        null,
                        null,
                        "Ensure route is in 'web' middleware group or add VerifyCsrfToken middleware",
                        ['type' => 'missing_csrf', 'route' => $uri, 'methods' => $methods]
                    );
                }
            }
        }
    }

    protected function checkSensitiveRoutes(): void
    {
        $routes = Route::getRoutes();
        $sensitivePatterns = [
            '/api/users' => 'User Data API',
            '/api/admin' => 'Admin API',
            '/delete' => 'Delete Operation',
            '/destroy' => 'Destroy Operation',
            '/export' => 'Data Export',
            '/download' => 'File Download',
            '/upload' => 'File Upload',
        ];

        foreach ($routes as $route) {
            $uri = $route->uri();
            $middleware = $route->middleware();
            $middlewareStr = implode(',', $middleware);

            foreach ($sensitivePatterns as $pattern => $description) {
                if (str_contains($uri, $pattern)) {
                    // Check for authentication
                    if (! str_contains($middlewareStr, 'auth') && ! str_contains($middlewareStr, 'sanctum')) {
                        $this->addVulnerability(
                            "Sensitive Route Without Authentication: {$description}",
                            VulnerabilitySeverity::CRITICAL,
                            "Route '{$uri}' performs sensitive operations but lacks authentication.",
                            $this->getRouteDefinitionFile($uri),
                            null,
                            null,
                            'Add authentication middleware: Route::middleware([\'auth\'])',
                            ['type' => 'sensitive_route_no_auth', 'route' => $uri, 'operation' => $description]
                        );
                    }

                    // Check for authorization
                    if (! $this->hasRoleMiddleware($middleware) && ! str_contains($uri, 'check-authorization')) {
                        $this->addVulnerability(
                            "Sensitive Route May Need Authorization: {$description}",
                            VulnerabilitySeverity::MEDIUM,
                            "Route '{$uri}' performs sensitive operations. Verify authorization checks are in place.",
                            $this->getRouteDefinitionFile($uri),
                            null,
                            null,
                            'Add authorization: $this->authorize(\'action\', $model) in controller or use Gate/Policy',
                            ['type' => 'sensitive_route_check_auth', 'route' => $uri, 'operation' => $description]
                        );
                    }
                }
            }
        }
    }

    protected function checkRouteParameterValidation(): void
    {
        $routeFiles = [
            base_path('routes/web.php'),
            base_path('routes/api.php'),
        ];

        foreach ($routeFiles as $routeFile) {
            if (! file_exists($routeFile)) {
                continue;
            }

            $content = file_get_contents($routeFile);
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                // Detect route parameters: {id}, {user}, {slug}
                if (preg_match('/\{(\w+)\}/', $line, $matches)) {
                    $param = $matches[1];

                    // Check if there's a where constraint
                    $nextLine = $lines[$lineNumber + 1] ?? '';
                    if (! str_contains($nextLine, "->where('{$param}'") && ! str_contains($nextLine, '->whereNumber') && ! str_contains($nextLine, '->whereAlpha')) {
                        $this->addVulnerability(
                            'Route Parameter Without Validation',
                            VulnerabilitySeverity::MEDIUM,
                            "Route parameter '{$param}' lacks validation constraint. This may allow injection attacks.",
                            $routeFile,
                            $lineNumber + 1,
                            $line,
                            "Add constraint: ->where('{$param}', '[0-9]+') or use ->whereNumber('{$param}')",
                            ['type' => 'route_param_no_validation', 'parameter' => $param]
                        );
                    }
                }
            }
        }
    }

    protected function checkApiRoutes(): void
    {
        $apiRouteFile = base_path('routes/api.php');

        if (! file_exists($apiRouteFile)) {
            return;
        }

        $content = file_get_contents($apiRouteFile);
        $routes = Route::getRoutes();

        foreach ($routes as $route) {
            if (! str_starts_with($route->uri(), 'api/')) {
                continue;
            }

            $middleware = $route->middleware();
            $middlewareStr = implode(',', $middleware);

            // Check for API authentication
            if (! str_contains($middlewareStr, 'auth:sanctum') && ! str_contains($middlewareStr, 'auth:api')) {
                $this->addVulnerability(
                    'API Route Without Authentication',
                    VulnerabilitySeverity::HIGH,
                    "API route '{$route->uri()}' lacks authentication. Consider using Sanctum or Passport.",
                    $apiRouteFile,
                    null,
                    null,
                    "Add auth:sanctum middleware: Route::middleware(['auth:sanctum'])",
                    ['type' => 'api_no_auth', 'route' => $route->uri()]
                );
            }

            // Check for rate limiting
            if (! $this->hasRateLimiting($middleware)) {
                $this->addVulnerability(
                    'API Route Without Rate Limiting',
                    VulnerabilitySeverity::MEDIUM,
                    "API route '{$route->uri()}' lacks rate limiting. API endpoints should be rate limited.",
                    $apiRouteFile,
                    null,
                    null,
                    "Add throttle middleware: Route::middleware(['throttle:60,1'])",
                    ['type' => 'api_no_rate_limit', 'route' => $route->uri()]
                );
            }
        }
    }

    protected function hasRoleMiddleware(array $middleware): bool
    {
        foreach ($middleware as $mw) {
            if (str_contains($mw, 'role') || str_contains($mw, 'permission') || str_contains($mw, 'can')) {
                return true;
            }
        }

        return false;
    }

    protected function hasRateLimiting(array $middleware): bool
    {
        foreach ($middleware as $mw) {
            if (str_contains($mw, 'throttle')) {
                return true;
            }
        }

        return false;
    }

    protected function getRouteDefinitionFile(string $uri): string
    {
        if (str_contains($uri, 'api/')) {
            return base_path('routes/api.php');
        }
        if (str_contains($uri, 'admin')) {
            return base_path('routes/web.php');
        }
        if (str_contains($uri, 'auth') || str_contains($uri, 'login') || str_contains($uri, 'register')) {
            $authFile = base_path('routes/auth.php');
            if (file_exists($authFile)) {
                return $authFile;
            }
        }

        return base_path('routes/web.php');
    }
}
