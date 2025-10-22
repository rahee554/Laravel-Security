<?php

use ArtflowStudio\LaravelSecurity\Http\Controllers\HandshakeController;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| Console Security Routes
|--------------------------------------------------------------------------
|
| These routes handle the handshake verification, token renewal, and status
| checking for the Console Security module. They are excluded from the
| ConsoleStrictMiddleware to prevent infinite redirects.
|
*/

// Handshake endpoints (excluded from console:strict middleware)
Route::prefix('_security/handshake')->name('console-security.')->group(function () {
    
    // Initial handshake verification - sets security cookie
    Route::post('/verify', [HandshakeController::class, 'verify'])
        ->name('verify')
        ->middleware(['web']);

    // Token renewal endpoint - prevents 419 errors
    Route::post('/renew', [HandshakeController::class, 'renew'])
        ->name('renew')
        ->middleware(['web']);

    // Status check endpoint - for debugging/monitoring
    Route::get('/status', [HandshakeController::class, 'status'])
        ->name('status')
        ->middleware(['web']);

    // Revoke token endpoint - logout/invalidate
    Route::post('/revoke', [HandshakeController::class, 'revoke'])
        ->name('revoke')
        ->middleware(['web']);
});

// Blocked page route
Route::get('/blocked', function () {
    return view('laravel-security::blocked');
})->name('console-security.blocked');

// Loader page route (fallback - normally shown by middleware)
Route::get('/loader', function () {
    return view('laravel-security::loader', [
        'previousUrl' => request()->query('return', '/'),
        'csrfToken' => csrf_token(),
    ]);
})->name('console-security.loader');
