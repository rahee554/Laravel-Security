/**
 * Laravel Security - Console Security Module
 * 
 * Multi-layered DevTools detection, console tampering prevention,
 * and automatic token renewal system.
 * 
 * @package artflow-studio/laravel-security
 * @version 2.0.0
 */

(function() {
    'use strict';

    // Configuration
    const config = {
        sizeThreshold: window.AF_SECURITY_SIZE_THRESHOLD || 160,
        timingThreshold: window.AF_SECURITY_TIMING_THRESHOLD || 120,
        loopIterations: window.AF_SECURITY_LOOP_ITERATIONS || 100000,
        renewalInterval: window.AF_SECURITY_RENEWAL_INTERVAL || 30000, // 30 seconds
        csrfToken: document.querySelector('meta[name="csrf-token"]')?.content,
        blockedUrl: window.AF_SECURITY_BLOCKED_URL || '/blocked',
        handshakeUrl: window.AF_SECURITY_HANDSHAKE_URL || '/_security/handshake',
    };

    // State management
    let devToolsDetected = false;
    let consoleTampered = false;
    let renewalTimer = null;
    let detectionTimer = null;

    // Lightweight logger: only prints info/log when AF_SECURITY_DEBUG is truthy.
    const DEBUG = !!window.AF_SECURITY_DEBUG;
    const logger = {
        log: (...args) => { if (DEBUG) console.log(...args); },
        info: (...args) => { if (DEBUG) console.info(...args); },
        warn: (...args) => { console.warn(...args); },
        error: (...args) => { console.error(...args); },
    };

    /**
     * Method 1: Window size difference detection
     * DevTools (especially docked) changes the window dimensions
     */
    function detectViaSizeDifference() {
        const widthDiff = window.outerWidth - window.innerWidth;
        const heightDiff = window.outerHeight - window.innerHeight;
        
        return widthDiff > config.sizeThreshold || heightDiff > config.sizeThreshold;
    }

    /**
     * Method 2: Console toString trick
     * When console is open, objects are inspected and toString is called
     * Also checks for Firebug/DevTools globals
     */
    function detectViaConsoleLog() {
        let detected = false;
        
        // Check for Firebug
        if (window.Firebug && window.Firebug.chrome && window.Firebug.chrome.isInitialized) {
            return true;
        }
        
        // Check for Chrome DevTools
        if (window.devtools && window.devtools.open) {
            return true;
        }
        
        const devtoolsDetector = {
            toString: function() {
                detected = true;
                return '';
            },
            // Some consoles call inspect/other hooks
            inspect: function() {
                detected = true;
                return '';
            }
        };

        try {
            // Use multiple console APIs to increase the chance the inspector touches the object
            console.log('%c', devtoolsDetector);
            if (console.dir) console.dir(devtoolsDetector);
            if (console.debug) console.debug(devtoolsDetector);
        } catch (e) {
            // ignore
        }

        return detected;
    }

    /**
     * Method 3: Performance timing analysis
     * Synchronous loops run slower when DevTools is open
     */
    function detectViaTimingAnalysis() {
        const start = performance.now();
        
        // Tight loop - runs slower with DevTools open
        for (let i = 0; i < config.loopIterations; i++) {
            // Empty loop
        }
        
        const elapsed = performance.now() - start;
        
        return elapsed > config.timingThreshold;
    }

    /**
     * Method 4: debugger statement timing
     * If debugger is active, this pauses execution
     */
    function detectViaDebugger() {
        const start = Date.now();
        // debugger; // Commented out - uncomment for stricter detection
        const elapsed = Date.now() - start;
        
        return elapsed > 100; // More than 100ms = debugger was active
    }

    /**
     * Multi-method DevTools detection
     * All methods must agree to reduce false positives
     */
    function detectDevTools() {
        const results = {
            size: detectViaSizeDifference(),
            console: detectViaConsoleLog(),
            timing: detectViaTimingAnalysis(),
        };

        // If console.toString trick detects DevTools, treat it as definitive for undocked DevTools
        if (results.console) {
            return true;
        }

        // Otherwise require at least 2 out of 3 methods to agree (helps avoid false positives)
        const detectedCount = Object.values(results).filter(Boolean).length;
        return detectedCount >= 2;
    }

    /**
     * Console tampering detection
     * Detects if console methods have been overridden
     */
    function detectConsoleTampering() {
        const originalConsole = {
            log: console.log,
            warn: console.warn,
            error: console.error,
            info: console.info,
            debug: console.debug,
        };

        // Check if console methods are native
        for (const [method, original] of Object.entries(originalConsole)) {
            if (console[method].toString() !== original.toString()) {
                return true;
            }
        }

        // Check for console.clear override
        if (console.clear.toString().indexOf('[native code]') === -1) {
            return true;
        }

        return false;
    }

    /**
     * Detect suspicious network activity
     * Monitors fetch/XHR for unusual patterns
     */
    function monitorNetworkActivity() {
        let requestCount = 0;
        let lastReset = Date.now();

        // Wrap fetch
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            requestCount++;
            
            // Check for suspicious velocity (>50 requests per second)
            if (requestCount > 50 && (Date.now() - lastReset) < 1000) {
                console.warn('[Security] Suspicious network activity detected');
                // Optionally block or report
            }

            // Reset counter every second
            if (Date.now() - lastReset > 1000) {
                requestCount = 0;
                lastReset = Date.now();
            }

            return originalFetch.apply(this, args);
        };

        // Wrap XMLHttpRequest
        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(...args) {
            requestCount++;
            return originalOpen.apply(this, args);
        };
    }

    /**
     * Detect prototype pollution attempts
     */
    function detectPrototypePollution() {
        const dangerous = ['__proto__', 'constructor', 'prototype'];
        
        for (const prop of dangerous) {
            try {
                if (Object.prototype.hasOwnProperty.call(window, prop)) {
                    console.error('[Security] Prototype pollution detected');
                    return true;
                }
            } catch (e) {
                // Access denied - good
            }
        }

        return false;
    }

    /**
     * Verify handshake token with server
     */
    async function verifyHandshake() {
        try {
            const response = await fetch(`${config.handshakeUrl}/verify`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': config.csrfToken,
                    'X-Requested-With': 'XMLHttpRequest',
                },
            });

            if (!response.ok) {
                throw new Error('Handshake failed');
            }

            const data = await response.json();
            
            if (data.ok) {
                logger.info('[Security] Handshake successful');
                return true;
            }

            return false;

        } catch (error) {
            console.error('[Security] Handshake error:', error);
            return false;
        }
    }

    /**
     * Renew token before expiration (prevents 419 errors)
     */
    async function renewToken() {
        try {
            const response = await fetch(`${config.handshakeUrl}/renew`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-TOKEN': config.csrfToken,
                    'X-Requested-With': 'XMLHttpRequest',
                },
            });

            if (!response.ok) {
                throw new Error('Token renewal failed');
            }

            const data = await response.json();
            
            if (data.renewed) {
                logger.info('[Security] Token renewed successfully');
                return true;
            }

            return false;

        } catch (error) {
            console.error('[Security] Token renewal error:', error);
            
            // If renewal fails, redirect to reload page
            if (error.message.includes('401')) {
                window.location.reload();
            }

            return false;
        }
    }

    /**
     * Block access and redirect to blocked page
     */
    function blockAccess() {
        // Store current URL for return after closing DevTools
        sessionStorage.setItem('af_security_prev_url', window.location.href);
        
        // Redirect to blocked page
        window.location.replace(config.blockedUrl);
    }

    /**
     * Start continuous detection monitoring
     */
    function startDetection() {
        // Run detection immediately on start
        if (detectDevTools()) {
            if (!devToolsDetected) {
                devToolsDetected = true;
                console.error('[Security] DevTools detected on start - blocking access');
                blockAccess();
                return; // Stop here since we're redirecting
            }
        }

        // Then continue with interval checks
        detectionTimer = setInterval(() => {
            // Check DevTools
            if (detectDevTools()) {
                if (!devToolsDetected) {
                    devToolsDetected = true;
                    console.error('[Security] DevTools detected - blocking access');
                    blockAccess();
                }
            } else {
                devToolsDetected = false;
            }

            // Check console tampering
            if (detectConsoleTampering()) {
                if (!consoleTampered) {
                    consoleTampered = true;
                    console.error('[Security] Console tampering detected');
                    // Optionally block or report
                }
            }

            // Check prototype pollution
            if (detectPrototypePollution()) {
                console.error('[Security] Prototype pollution detected');
                blockAccess();
            }

        }, 500); // Check every 500ms for faster detection
    }

    /**
     * Start automatic token renewal
     */
    function startAutoRenewal() {
        renewalTimer = setInterval(async () => {
            await renewToken();
        }, config.renewalInterval);
    }

    /**
     * Stop all monitoring (for cleanup)
     */
    function stopMonitoring() {
        if (detectionTimer) {
            clearInterval(detectionTimer);
            detectionTimer = null;
        }

        if (renewalTimer) {
            clearInterval(renewalTimer);
            renewalTimer = null;
        }
    }

    /**
     * Initialize security module
     */
    async function init() {
        logger.info('[Security] Console Security Module v2.0.0');

        // Check for DevTools on page load
        if (detectDevTools()) {
            console.error('[Security] DevTools detected on load - blocking');
            blockAccess();
            return;
        }

        // Verify handshake (if on loader page, this will set cookie)
        const verified = await verifyHandshake();
        
        if (verified) {
            // Start continuous monitoring
            startDetection();

            // Start auto-renewal
            startAutoRenewal();

            // Monitor network activity
            monitorNetworkActivity();

            logger.info('[Security] Protection active');

            // If on loader page, reload to main app
            if (window.location.pathname === '/loader') {
                window.location.reload();
            }
        } else {
            console.error('[Security] Handshake failed');
        }
    }

    /**
     * Cleanup on page unload
     */
    window.addEventListener('beforeunload', () => {
        stopMonitoring();
    });

    /**
     * Detect keyboard shortcuts for DevTools
     * Shows user-friendly alerts instead of silent blocking
     */
    document.addEventListener('keydown', (e) => {
        let blocked = false;
        let keyName = '';

        // F12
        if (e.key === 'F12' || e.keyCode === 123) {
            e.preventDefault();
            keyName = 'F12';
            blocked = true;
        }

        // Ctrl+Shift+I / Cmd+Option+I
        else if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'I' || e.key === 'i')) {
            e.preventDefault();
            keyName = (e.metaKey ? 'Cmd' : 'Ctrl') + '+Shift+I';
            blocked = true;
        }

        // Ctrl+Shift+J / Cmd+Option+J (Console)
        else if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'J' || e.key === 'j')) {
            e.preventDefault();
            keyName = (e.metaKey ? 'Cmd' : 'Ctrl') + '+Shift+J';
            blocked = true;
        }

        // Ctrl+Shift+C / Cmd+Option+C (Inspect)
        else if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'C' || e.key === 'c')) {
            e.preventDefault();
            keyName = (e.metaKey ? 'Cmd' : 'Ctrl') + '+Shift+C';
            blocked = true;
        }

        // Ctrl+U (View Source)
        else if ((e.ctrlKey || e.metaKey) && (e.key === 'u' || e.key === 'U')) {
            e.preventDefault();
            keyName = (e.metaKey ? 'Cmd' : 'Ctrl') + '+U';
            blocked = true;
        }

        // Show alert if keyboard shortcut was blocked
        if (blocked) {
            logger.warn(`[Security] Keyboard shortcut blocked: ${keyName}`);
            alert(`⚠️ Security Alert\n\nThe keyboard shortcut "${keyName}" is blocked for security reasons.\n\nThis application is protected against unauthorized developer tools access.`);

            // After the shortcut, check quickly if DevTools opened and blockAccess if so
            try {
                setTimeout(() => {
                    if (detectDevTools()) {
                        logger.error('[Security] DevTools opened via keyboard shortcut - blocking access');
                        blockAccess();
                    }
                }, 300);
            } catch (err) {
                // ignore
            }

            return false;
        }
    });

    /**
     * Right-click is ALLOWED - Only DevTools is blocked, not normal browser features
     * Users can right-click normally, but opening "Inspect Element" will trigger blocked page
     */

    /**
     * Detect window resize (DevTools docking)
     */
    window.addEventListener('resize', () => {
        if (detectViaSizeDifference()) {
            console.warn('[Security] Suspicious window resize detected');
        }
    });

    /**
     * Detect Inspect Element from context menu
     * Some browsers open DevTools when user selects "Inspect" from right-click.
     * We listen for the contextmenu event and after it we briefly check if DevTools opened.
     */
    document.addEventListener('contextmenu', (e) => {
        try {
            // Allow normal context menu to appear for users
            // But schedule a quick check: if DevTools opens immediately after, block access.
            setTimeout(() => {
                if (detectDevTools()) {
                    logger.error('[Security] Inspect/Context menu triggered DevTools - blocking access');
                    blockAccess();
                }
            }, 500); // give browser a short moment to open DevTools
        } catch (err) {
            console.error('[Security] Contextmenu detection error', err);
        }
    });

    // Start on DOM ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose API for manual control (optional)
    window.AF_SECURITY = {
        detectDevTools,
        renewToken,
        stopMonitoring,
        startDetection,
        startAutoRenewal,
    };

})();
