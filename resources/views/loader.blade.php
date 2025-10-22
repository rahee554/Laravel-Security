<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="{{ $csrfToken }}">
    <title>Loading...</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
        }

        .loader-container {
            text-align: center;
            color: white;
        }

        .noscript-error {
            background: rgba(239, 68, 68, 0.9);
            color: white;
            padding: 30px;
            border-radius: 12px;
            max-width: 500px;
            margin: 20px;
            text-align: center;
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
        }

        .noscript-error h1 {
            font-size: 28px;
            margin-bottom: 15px;
            animation: none;
            opacity: 1;
        }

        .noscript-error p {
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 10px;
            animation: none;
            opacity: 1;
        }

        .noscript-error strong {
            display: block;
            margin-top: 20px;
            font-size: 18px;
        }

        .spinner {
            width: 60px;
            height: 60px;
            margin: 0 auto 30px;
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-top-color: white;
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        h1 {
            font-size: 24px;
            font-weight: 600;
            margin-bottom: 10px;
            opacity: 0;
            animation: fadeIn 0.5s ease-out 0.3s forwards;
        }

        p {
            font-size: 14px;
            opacity: 0.9;
            opacity: 0;
            animation: fadeIn 0.5s ease-out 0.6s forwards;
        }

        @keyframes fadeIn {
            to { opacity: 1; }
        }

        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 255, 255, 0.2);
            padding: 10px 20px;
            border-radius: 20px;
            margin-top: 30px;
            font-size: 13px;
            opacity: 0;
            animation: fadeIn 0.5s ease-out 0.9s forwards;
        }

        .security-icon {
            width: 16px;
            height: 16px;
        }

        .error-message {
            display: none;
            background: rgba(239, 68, 68, 0.2);
            border: 1px solid rgba(239, 68, 68, 0.5);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-top: 30px;
            max-width: 400px;
            text-align: left;
        }

        .error-message.show {
            display: block;
        }

        .dots {
            display: inline-block;
        }

        .dots::after {
            content: '';
            animation: dots 1.5s steps(4, end) infinite;
        }

        @keyframes dots {
            0%, 20% { content: ''; }
            40% { content: '.'; }
            60% { content: '..'; }
            80%, 100% { content: '...'; }
        }
    </style>
</head>
<body>
    <!-- NoScript Warning - Shown ONLY if JavaScript is disabled -->
    <noscript>
        <div class="noscript-error">
            <h1>🚫 JavaScript Required</h1>
            <p>This application requires JavaScript to function properly and ensure security.</p>
            <p><strong>JavaScript is currently disabled in your browser.</strong></p>
            <p>Please enable JavaScript to continue:</p>
            <ul style="text-align: left; margin: 20px auto; display: inline-block;">
                <li style="margin: 10px 0;">Open your browser settings</li>
                <li style="margin: 10px 0;">Find the "JavaScript" or "Content" section</li>
                <li style="margin: 10px 0;">Enable JavaScript</li>
                <li style="margin: 10px 0;">Reload this page</li>
            </ul>
            <strong>If you're using a JavaScript blocker extension, please whitelist this site.</strong>
        </div>
    </noscript>

    <!-- Normal loader - Only shown when JavaScript is enabled -->
    <div class="loader-container">
        <div class="spinner"></div>
        <h1>Verifying Security<span class="dots"></span></h1>
        <p>Please wait while we verify your browser</p>
        
        <div class="security-badge">
            <svg class="security-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
            </svg>
            Protected by Laravel Security
        </div>

        <div class="error-message" id="error-message">
            <strong>Connection Failed</strong><br>
            Unable to verify security. Please check your connection and try again.
        </div>
    </div>

    <script>
        (function() {
            'use strict';

            const csrfToken = document.querySelector('meta[name="csrf-token"]').content;
            const previousUrl = @json($previousUrl ?? '/');
            let attemptCount = 0;
            const maxAttempts = 3;

            /**
             * Quick DevTools detection before handshake
             */
            function quickDevToolsCheck() {
                const widthDiff = window.outerWidth - window.innerWidth;
                const heightDiff = window.outerHeight - window.innerHeight;
                
                return widthDiff > 160 || heightDiff > 160;
            }

            /**
             * Perform handshake with server
             */
            async function performHandshake() {
                try {
                    // Check for DevTools before handshake
                    if (quickDevToolsCheck()) {
                        console.error('[Security] DevTools detected - redirecting to blocked page');
                        window.location.replace('/blocked');
                        return;
                    }

                    attemptCount++;

                    const response = await fetch('/_security/handshake/verify', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-TOKEN': csrfToken,
                            'X-Requested-With': 'XMLHttpRequest',
                        },
                    });

                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}`);
                    }

                    const data = await response.json();

                    if (data.ok) {
                        // Handshake successful - redirect to original page
                        console.info('[Security] Handshake successful - loading application');
                        
                        // Small delay to ensure cookie is set
                        setTimeout(() => {
                            window.location.replace(previousUrl);
                        }, 100);
                    } else {
                        throw new Error(data.error || 'Handshake failed');
                    }

                } catch (error) {
                    console.error('[Security] Handshake error:', error);

                    if (attemptCount < maxAttempts) {
                        // Retry with exponential backoff
                        const delay = Math.pow(2, attemptCount) * 1000;
                        console.info(`[Security] Retrying in ${delay}ms (attempt ${attemptCount}/${maxAttempts})`);
                        
                        setTimeout(performHandshake, delay);
                    } else {
                        // Max attempts reached - show error
                        document.getElementById('error-message').classList.add('show');
                        
                        // Offer manual reload after 5 seconds
                        setTimeout(() => {
                            if (confirm('Security verification failed. Would you like to reload the page?')) {
                                window.location.reload();
                            }
                        }, 5000);
                    }
                }
            }

            /**
             * Initialize on page load
             */
            function init() {
                // Small delay to allow metrics to stabilize
                setTimeout(() => {
                    performHandshake();
                }, 300);
            }

            // Start when DOM is ready
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', init);
            } else {
                init();
            }

        })();
    </script>
</body>
</html>
