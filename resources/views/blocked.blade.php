<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Restricted</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .blocked-container {
            background: white;
            border-radius: 16px;
            padding: 50px 40px;
            max-width: 500px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        .icon-container {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            animation: pulse 2s ease-in-out infinite;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.05); }
        }

        .icon {
            width: 40px;
            height: 40px;
            color: white;
        }

        h1 {
            font-size: 28px;
            color: #1a202c;
            margin-bottom: 15px;
            font-weight: 700;
        }

        .description {
            font-size: 16px;
            color: #4a5568;
            line-height: 1.6;
            margin-bottom: 30px;
        }

        .info-box {
            background: #f7fafc;
            border-left: 4px solid #667eea;
            padding: 20px;
            margin-bottom: 30px;
            text-align: left;
            border-radius: 8px;
        }

        .info-box h3 {
            font-size: 14px;
            color: #2d3748;
            margin-bottom: 10px;
            font-weight: 600;
        }

        .info-box ul {
            list-style: none;
            padding: 0;
        }

        .info-box li {
            font-size: 14px;
            color: #4a5568;
            margin-bottom: 8px;
            padding-left: 24px;
            position: relative;
        }

        .info-box li::before {
            content: '✓';
            position: absolute;
            left: 0;
            color: #667eea;
            font-weight: bold;
        }

        .status {
            display: inline-block;
            background: #fed7d7;
            color: #c53030;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 20px;
        }

        .status.checking {
            background: #feebc8;
            color: #c05621;
        }

        .status.success {
            background: #c6f6d5;
            color: #2f855a;
        }

        .button {
            display: inline-block;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 14px 32px;
            border-radius: 8px;
            text-decoration: none;
            font-weight: 600;
            font-size: 15px;
            transition: transform 0.2s, box-shadow 0.2s;
            border: none;
            cursor: pointer;
        }

        .button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 30px rgba(102, 126, 234, 0.4);
        }

        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e2e8f0;
            font-size: 13px;
            color: #718096;
        }

        .monitoring {
            display: none;
            margin-top: 20px;
            font-size: 14px;
            color: #4a5568;
        }

        .monitoring.active {
            display: block;
        }

        @keyframes blink {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        .blink {
            animation: blink 1.5s ease-in-out infinite;
        }
    </style>
</head>
<body>
    <div class="blocked-container">
        <div class="icon-container">
            <svg class="icon" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
            </svg>
        </div>

        <h1>Access Restricted</h1>
        
        <div class="status" id="status">
            🚫 Developer Tools Detected
        </div>

        <p class="description">
            For security reasons, access is restricted while browser developer tools are open.
            This helps protect your data and prevent unauthorized access.
        </p>

        <div class="info-box">
            <h3>To continue, please:</h3>
            <ul>
                <li>Close the developer tools/console</li>
                <li>Close the debugger if active</li>
                <li>Wait for automatic verification</li>
            </ul>
        </div>

        <div class="monitoring">
            <span class="blink">●</span> Monitoring for developer tools closure...
        </div>

        <button class="button" onclick="checkManually()">Check Now</button>

        <div class="footer">
            Protected by <strong>Laravel Security</strong> v2.0.0<br>
            Having issues? Contact your administrator
        </div>
    </div>

    <script>
        (function() {
            'use strict';

            const previousUrl = sessionStorage.getItem('af_security_prev_url') || '/';
            const statusEl = document.getElementById('status');
            const monitoringEl = document.querySelector('.monitoring');
            let checkInterval = null;

            /**
             * Quick DevTools detection
             */
            function detectDevTools() {
                const widthDiff = window.outerWidth - window.innerWidth;
                const heightDiff = window.outerHeight - window.innerHeight;
                
                // Method 1: Size check
                if (widthDiff > 160 || heightDiff > 160) {
                    return true;
                }

                // Method 2: Console check
                let consoleOpened = false;
                const detector = {
                    toString: function() {
                        consoleOpened = true;
                        return '';
                    }
                };
                console.log('%c', detector);
                
                if (consoleOpened) {
                    return true;
                }

                // Method 3: Timing check
                const start = performance.now();
                for (let i = 0; i < 100000; i++) {}
                const elapsed = performance.now() - start;
                
                return elapsed > 120;
            }

            /**
             * Check if DevTools are still open
             */
            function checkDevToolsStatus() {
                const detected = detectDevTools();

                if (!detected) {
                    // DevTools closed! Redirect back
                    statusEl.textContent = '✓ Verification Successful';
                    statusEl.className = 'status success';
                    monitoringEl.classList.remove('active');

                    console.info('[Security] DevTools closed - redirecting back');

                    setTimeout(() => {
                        window.location.replace(previousUrl);
                    }, 500);

                    return true;
                }

                return false;
            }

            /**
             * Manual check button handler
             */
            window.checkManually = function() {
                statusEl.textContent = '🔄 Checking...';
                statusEl.className = 'status checking';

                setTimeout(() => {
                    if (!checkDevToolsStatus()) {
                        statusEl.textContent = '🚫 Developer Tools Still Detected';
                        statusEl.className = 'status';
                    }
                }, 500);
            };

            /**
             * Start automatic monitoring
             */
            function startMonitoring() {
                monitoringEl.classList.add('active');

                // Check every 700ms
                checkInterval = setInterval(() => {
                    checkDevToolsStatus();
                }, 700);
            }

            /**
             * Initialize
             */
            function init() {
                console.warn('[Security] Access blocked - Developer tools detected');
                console.warn('[Security] Close developer tools to continue');

                // Start monitoring after short delay
                setTimeout(startMonitoring, 1000);

                // Prevent keyboard shortcuts
                document.addEventListener('keydown', (e) => {
                    // F12, Ctrl+Shift+I, etc.
                    if (e.key === 'F12' || 
                        ((e.ctrlKey || e.metaKey) && e.shiftKey && ['I', 'J', 'C'].includes(e.key))) {
                        e.preventDefault();
                        return false;
                    }
                });

                // Prevent right-click
                document.addEventListener('contextmenu', (e) => {
                    e.preventDefault();
                    return false;
                });
            }

            // Cleanup on unload
            window.addEventListener('beforeunload', () => {
                if (checkInterval) {
                    clearInterval(checkInterval);
                }
            });

            // Start on load
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', init);
            } else {
                init();
            }

        })();
    </script>
</body>
</html>
