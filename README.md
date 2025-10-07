# 🔒 Artflow Vulnerability Scanner

[![Latest Version on Packagist](https://img.shields.io/packagist/v/artflow-studio/scanner.svg?style=flat-square)](https://packagist.org/packages/artflow-studio/scanner)
[![Total Downloads](https://img.shields.io/packagist/dt/artflow-studio/scanner.svg?style=flat-square)](https://packagist.org/packages/artflow-studio/scanner)
[![License](https://img.shields.io/packagist/l/artflow-studio/scanner.svg?style=flat-square)](https://packagist.org/packages/artflow-studio/scanner)

A comprehensive security vulnerability scanner for Laravel and Livewire applications. Detect security issues, misconfigurations, and potential exploits before they become problems.

## ✨ Features

- 🔍 **13+ Security Scanners** - Comprehensive coverage of common vulnerabilities
- ⚡ **Livewire-Specific Scanning** - Specialized security checks for Livewire components
- 🎯 **Interactive CLI** - User-friendly command-line interface with progress indicators
- 📊 **Multiple Report Formats** - Console, JSON, HTML, and Markdown outputs
- 🎨 **Severity-Based Results** - Color-coded findings from Info to Critical
- ⚙️ **Highly Configurable** - Customize scans to match your needs
- 💡 **Fix Suggestions** - Get actionable recommendations for each vulnerability
- 🚀 **Fast & Efficient** - Static analysis without running your application

## 🛡️ What It Scans

### Core Security Scanners

1. **Livewire Scanner** - Public property exposure, missing validation, authorization gaps
2. **SQL Injection Scanner** - Raw queries, variable interpolation, unsafe where clauses
3. **XSS Scanner** - Unescaped output, JavaScript injection, URL injection
4. **Rate Limiting Scanner** - Missing throttle middleware on sensitive routes
5. **CSRF Scanner** - Missing CSRF tokens, insecure form submissions
6. **Authentication Scanner** - Password policies, session configuration
7. **Authorization Scanner** - Missing authorization checks in controllers
8. **Data Exposure Scanner** - Debug mode, sensitive logging, API leakage
9. **Function Security Scanner** - Dangerous functions (eval, exec, unserialize)
10. **File Security Scanner** - File inclusion vulnerabilities, unsafe uploads
11. **Configuration Scanner** - APP_KEY, CORS, environment issues
12. **Dependency Scanner** - Outdated packages, known vulnerabilities
13. **Console Security Scanner** - Artisan command security issues

## 📦 Installation

Require the package via Composer:

```bash
composer require artflow-studio/scanner --dev
```

The package will automatically register its service provider.

### Publish Configuration (Optional)

```bash
php artisan vendor:publish --tag=scanner-config
```

This creates `config/scanner.php` where you can customize the scanner behavior.

## 🚀 Usage

### Interactive Scan (Recommended)

Run the interactive scanner to select which checks to perform:

```bash
php artisan scan
```

This will present you with a menu to choose scanners and provide real-time progress updates.

### Scan Everything

Run all available scanners:

```bash
php artisan scan --all
```

### Specific Scanners

Run individual scanners:

```bash
# Scan Livewire components
php artisan scan:livewire

# Check rate limiting
php artisan scan:rate-limit

# Comprehensive security scan (XSS, SQL Injection, CSRF, Functions)
php artisan scan:security

# Check dependencies
php artisan scan:dependencies

# Check configuration
php artisan scan:configuration

# Check authentication
php artisan scan:authentication
```

### Generate Reports

Generate a report in different formats:

```bash
# JSON report
php artisan scan:report json --output=security-report.json

# HTML report (great for sharing)
php artisan scan:report html --output=security-report.html

# Markdown report
php artisan scan:report markdown --output=security-report.md

# Run specific scanners only
php artisan scan:report html --scanners=livewire,xss,sql-injection --output=report.html
```

## 📖 Example Output

### Console Output

```
╔══════════════════════════════════════════════════════════════╗
║        Artflow Vulnerability Scanner v1.0.0                  ║
╚══════════════════════════════════════════════════════════════╝

🔍 Livewire Security Scanner
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Scans Livewire components for security vulnerabilities

Found 3 issue(s):

🔴 [CRITICAL] Public Property Without Validation
  📁 File: app/Http/Livewire/UserProfile.php:15
  📝 Issue: Public property $email can be manipulated without validation
  💡 Fix: Add validation rules or use protected property with setter

🟠 [HIGH] Missing Authorization Check
  📁 File: app/Http/Livewire/DeleteUser.php:22
  📝 Issue: delete() method lacks authorization check
  💻 Code: public function delete()
  💡 Fix: Add $this->authorize('delete', $user)

╔══════════════════════════════════════════════════════════════╗
║                         SUMMARY                              ║
╚══════════════════════════════════════════════════════════════╝

Total Vulnerabilities: 23
Files Scanned: 187

Severity Breakdown:
  🔴 Critical: 3
  🟠 High:     7
  🟡 Medium:   12
  🔵 Low:      5
  🟢 Info:     8
```

## ⚙️ Configuration

After publishing the config file (`config/scanner.php`), you can customize scanner behavior, paths, severity thresholds, and more.

## 🎯 Livewire-Specific Features

The scanner includes specialized checks for Livewire components including public property security, authorization checks, mass assignment protection, and file upload security.

## 🚦 Requirements

- PHP 8.1 or higher
- Laravel 10.0 or Laravel 11.0
- Composer

## 📜 License

The MIT License (MIT). Please see [License File](LICENSE) for more information.

---

**Made with ❤️ by Artflow Studio**
