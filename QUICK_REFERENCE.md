# Quick Reference Guide - Artflow Scanner

## 🚀 Quick Start

### Interactive Mode
```bash
php artisan scan
```
- Select from 0-13 (0 for all scanners)
- View results with type breakdown
- Color-coded severity levels

### Scan All
```bash
php artisan scan --all
```
- Runs all 13 scanners at once
- Comprehensive vulnerability report
- 471 vulnerabilities found in test app

---

## 🔍 Individual Scanner Commands

```bash
php artisan scan:livewire           # Livewire components
php artisan scan:rate-limit         # Rate limiting
php artisan scan:security           # XSS, SQL, CSRF, functions
php artisan scan:authentication     # Auth & session security
php artisan scan:configuration      # Config issues
php artisan scan:dependencies       # Package vulnerabilities
```

---

## 🛠️ Auto-Fix Commands

### Preview Fixes (Safe)
```bash
php artisan scan:fix --dry-run
```
- Shows exactly what would be changed
- No files are modified
- Displays diff for each fix
- **Found 363 fixable issues in test app**

### Apply Fixes with Backup
```bash
php artisan scan:fix --backup
```
- Creates backup in `storage/scanner-backups/`
- Shows preview before applying
- Asks for confirmation
- Displays progress

### Automated Mode (CI/CD)
```bash
php artisan scan:fix --auto
```
- Skips confirmations
- Perfect for automated pipelines
- Still safe with conservative fixes

### Combined Flags
```bash
php artisan scan:fix --dry-run --backup --auto
```

---

## 📊 Report Generation

### Console Report (Default)
```bash
php artisan scan:report
```
- Colored output
- Type breakdown
- Severity indicators

### HTML Report
```bash
php artisan scan:report --format=html
```
- Professional HTML output
- Searchable and filterable
- Saved to `storage/scanner-reports/`

### JSON Export
```bash
php artisan scan:report --format=json
```
- Machine-readable format
- Perfect for CI/CD integration
- API consumption

### Markdown Report
```bash
php artisan scan:report --format=markdown
```
- Documentation-friendly
- GitHub/GitLab compatible
- Easy to share

---

## 🎯 Common Use Cases

### 1. Quick Security Check
```bash
php artisan scan --all
```

### 2. Before Committing Code
```bash
php artisan scan --all
php artisan scan:fix --dry-run
```

### 3. Safe Auto-Fix Workflow
```bash
# Step 1: Preview what will change
php artisan scan:fix --dry-run

# Step 2: Apply fixes with backup
php artisan scan:fix --backup

# Step 3: Verify changes
php artisan scan --all
```

### 4. Focus on Critical Issues
```bash
php artisan scan:security          # Check XSS, SQL, CSRF
```

### 5. Check Specific Scanner
```bash
php artisan scan                   # Interactive
# Select: 10 (for XSS scanner)
```

---

## 📈 Understanding Output

### Type Breakdown Example (XSS)
```
📊 Issue Types:
   • Inline Handler: 13
   • Unescaped Output Warning: 2
   • Url Injection: 1
```

### Severity Levels
- 🔴 **Critical** (0-29) - Immediate action required
- 🟠 **High** (389) - Should be fixed soon
- 🟡 **Medium** (53) - Plan to fix
- 🔵 **Low** (0) - Nice to fix
- 🟢 **Info** (0) - Informational

### Fix Preview Format
```
📁 File: resources\views\profile.blade.php
Type: XSS - Unescaped Output
Line: 42

- {!! $user->bio !!}
+ {{ $user->bio }}
```

---

## 🛡️ What Each Scanner Checks

### 1. Livewire Scanner
- Public property exposure
- Missing validation rules
- Authorization checks
- Mass assignment issues

### 2. Rate Limit Scanner
- Route protection
- Throttle middleware
- Login attempt limits
- API rate limiting

### 3. Function Security Scanner
- SQL injection risks
- Command injection
- Unsafe deserialization
- Eval usage
- Dangerous functions

### 4. Data Exposure Scanner
- Debug mode in production
- Sensitive data in logs
- API response leakage
- Hidden field exposure

### 5. Console Security Scanner
- Command input validation
- Argument injection
- Dangerous artisan commands

### 6. Authentication Scanner
- Password policies
- Session security
- CSRF protection
- Remember token security

### 7. Authorization Scanner
- Policy implementations
- Gate definitions
- Permission checks

### 8. Dependency Scanner
- Outdated packages
- Known vulnerabilities
- Security advisories

### 9. Configuration Scanner
- Hardcoded secrets
- CORS configuration
- Cookie security
- File permissions

### 10. XSS Scanner
- Unescaped Blade output
- Inline event handlers
- JavaScript injection
- URL injection

### 11. SQL Injection Scanner
- Raw queries
- Unbound parameters
- DB::raw() usage

### 12. File Security Scanner
- Upload validation
- MIME type verification
- Path traversal

### 13. CSRF Scanner
- Missing @csrf tokens
- Form protection

---

## 🔧 Auto-Fix Capabilities

### What Gets Fixed Automatically

#### ✅ XSS Issues
```blade
Before: {!! $variable !!}
After:  {{ $variable }}
```

#### ✅ CSRF Protection
```blade
Before: <form method="POST">
After:  <form method="POST">
            @csrf
```

#### ✅ Livewire Validation
```php
Before: public $email;
After:  public $email; // TODO: Add validation in rules() method
```

#### ✅ SQL Injection Warnings
```php
Before: $query->whereRaw("name = $input");
After:  $query->whereRaw("name = $input"); // WARNING: Potential SQL injection risk
```

---

## 📁 Output Locations

### Scan Results
- Console: Real-time display
- HTML: `storage/scanner-reports/scan-{timestamp}.html`
- JSON: `storage/scanner-reports/scan-{timestamp}.json`
- Markdown: `storage/scanner-reports/scan-{timestamp}.md`

### Backups
- Location: `storage/scanner-backups/{timestamp}/`
- Contains: Original files before fixes
- Retention: Manual cleanup required

---

## 💡 Pro Tips

1. **Run scans before deployment**
   ```bash
   php artisan scan --all > scan-results.txt
   ```

2. **Use dry-run first, always**
   ```bash
   php artisan scan:fix --dry-run
   ```

3. **Create backups for peace of mind**
   ```bash
   php artisan scan:fix --backup
   ```

4. **Focus on critical issues first**
   - Fix Critical and High severity first
   - Medium can be planned
   - Low are optional

5. **Regular scanning schedule**
   - Daily: Quick scan during development
   - Weekly: Full scan with reports
   - Before deployment: Always

6. **CI/CD Integration**
   ```yaml
   # .github/workflows/security-scan.yml
   - name: Security Scan
     run: |
       php artisan scan --all
       php artisan scan:fix --auto --dry-run
   ```

---

## ❓ Troubleshooting

### "Too many vulnerabilities found"
- This is good! Better to know about them
- Use `--dry-run` to preview fixes
- Fix in batches by scanner type

### "Command not found"
- Ensure package is installed: `composer require artflow-studio/scanner`
- Clear config cache: `php artisan config:clear`

### "No fixable issues found"
- Not all issues can be auto-fixed
- Manual review still needed
- Check individual scanner outputs

---

## 📞 Support

- Documentation: `PROCESS.md`
- Enhancement Details: `ENHANCEMENT_SUMMARY.md`
- Test Results: `COMPLETE_TEST_REPORT.md`
- Fixes Applied: `FIXES_APPLIED.md`

---

**Last Updated:** January 2024
**Version:** 1.0.0
**Status:** Production Ready ✅
