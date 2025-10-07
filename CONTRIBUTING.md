# Contributing to Artflow Vulnerability Scanner

Thank you for considering contributing to the Artflow Vulnerability Scanner! We welcome contributions from the community.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue on GitHub with:
- A clear title and description
- Steps to reproduce the issue
- Expected behavior
- Actual behavior
- Laravel and PHP versions
- Any relevant code snippets or error messages

### Suggesting Features

We're always looking for ways to improve! To suggest a new feature:
1. Check if the feature has already been suggested
2. Create a detailed issue explaining:
   - The problem it solves
   - How it should work
   - Example use cases

### Adding New Scanners

Want to add a new security scanner? Great! Here's how:

1. **Create the Scanner Class**
   ```php
   namespace ArtflowStudio\Scanner\Scanners;
   
   class YourScanner extends AbstractScanner
   {
       public function getName(): string
       {
           return 'Your Scanner Name';
       }
       
       public function getDescription(): string
       {
           return 'What your scanner checks for';
       }
       
       protected function execute(): void
       {
           // Your scanning logic
       }
   }
   ```

2. **Register the Scanner**
   Add it to `ScannerService::registerScanners()`

3. **Add Configuration**
   Update `config/scanner.php` with scanner-specific options

4. **Create Tests**
   Add comprehensive tests for your scanner

5. **Update Documentation**
   Document what the scanner checks for in README.md

### Pull Request Process

1. **Fork the Repository**
   ```bash
   git clone https://github.com/artflow-studio/scanner.git
   cd scanner
   ```

2. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow PSR-12 coding standards
   - Write clear, descriptive commit messages
   - Add tests for new features
   - Update documentation

4. **Run Tests**
   ```bash
   composer test
   composer format
   composer analyse
   ```

5. **Submit Pull Request**
   - Provide a clear description of changes
   - Reference any related issues
   - Ensure all tests pass

## Development Setup

```bash
# Clone the repository
git clone https://github.com/artflow-studio/scanner.git
cd scanner

# Install dependencies
composer install

# Run tests
composer test

# Format code
composer format

# Run static analysis
composer analyse
```

## Code Style

We follow PSR-12 coding standards. Use Laravel Pint to format your code:

```bash
composer format
```

## Testing

All new features should include tests. Run the test suite:

```bash
composer test
```

## Documentation

Please update the README.md and other documentation when:
- Adding new features
- Changing existing functionality
- Adding new configuration options
- Creating new scanners

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of:
- Age
- Body size
- Disability
- Ethnicity
- Gender identity
- Experience level
- Nationality
- Personal appearance
- Race
- Religion
- Sexual identity and orientation

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Accepting constructive criticism
- Focusing on what's best for the community
- Showing empathy towards others

**Unacceptable behavior includes:**
- Harassment, trolling, or derogatory comments
- Publishing others' private information
- Other conduct inappropriate in a professional setting

## Questions?

Feel free to:
- Open a GitHub issue
- Email us at support@artflow-studio.com
- Join discussions in issues and pull requests

## Recognition

Contributors will be recognized in:
- The README.md credits section
- Release notes
- Project documentation

Thank you for helping make Laravel applications more secure! 🔒
