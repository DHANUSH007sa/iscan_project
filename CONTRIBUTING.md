# Contributing to iScan

Thank you for your interest in contributing to iScan! This document provides guidelines for participating in the project.

## Code of Conduct

Be respectful, inclusive, and professional. We value all contributors regardless of experience level.

## How to Contribute

### Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/yourusername/iscan/issues) with:

1. **Clear title** - Brief description of the issue
2. **Description** - What happened, what you expected
3. **Steps to reproduce** - How to trigger the issue (for bugs)
4. **Environment** - OS, Python version, Node version
5. **Logs** - Error messages or terminal output (if relevant)

### Security Vulnerabilities

**DO NOT** open a public issue for security vulnerabilities.

Instead, email your findings to: `security@yourdomain.com` with:
- Vulnerability description
- Affected component(s)
- Steps to reproduce (if safe)
- Potential impact
- Suggested fix (if you have one)

We take security seriously and will respond within 48 hours.

### Submitting Changes

1. **Fork the Repository**
   ```bash
   git clone https://github.com/yourusername/iscan.git
   cd iscan
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   # or
   git checkout -b fix/bug-fix-name
   ```

3. **Make Your Changes**
   - Keep commits small and focused
   - Write clear commit messages
   - Test your changes thoroughly

4. **Commit and Push**
   ```bash
   git add .
   git commit -m "Add amazing feature

   - Describe what the change does
   - Explain why it's needed
   - Reference related issues if any (#123)"
   
   git push origin feature/amazing-feature
   ```

5. **Open a Pull Request**
   - Provide a clear description
   - Link related issues
   - Explain the approach taken
   - Request review from maintainers

## Development Setup

### Frontend Development
```bash
npm install
npm run dev
```
Runs on http://localhost:8080 with hot module reloading.

### Backend Development
```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux/Mac
# or
venv\Scripts\activate           # Windows

# Install dependencies
pip install -r requirements.txt

# Run with debug mode
FLASK_ENV=development FLASK_DEBUG=1 PISHIELD_SIMULATE_SCANS=1 python3 app.py
```
Runs on http://localhost:5001

### Testing Before Submission

```bash
# Frontend linting
npm run lint

# Backend format check (if using black)
# pip install black
# black backend/

# Test demo mode
PISHIELD_SIMULATE_SCANS=1 python3 app.py
```

## Code Style

### Python (Backend)
- Follow PEP 8 style guide
- Use type hints where possible
- Write docstrings for functions
- Keep functions focused and modular

### JavaScript/TypeScript (Frontend)
- Use ESLint configuration (`npm run lint`)
- Follow React hooks patterns
- Use TypeScript for type safety
- Keep components small and reusable

Example function:
```python
def scan_target(target_ip: str, profile: str) -> Dict[str, Any]:
    """
    Scan a target IP address with specified profile.
    
    Args:
        target_ip: Target IP address (e.g. "192.168.1.100")
        profile: Scan profile - "small", "medium", or "deep"
    
    Returns:
        Dictionary with scan results and metadata
    """
    # Implementation
```

## Commit Message Format

```
Brief description (under 50 chars)

Longer explanation of the change:
- What was changed
- Why it was changed  
- How it works

Fixes #123
Closes #456
```

## Pull Request Template

```markdown
## Description
Brief description of changes

## Related Issues
Fixes #123

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Other

## Testing
- [ ] Added/updated tests
- [ ] Tested locally
- [ ] Verified demo mode works

## Checklist
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No hardcoded secrets/paths
- [ ] Uses .env variables for config
```

## Project Structure

```
iscan/
├── frontend/
│   ├── src/
│   │   ├── components/      # React components
│   │   ├── pages/           # Page components
│   │   ├── contexts/        # React context providers
│   │   ├── lib/             # Utilities and helpers
│   │   └── main.tsx         # Entry point
│   └── package.json
│
├── backend/
│   ├── app.py              # Main Flask application
│   ├── requirements.txt     # Python dependencies
│   └── [other files]
│
├── README.md               # User documentation
├── CONTRIBUTING.md         # This file
├── .env.example           # Configuration template
└── .gitignore             # Git ignore rules
```

## Key Areas for Contribution

### High Priority
- [ ] Additional scanner integrations (Nessus, GVM, etc.)
- [ ] Improved reporting and export formats
- [ ] Performance optimizations
- [ ] Security hardening

### Medium Priority
- [ ] User interface improvements
- [ ] Documentation enhancements
- [ ] Additional scan profiles
- [ ] API endpoints

### Welcome Anytime
- [ ] Bug fixes
- [ ] Documentation improvements
- [ ] Code cleanup
- [ ] Typo corrections

## Review Process

1. **Automated Checks** - GitHub Actions runs linters/tests
2. **Code Review** - Maintainers review for quality and security
3. **Discussion** - Questions or changes may be requested
4. **Approval** - Once approved, changes will be merged
5. **Release** - Your contribution will be included in next release

## Questions?

- Check existing documentation
- Open a discussion issue
- Email maintainers
- Join our community chat (if available)

## Recognition

Contributors will be recognized in:
- Release notes
- README.md contributors section
- Our community

Thank you for making iScan better! 🎉

---

**Last Updated**: 2026-03-03
