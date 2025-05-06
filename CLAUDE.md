# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview
Cisco UC Certificate Management tool that automates SSL certificate generation, validation, and installation for Cisco Unified Communications servers using various DNS and SSL providers.

## Environment Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run Commands
```bash
python3 get-cert.py --host <hostname> --domain <domain> [options]
```

## Code Style Guidelines
- Imports: Standard library first, then third-party libraries
- Type Annotations: Use type hints for all functions with the `typing` module
- Error Handling: Try/except blocks with appropriate error codes
- Logging: Use the custom Logger class with appropriate log levels
- Classes: Follow provider pattern with abstract base classes
- API Interactions: Use the requests library with proper error handling
- Security: Store credentials in environment variables only
- Documentation: Clear docstrings and comments for complex operations
- Naming: Use snake_case for functions and variables, CamelCase for classes
- Function length: Keep functions focused and concise (under 50 lines)