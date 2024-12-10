import logging
import re
from pathlib import Path

import jsonschema


class SecurityError(Exception):
    """Raised for security-related errors"""

    pass


def validate_safe_path(filepath: str, base_dir: str) -> Path:
    """Validate that a file path is safe (within base directory)"""
    abs_path = Path(filepath).resolve()
    base_path = Path(base_dir).resolve()

    if not str(abs_path).startswith(str(base_path)):
        raise SecurityError(f"Path {filepath} is outside of {base_dir}")

    return abs_path


def validate_package_name(package_name: str) -> bool:
    """Validate package name against PyPI naming rules"""
    if not isinstance(package_name, str):
        raise SecurityError("Package name must be a string")
    if not package_name:
        raise SecurityError("Package name cannot be empty")
    if not re.match(r"^[a-zA-Z0-9-_.]+$", package_name):
        raise SecurityError("Invalid package name format")
    return True


def read_file_chunked(filepath: str, chunk_size: int = 8192) -> str:
    """Safely read a file in chunks to prevent memory exhaustion"""
    if not isinstance(chunk_size, int) or chunk_size <= 0:
        raise SecurityError("Invalid chunk size")

    content = []
    total_size = 0
    max_size = 50 * 1024 * 1024  # 50MB limit

    with open(filepath, "r", encoding="utf-8") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > max_size:
                raise SecurityError("File too large to process")
            content.append(chunk)

    return "".join(content)


# JSON Schema definitions
PYPI_SCHEMA = {
    "type": "object",
    "required": ["info"],
    "properties": {
        "info": {
            "type": "object",
            "required": ["name", "version"],  # Remove home_page from required
            "properties": {
                "name": {"type": "string"},
                "version": {"type": "string"},
                "license": {"type": ["string", "null"]},
                "project_urls": {"type": ["object", "null"]},
                "home_page": {"type": ["string", "null"]},  # Allow null
                "description": {"type": ["string", "null"]},
            },
        }
    },
}
OSV_SCHEMA = {
    "type": "object",
    "properties": {
        "vulns": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}, "summary": {"type": "string"}},
            },
        }
    },
}

NVD_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerabilities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "cve": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "descriptions": {"type": "array"},
                            "references": {"type": "array"},
                        },
                    }
                },
            },
        }
    },
}


def validate_json_response(data: dict, schema: dict, source: str) -> None:
    """Validate JSON response against schema"""
    try:
        jsonschema.validate(instance=data, schema=schema)
    except jsonschema.exceptions.ValidationError as e:
        raise SecurityError(f"Invalid {source} response format: {str(e)}")


class LogSanitizer:
    """Sanitize sensitive data from log messages"""

    PATTERNS = [
        (r'token[=:]\s*["\']?\w+["\']?', "token=REDACTED"),
        (r'password[=:]\s*["\']?\w+["\']?', "password=REDACTED"),
        (r'api[-_]?key[=:]\s*["\']?\w+["\']?', "api_key=REDACTED"),
        (r'auth[=:]\s*["\']?bearer\s+\w+["\']?', "auth=REDACTED"),
        (r'secret[=:]\s*["\']?\w+["\']?', "secret=REDACTED"),
    ]

    @classmethod
    def sanitize(cls, message: str) -> str:
        """Remove sensitive data from log message"""
        import re

        result = str(message)
        for pattern, replacement in cls.PATTERNS:
            result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
        return result


class SanitizedFormatter(logging.Formatter):
    """Log formatter that sanitizes messages"""

    def format(self, record):
        record.msg = LogSanitizer.sanitize(record.msg)
        if isinstance(record.args, dict):
            record.args = {
                k: LogSanitizer.sanitize(str(v)) for k, v in record.args.items()
            }
        elif isinstance(record.args, (list, tuple)):
            record.args = tuple(LogSanitizer.sanitize(str(arg)) for arg in record.args)
        return super().format(record)
