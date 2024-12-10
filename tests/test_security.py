# tests/test_security.py
import pytest
from pathlib import Path
from bettercheck.security import (
    validate_safe_path,
    validate_package_name,
    read_file_chunked,
    SecurityError,
    LogSanitizer,
)


class TestSecurityValidations:
    def test_validate_safe_path_valid(self):
        base_dir = "/tmp/test"
        filepath = "/tmp/test/file.txt"
        result = validate_safe_path(filepath, base_dir)
        assert isinstance(result, Path)

    def test_validate_safe_path_invalid(self):
        with pytest.raises(SecurityError):
            validate_safe_path("/etc/passwd", "/tmp/test")

    def test_validate_package_name_valid(self):
        assert validate_package_name("requests") == True
        assert validate_package_name("python-package") == True

    def test_validate_package_name_invalid(self):
        with pytest.raises(SecurityError):
            validate_package_name("")
        with pytest.raises(SecurityError):
            validate_package_name("invalid/name")

    def test_log_sanitizer(self):
        sensitive = "password=secret123 token=abc123"
        sanitized = LogSanitizer.sanitize(sensitive)
        assert "secret123" not in sanitized
        assert "abc123" not in sanitized
