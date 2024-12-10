import pytest
import os
from pathlib import Path
import logging
from bettercheck.security import (
    validate_safe_path,
    validate_package_name,
    read_file_chunked,
    validate_json_response,
    SecurityError,
    LogSanitizer,
    SanitizedFormatter,
    PYPI_SCHEMA,
)


# Test fixtures
@pytest.fixture
def temp_test_file(tmp_path):
    test_file = tmp_path / "test.txt"
    content = "test content\n" * 1000  # Create some meaningful content
    test_file.write_text(content)
    return test_file


@pytest.fixture
def base_dir(tmp_path):
    return str(tmp_path)


# Test validate_safe_path
def test_validate_safe_path_valid(temp_test_file, base_dir):
    result = validate_safe_path(str(temp_test_file), base_dir)
    assert isinstance(result, Path)
    assert str(result).startswith(base_dir)


def test_validate_safe_path_outside_base():
    with pytest.raises(SecurityError):
        validate_safe_path("/etc/passwd", "/tmp")


# Test validate_package_name
def test_validate_package_name_valid():
    assert validate_package_name("requests") is True
    assert validate_package_name("python-package") is True
    assert validate_package_name("package_name") is True
    assert validate_package_name("package.name") is True


def test_validate_package_name_invalid():
    invalid_names = [
        "",  # empty
        "package!name",  # invalid character
        "package/name",  # invalid character
        123,  # wrong type
        None,  # wrong type
        "package name",  # space not allowed
    ]
    for name in invalid_names:
        with pytest.raises(SecurityError):
            validate_package_name(name)


# Test read_file_chunked
def test_read_file_chunked_valid(temp_test_file):
    content = read_file_chunked(str(temp_test_file), chunk_size=100)
    assert isinstance(content, str)
    assert len(content) > 0


def test_read_file_chunked_invalid_chunk_size(temp_test_file):
    invalid_sizes = [0, -1, "100", None]
    for size in invalid_sizes:
        with pytest.raises(SecurityError):
            read_file_chunked(str(temp_test_file), chunk_size=size)


# Test JSON validation
def test_validate_json_response_valid():
    valid_pypi_data = {
        "info": {
            "name": "test-package",
            "version": "1.0.0",
            "license": "MIT",
            "home_page": "https://example.com",
        }
    }
    # Should not raise any exception
    validate_json_response(valid_pypi_data, PYPI_SCHEMA, "PyPI")


def test_validate_json_response_invalid():
    invalid_pypi_data = {
        "info": {
            "name": 123,  # Should be string
            "version": "1.0.0",
        }
    }
    with pytest.raises(SecurityError):
        validate_json_response(invalid_pypi_data, PYPI_SCHEMA, "PyPI")


# Test LogSanitizer
def test_log_sanitizer():
    sensitive_messages = [
        "token=abc123",
        "password=secret",
        "api_key=xyz789",
        "auth=bearer 12345",
        "secret=mysecret",
    ]

    for message in sensitive_messages:
        sanitized = LogSanitizer.sanitize(message)
        assert "REDACTED" in sanitized
        assert message not in sanitized


# Test SanitizedFormatter
def test_sanitized_formatter():
    formatter = SanitizedFormatter("%(message)s")
    log_record = logging.LogRecord(
        "test_logger", logging.INFO, "", 0, "password=secret api_key=12345", None, None
    )

    formatted = formatter.format(log_record)
    assert "password=REDACTED" in formatted
    assert "api_key=REDACTED" in formatted
    assert "secret" not in formatted
    assert "12345" not in formatted


def test_sanitized_formatter_with_args():
    formatter = SanitizedFormatter("%(message)s")
    log_record = logging.LogRecord(
        "test_logger",
        logging.INFO,
        "",
        0,
        "Config: %s",
        args=("password=secret",),
        exc_info=None,
    )

    formatted = formatter.format(log_record)
    assert "password=REDACTED" in formatted
    assert "secret" not in formatted
