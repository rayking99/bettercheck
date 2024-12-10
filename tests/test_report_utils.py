# tests/test_report_utils.py
import pytest
from pathlib import Path
from bettercheck.report_utils import get_report_path, get_log_path


class TestReportUtils:
    def test_get_report_path_valid(self):
        path = get_report_path("requests", "20240101", "md")
        assert isinstance(path, Path)
        assert path.suffix == ".md"

    def test_get_log_path_valid(self):
        path = get_log_path("requests", "20240101")
        assert isinstance(path, Path)
        assert path.suffix == ".log"
