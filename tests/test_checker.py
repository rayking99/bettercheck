# tests/test_checker.py
import pytest
from unittest.mock import patch, MagicMock
from bettercheck.checker import PackageChecker


class TestPackageChecker:
    @pytest.fixture
    def checker(self):
        return PackageChecker("requests")

    @pytest.mark.vcr
    def test_check_pypi_info(self, checker):
        info = checker.check_pypi_info()
        assert info is not None
        assert "name" in info
        assert "version" in info

    @pytest.mark.asyncio
    @pytest.mark.vcr
    async def test_check_security(self, checker):
        vulns = await checker.check_security()
        assert isinstance(vulns, list)
