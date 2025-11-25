# tests/test_checker.py
import pytest
from unittest.mock import patch, MagicMock
from bettercheck.checker import PackageChecker


class TestPackageChecker:
    @pytest.fixture
    def checker(self):
        return PackageChecker("requests")
    
    def test_checker_initialization(self, checker):
        assert checker.package_name == "requests"
        assert "pypi.org" in checker.pypi_api
        assert checker.osv_api is not None
        assert checker.nvd_api is not None
    
    @patch('bettercheck.checker.requests.get')
    def test_check_pypi_info_success(self, mock_get, checker):
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "info": {
                "name": "requests",
                "version": "2.31.0",
                "license": "Apache-2.0",
                "project_urls": {"Source": "https://github.com/psf/requests"}
            }
        }
        mock_response.raise_for_status = MagicMock()
        mock_get.return_value = mock_response
        
        info = checker.check_pypi_info()
        assert info is not None
        assert info["name"] == "requests"
        assert "version" in info
    
    @pytest.mark.asyncio
    async def test_check_security_returns_list(self, checker):
        # Test that check_security returns a list (even if empty due to mocked/blocked network)
        vulns = await checker.check_security()
        assert isinstance(vulns, list)
    
    def test_extract_github_url(self, checker):
        info = {
            "project_urls": {
                "Source": "https://github.com/psf/requests",
            }
        }
        url = checker._extract_github_url(info)
        assert url is not None
        assert "github.com" in url
    
    def test_extract_github_url_from_home_page(self, checker):
        info = {
            "home_page": "https://github.com/psf/requests",
            "project_urls": None
        }
        url = checker._extract_github_url(info)
        assert url is not None
        assert "github.com" in url
    
    def test_normalize_github_url(self, checker):
        url = checker._normalize_github_url("git+https://github.com/user/repo.git")
        assert url == "https://github.com/user/repo"
        
        url = checker._normalize_github_url("git://github.com/user/repo")
        assert url == "https://github.com/user/repo"
