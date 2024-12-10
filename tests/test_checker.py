import pytest
import aiohttp
from unittest.mock import Mock, patch, MagicMock
from bettercheck.checker import PackageChecker
from bettercheck.security import SecurityError


@pytest.fixture
async def mock_session():
    async with aiohttp.ClientSession() as session:
        yield session


@pytest.fixture
def checker(test_package_name):
    checker = PackageChecker(test_package_name)
    return checker


def test_init_valid(test_package_name):
    checker = PackageChecker(test_package_name)
    assert checker.package_name == test_package_name


def test_init_invalid():
    with pytest.raises(SecurityError):
        PackageChecker("invalid/package")


@pytest.mark.asyncio(scope="function")
async def test_check_pypi_info_valid(checker, sample_pypi_data, async_session):
    checker.session = async_session
    with patch("requests.get") as mock_get:
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = sample_pypi_data

        result = checker.check_pypi_info()
        assert result is not None
        assert result["name"] == sample_pypi_data["info"]["name"]
        assert result["version"] == sample_pypi_data["info"]["version"]


@pytest.mark.asyncio(scope="function")
async def test_check_security_valid(checker, async_session):
    checker.session = async_session
    mock_response = MagicMock()
    mock_response.status = 200
    mock_response.json.return_value = {"vulns": []}

    with patch.object(async_session, "post") as mock_post, patch.object(
        async_session, "get"
    ) as mock_get:
        mock_post.return_value.__aenter__.return_value = mock_response
        mock_get.return_value.__aenter__.return_value = mock_response

        result = await checker.check_security()
        assert isinstance(result, list)


def test_check_github_metrics_valid(checker, mock_github_data):
    with patch("github.Github.get_repo") as mock_get_repo:
        mock_repo = Mock()
        for key, value in mock_github_data.items():
            setattr(mock_repo, key, value)
        mock_get_repo.return_value = mock_repo

        result = checker.check_github_metrics("https://github.com/test/test-package")
        assert result is not None
        assert result["stars"] == mock_github_data["stargazers_count"]
        assert result["forks"] == mock_github_data["forks_count"]


def test_extract_github_url(checker):
    test_cases = [
        {
            "input": {
                "project_urls": {"Source": "https://github.com/test/package"},
                "home_page": "https://example.com",
            },
            "expected": "https://github.com/test/package",
        },
        {
            "input": {
                "project_urls": {},
                "home_page": "https://github.com/test/package",
            },
            "expected": "https://github.com/test/package",
        },
        {
            "input": {
                "project_urls": {},
                "home_page": "https://example.com",
                "description": "Find us at https://github.com/test/package",
            },
            "expected": "https://github.com/test/package",
        },
    ]

    for case in test_cases:
        result = checker._extract_github_url(case["input"])
        assert result == case["expected"]
