import pytest
from pathlib import Path
import json
import requests
import aiohttp


@pytest.fixture
def sample_pypi_data():
    return {
        "info": {
            "name": "test-package",
            "version": "1.0.0",
            "license": "MIT",
            "home_page": "https://github.com/test/test-package",
            "project_urls": {"Source": "https://github.com/test/test-package"},
            "description": "A test package",
            "downloads": {"last_month": 1000, "last_week": 100},
        }
    }


@pytest.fixture
def sample_security_data():
    return {
        "source": "test",
        "vulnerability_id": "TEST-2023-001",
        "advisory": "Test vulnerability",
    }


@pytest.fixture
def test_package_name():
    return "test-package"


@pytest.fixture
def project_root():
    return Path(__file__).parent.parent


@pytest.fixture
def mock_github_data():
    return {
        "stargazers_count": 100,
        "forks_count": 50,
        "open_issues_count": 10,
        "pushed_at": "2023-01-01T00:00:00Z",
        "created_at": "2022-01-01T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z",
        "subscribers_count": 20,
        "network_count": 30,
        "default_branch": "main",
    }


@pytest.fixture
def test_file_content():
    return "test content\n" * 1000


@pytest.fixture
def mock_response():
    class MockResponse:
        def __init__(self, status_code=200, json_data=None):
            self.status_code = status_code
            self._json_data = json_data or {}

        def json(self):
            return self._json_data

        def raise_for_status(self):
            if self.status_code >= 400:
                raise requests.exceptions.HTTPError()

    return MockResponse


@pytest.fixture
async def async_session():
    async with aiohttp.ClientSession() as session:
        yield session
    await session.close()


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for each test case."""
    import asyncio

    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()
