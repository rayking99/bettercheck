import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
import aiohttp
from bettercheck.dep_tree import DependencyAnalyzer, DependencyNode, analyze_deps


@pytest.fixture
def analyzer():
    return DependencyAnalyzer()


@pytest.fixture
def sample_dep_data():
    return {
        "name": "test-package",
        "version": "1.0.0",
        "requires_dist": [
            "requests>=2.25.0",
            "click>=7.0",
        ],
    }


@pytest.fixture
def async_session():
    return AsyncMock()


@pytest.mark.asyncio
async def test_get_package_deps(analyzer, async_session, sample_dep_data):
    analyzer.session = async_session
    await analyzer.init_session()
    try:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"info": sample_dep_data})
        async_session.get = AsyncMock(return_value=mock_response)

        result = await analyzer.get_package_deps("test-package")
        assert result == {
            "name": sample_dep_data["name"],
            "version": sample_dep_data["version"],
            "requires_dist": sample_dep_data["requires_dist"],
        }

        async_session.get.assert_called_once_with(
            "https://pypi.org/pypi/test-package/json"
        )
    finally:
        await analyzer.close_session()


@pytest.mark.asyncio
async def test_build_tree(analyzer, async_session, sample_dep_data):
    analyzer.session = async_session
    await analyzer.init_session()
    try:
        mock_response = AsyncMock()
        mock_response.status = 200
        mock_response.json = AsyncMock(return_value={"info": sample_dep_data})
        async_session.get = AsyncMock(return_value=mock_response)

        tree = await analyzer.build_tree("test-package", max_depth=2)
        assert isinstance(tree, DependencyNode)
        assert tree.name == sample_dep_data["name"]
        assert tree.version == sample_dep_data["version"]

        async_session.get.assert_called_with("https://pypi.org/pypi/test-package/json")
    finally:
        await analyzer.close_session()


@pytest.mark.asyncio
async def test_analyze_deps_main():
    mock_analyzer = AsyncMock()
    mock_analyzer.build_tree.return_value = DependencyNode(
        name="test-package", version="1.0.0", requires=[], depth=0
    )

    with patch("bettercheck.dep_tree.DependencyAnalyzer", return_value=mock_analyzer):
        result = await analyze_deps("test-package", max_depth=2)
        assert isinstance(result, dict)
        assert result["name"] == "test-package"
