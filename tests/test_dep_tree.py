# tests/test_dep_tree.py
import pytest
from bettercheck.dep_tree import DependencyNode, DependencyAnalyzer


class TestDependencyTree:
    @pytest.mark.asyncio
    async def test_dependency_node_creation(self):
        node = DependencyNode("requests", "2.31.0", [], 0)
        assert node.name == "requests"
        assert node.version == "2.31.0"

    @pytest.mark.asyncio
    async def test_analyzer_init(self):
        analyzer = DependencyAnalyzer()
        assert analyzer.seen_packages == set()

    @pytest.mark.vcr  # Use VCR.py to record/replay HTTP requests
    @pytest.mark.asyncio
    async def test_get_package_deps(self):
        analyzer = DependencyAnalyzer()
        await analyzer.init_session()
        deps = await analyzer.get_package_deps("requests")
        await analyzer.close_session()
        assert deps is not None
        assert "name" in deps
