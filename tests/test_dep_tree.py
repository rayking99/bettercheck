# tests/test_dep_tree.py
import pytest
from bettercheck.dep_tree import DependencyNode, DependencyAnalyzer


class TestDependencyTree:
    def test_dependency_node_creation(self):
        node = DependencyNode("requests", "2.31.0", [], 0)
        assert node.name == "requests"
        assert node.version == "2.31.0"
        assert node.depth == 0
        assert node.requires == []
    
    def test_dependency_node_with_children(self):
        child = DependencyNode("urllib3", "2.0.0", [], 1)
        parent = DependencyNode("requests", "2.31.0", [child], 0)
        
        assert len(parent.requires) == 1
        assert parent.requires[0].name == "urllib3"
    
    def test_dependency_node_to_dict(self):
        node = DependencyNode("requests", "2.31.0", [], 0, parent="flask")
        result = node.to_dict()
        
        assert result["name"] == "requests"
        assert result["version"] == "2.31.0"
        assert result["depth"] == 0
        assert result["parent"] == "flask"
        assert result["requires"] == []
    
    def test_analyzer_initialization(self):
        analyzer = DependencyAnalyzer()
        assert analyzer.seen_packages == set()
        assert analyzer.session is None
    
    @pytest.mark.asyncio
    async def test_analyzer_session_lifecycle(self):
        analyzer = DependencyAnalyzer()
        await analyzer.init_session()
        assert analyzer.session is not None
        
        await analyzer.close_session()
        assert analyzer.session is None
    
    def test_analyzer_cache_path(self):
        analyzer = DependencyAnalyzer()
        cache_path = analyzer._get_cache_path("requests")
        
        assert cache_path.name == "requests.json"
        assert ".bettercheck" in str(cache_path)
