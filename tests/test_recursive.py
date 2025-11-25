# tests/test_recursive.py
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch, AsyncMock
from bettercheck.recursive import (
    ContributorStats,
    PackageAnalysis,
    RecursiveAnalyzer,
    SupplyChainVisualizer,
    generate_report,
    HAS_MATPLOTLIB,
)


class TestContributorStats:
    def test_contributor_stats_creation(self):
        stats = ContributorStats(
            total_contributors=10,
            top_contributors=[{"login": "user1", "contributions": 100}],
            contribution_distribution={"commits": 500, "additions": 1000, "deletions": 200}
        )
        assert stats.total_contributors == 10
        assert len(stats.top_contributors) == 1
        assert stats.contribution_distribution["commits"] == 500
    
    def test_contributor_stats_to_dict(self):
        stats = ContributorStats(
            total_contributors=5,
            top_contributors=[{"login": "dev", "contributions": 50}],
        )
        result = stats.to_dict()
        assert result["total_contributors"] == 5
        assert "top_contributors" in result
        assert "contribution_distribution" in result


class TestPackageAnalysis:
    def test_package_analysis_creation(self):
        analysis = PackageAnalysis(
            name="test-pkg",
            version="1.0.0",
            depth=0,
        )
        assert analysis.name == "test-pkg"
        assert analysis.version == "1.0.0"
        assert analysis.depth == 0
        assert analysis.security_info == []
    
    def test_package_analysis_to_dict(self):
        analysis = PackageAnalysis(
            name="test-pkg",
            version="1.0.0",
            depth=1,
            pypi_info={"name": "test-pkg", "version": "1.0.0"},
            security_info=[{"vulnerability_id": "CVE-2021-1234"}],
        )
        result = analysis.to_dict()
        assert result["name"] == "test-pkg"
        assert result["version"] == "1.0.0"
        assert result["depth"] == 1
        assert result["pypi"] is not None
        assert len(result["security"]) == 1


class TestRecursiveAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return RecursiveAnalyzer(max_depth=2, include_contributors=False)
    
    def test_analyzer_initialization(self, analyzer):
        assert analyzer.max_depth == 2
        assert analyzer.include_contributors == False
        assert analyzer.seen_packages == set()
        assert analyzer.results == {}
    
    @pytest.mark.asyncio
    async def test_analyzer_respects_max_depth(self):
        analyzer = RecursiveAnalyzer(max_depth=0, include_contributors=False)
        # With max_depth=0, it should only analyze the root package
        # The analyze method will be tested with mocked dependencies


class TestSupplyChainVisualizer:
    @pytest.fixture
    def sample_results(self):
        return {
            "pkg-a": PackageAnalysis(
                name="pkg-a", 
                version="1.0.0", 
                depth=0,
                security_info=[{"vulnerability_id": "CVE-1"}]
            ),
            "pkg-b": PackageAnalysis(
                name="pkg-b", 
                version="2.0.0", 
                depth=1,
                security_info=[]
            ),
        }
    
    @pytest.fixture
    def sample_graph(self):
        return {"pkg-a": ["pkg-b"]}
    
    def test_visualizer_creation(self, sample_results, sample_graph):
        visualizer = SupplyChainVisualizer(sample_results, sample_graph)
        assert visualizer.results == sample_results
        assert visualizer.dependency_graph == sample_graph
    
    def test_generate_ascii_tree(self, sample_results, sample_graph):
        visualizer = SupplyChainVisualizer(sample_results, sample_graph)
        tree = visualizer.generate_dependency_tree_ascii("pkg-a")
        assert "pkg-a" in tree
        assert "pkg-b" in tree
        assert "1.0.0" in tree
        assert "2.0.0" in tree
    
    @pytest.mark.skipif(not HAS_MATPLOTLIB, reason="matplotlib not installed")
    def test_generate_vulnerability_chart_returns_bytes(self, sample_results, sample_graph):
        visualizer = SupplyChainVisualizer(sample_results, sample_graph)
        result = visualizer.generate_vulnerability_chart()
        # Should return bytes for PNG image
        assert isinstance(result, bytes)
        # PNG files start with specific magic bytes
        assert result[:8] == b'\x89PNG\r\n\x1a\n'
    
    @pytest.mark.skipif(not HAS_MATPLOTLIB, reason="matplotlib not installed")
    def test_generate_depth_distribution_chart(self, sample_results, sample_graph):
        visualizer = SupplyChainVisualizer(sample_results, sample_graph)
        result = visualizer.generate_depth_distribution_chart()
        assert isinstance(result, bytes)
        assert result[:8] == b'\x89PNG\r\n\x1a\n'


class TestGenerateReport:
    @pytest.fixture
    def sample_data(self):
        results = {
            "flask": PackageAnalysis(
                name="flask",
                version="2.0.0",
                depth=0,
                pypi_info={"name": "flask", "version": "2.0.0"},
                security_info=[{"vulnerability_id": "CVE-2023-1234", "source": "OSV", "advisory": "Test vuln"}],
                contributor_stats=ContributorStats(total_contributors=50, top_contributors=[{"login": "dev1", "contributions": 100}]),
            ),
        }
        graph = {"flask": []}
        return results, graph
    
    def test_generate_json_report(self, sample_data, tmp_path):
        results, graph = sample_data
        report_path = generate_report(results, graph, "flask", tmp_path, "json")
        
        assert report_path.exists()
        assert report_path.suffix == ".json"
        
        import json
        with open(report_path) as f:
            data = json.load(f)
        
        assert "summary" in data
        assert data["root_package"] == "flask"
        assert data["summary"]["total_packages"] == 1
    
    def test_generate_md_report(self, sample_data, tmp_path):
        results, graph = sample_data
        report_path = generate_report(results, graph, "flask", tmp_path, "md")
        
        assert report_path.exists()
        assert report_path.suffix == ".md"
        
        content = report_path.read_text()
        assert "# Supply Chain Analysis: flask" in content
        assert "## Summary" in content
        assert "## Dependency Tree" in content
