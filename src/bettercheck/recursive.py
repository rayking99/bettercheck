"""
Recursive supply-chain analysis with contributor statistics and visualizations.

This module provides functionality to recursively analyze the entire dependency
tree of a Python package, including:
- Security vulnerability scanning
- Contributor statistics from GitHub
- Dependency tree visualizations
"""

import asyncio
import json
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import click

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    plt = None

from github import Github

from bettercheck.checker import PackageChecker
from bettercheck.dep_tree import analyze_deps
from bettercheck.security import validate_package_name, SecurityError


@dataclass
class ContributorStats:
    """Statistics about repository contributors."""
    total_contributors: int = 0
    top_contributors: List[Dict[str, Any]] = field(default_factory=list)
    contribution_distribution: Dict[str, int] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_contributors": self.total_contributors,
            "top_contributors": self.top_contributors,
            "contribution_distribution": self.contribution_distribution,
        }


@dataclass
class PackageAnalysis:
    """Complete analysis results for a package."""
    name: str
    version: str
    depth: int
    pypi_info: Optional[Dict[str, Any]] = None
    security_info: List[Dict[str, Any]] = field(default_factory=list)
    github_metrics: Optional[Dict[str, Any]] = None
    contributor_stats: Optional[ContributorStats] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "depth": self.depth,
            "pypi": self.pypi_info,
            "security": self.security_info,
            "github": self.github_metrics,
            "contributors": self.contributor_stats.to_dict() if self.contributor_stats else None,
        }


class RecursiveAnalyzer:
    """Recursively analyze a package and its entire dependency tree."""
    
    def __init__(self, max_depth: int = 3, include_contributors: bool = True):
        self.max_depth = max_depth
        self.include_contributors = include_contributors
        self.seen_packages: Set[str] = set()
        self.results: Dict[str, PackageAnalysis] = {}
        self.dependency_graph: Dict[str, List[str]] = defaultdict(list)
    
    async def analyze(self, package_name: str) -> Dict[str, PackageAnalysis]:
        """
        Recursively analyze a package and all its dependencies.
        
        Args:
            package_name: The root package to analyze
            
        Returns:
            Dictionary mapping package names to their analysis results
        """
        validate_package_name(package_name)
        await self._analyze_package(package_name, depth=0)
        return self.results
    
    async def _analyze_package(self, package_name: str, depth: int, parent: Optional[str] = None):
        """Analyze a single package and recurse into its dependencies."""
        if depth > self.max_depth:
            return
        
        pkg_lower = package_name.lower()
        if pkg_lower in self.seen_packages:
            # Still record the dependency relationship
            if parent:
                self.dependency_graph[parent].append(package_name)
            return
        
        self.seen_packages.add(pkg_lower)
        
        if parent:
            self.dependency_graph[parent].append(package_name)
        
        click.echo(f"  Analyzing {package_name} (depth {depth})...")
        
        try:
            checker = PackageChecker(package_name)
            
            # Get PyPI info
            pypi_info = checker.check_pypi_info()
            version = pypi_info.get("version", "unknown") if pypi_info else "unknown"
            
            # Get security info
            security_info = await checker.check_security()
            
            # Get GitHub metrics and contributor stats
            github_metrics = None
            contributor_stats = None
            
            if pypi_info and pypi_info.get("github_url"):
                github_metrics = checker.check_github_metrics(pypi_info["github_url"])
                
                if self.include_contributors and github_metrics:
                    contributor_stats = await self._get_contributor_stats(
                        pypi_info["github_url"]
                    )
            
            # Store results
            self.results[package_name] = PackageAnalysis(
                name=package_name,
                version=version,
                depth=depth,
                pypi_info=pypi_info,
                security_info=security_info or [],
                github_metrics=github_metrics,
                contributor_stats=contributor_stats,
            )
            
            # Get dependencies and recurse
            deps_tree = await analyze_deps(package_name, max_depth=1)
            if deps_tree:
                for dep in deps_tree.get("requires", []):
                    await self._analyze_package(dep["name"], depth + 1, package_name)
                    
        except Exception as e:
            click.echo(f"    Warning: Error analyzing {package_name}: {e}")
    
    async def _get_contributor_stats(self, github_url: str) -> Optional[ContributorStats]:
        """
        Fetch contributor statistics from GitHub.
        
        Note: Without authentication, GitHub API has a rate limit of 60 requests/hour.
        Set GITHUB_TOKEN environment variable for higher limits (5000/hour).
        """
        try:
            import os
            
            # Extract repo path from URL
            repo_path = github_url.replace("https://github.com/", "").rstrip("/")
            if not repo_path or "/" not in repo_path:
                return None
            
            # Use token if available for higher rate limits
            github_token = os.environ.get("GITHUB_TOKEN")
            g = Github(github_token) if github_token else Github()
            repo = g.get_repo(repo_path)
            
            # Get contributors
            contributors = list(repo.get_contributors()[:50])  # Top 50 contributors
            
            top_contributors = []
            contribution_distribution = {"commits": 0, "additions": 0, "deletions": 0}
            
            for contrib in contributors[:10]:  # Top 10 for detailed stats
                top_contributors.append({
                    "login": contrib.login,
                    "contributions": contrib.contributions,
                    "avatar_url": contrib.avatar_url,
                })
            
            # Get commit stats for contribution distribution
            try:
                stats = repo.get_stats_contributors()
                if stats:
                    for stat in stats:
                        for week in stat.weeks:
                            contribution_distribution["commits"] += week.c
                            contribution_distribution["additions"] += week.a
                            contribution_distribution["deletions"] += week.d
            except Exception:
                pass  # Stats may not be available for all repos
            
            return ContributorStats(
                total_contributors=len(contributors),
                top_contributors=top_contributors,
                contribution_distribution=contribution_distribution,
            )
            
        except Exception as e:
            click.echo(f"    Warning: Could not fetch contributor stats: {e}")
            return None


class SupplyChainVisualizer:
    """Generate visualizations for supply chain analysis."""
    
    def __init__(self, results: Dict[str, PackageAnalysis], 
                 dependency_graph: Dict[str, List[str]]):
        self.results = results
        self.dependency_graph = dependency_graph
    
    def generate_dependency_tree_ascii(self, root_package: str) -> str:
        """Generate an ASCII representation of the dependency tree."""
        lines = []
        self._build_tree_ascii(root_package, "", True, lines, set())
        return "\n".join(lines)
    
    def _build_tree_ascii(self, package: str, prefix: str, is_last: bool, 
                          lines: List[str], visited: Set[str]):
        """Recursively build ASCII tree representation."""
        # Get package info
        pkg_info = self.results.get(package)
        vuln_count = len(pkg_info.security_info) if pkg_info else 0
        version = pkg_info.version if pkg_info else "?"
        
        # Build the line
        connector = "└── " if is_last else "├── "
        vuln_indicator = f" ⚠️ {vuln_count} vulns" if vuln_count > 0 else ""
        lines.append(f"{prefix}{connector}{package} ({version}){vuln_indicator}")
        
        # Mark as visited
        if package in visited:
            return
        visited.add(package)
        
        # Get children
        children = self.dependency_graph.get(package, [])
        
        # Recurse
        new_prefix = prefix + ("    " if is_last else "│   ")
        for i, child in enumerate(children):
            is_last_child = i == len(children) - 1
            self._build_tree_ascii(child, new_prefix, is_last_child, lines, visited)
    
    def generate_vulnerability_chart(self, output_path: Optional[Path] = None) -> Optional[bytes]:
        """Generate a bar chart showing vulnerabilities per package."""
        if not HAS_MATPLOTLIB:
            click.echo("Warning: matplotlib not installed. Install with: pip install matplotlib")
            return None
        
        # Filter packages with vulnerabilities
        vuln_packages = {
            name: len(pkg.security_info) 
            for name, pkg in self.results.items() 
            if pkg.security_info
        }
        
        if not vuln_packages:
            return None
        
        # Create figure
        fig, ax = plt.subplots(figsize=(12, max(6, len(vuln_packages) * 0.4)))
        
        packages = list(vuln_packages.keys())
        counts = list(vuln_packages.values())
        
        # Create horizontal bar chart
        colors = ['#ff6b6b' if c > 5 else '#ffa94d' if c > 2 else '#69db7c' for c in counts]
        bars = ax.barh(packages, counts, color=colors)
        
        ax.set_xlabel('Number of Vulnerabilities')
        ax.set_title('Vulnerabilities by Package')
        ax.set_xlim(0, max(counts) * 1.1)
        
        # Add value labels
        for bar, count in zip(bars, counts):
            ax.text(bar.get_width() + 0.1, bar.get_y() + bar.get_height()/2, 
                    str(count), va='center', fontsize=10)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            return None
        else:
            buf = BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf.read()
    
    def generate_contributor_chart(self, output_path: Optional[Path] = None) -> Optional[bytes]:
        """Generate a chart showing top contributors across the supply chain."""
        if not HAS_MATPLOTLIB:
            click.echo("Warning: matplotlib not installed. Install with: pip install matplotlib")
            return None
        
        # Aggregate contributors
        contributor_counts: Dict[str, int] = defaultdict(int)
        
        for pkg in self.results.values():
            if pkg.contributor_stats:
                for contrib in pkg.contributor_stats.top_contributors:
                    contributor_counts[contrib["login"]] += contrib["contributions"]
        
        if not contributor_counts:
            return None
        
        # Get top 15 contributors
        top_contributors = sorted(contributor_counts.items(), 
                                  key=lambda x: x[1], reverse=True)[:15]
        
        fig, ax = plt.subplots(figsize=(12, 8))
        
        names = [c[0] for c in top_contributors]
        contributions = [c[1] for c in top_contributors]
        
        bars = ax.barh(names, contributions, color='#4c6ef5')
        
        ax.set_xlabel('Total Contributions')
        ax.set_title('Top Contributors Across Supply Chain')
        
        # Add value labels
        for bar, count in zip(bars, contributions):
            ax.text(bar.get_width() + max(contributions) * 0.01, 
                    bar.get_y() + bar.get_height()/2, 
                    str(count), va='center', fontsize=9)
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            return None
        else:
            buf = BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf.read()
    
    def generate_depth_distribution_chart(self, output_path: Optional[Path] = None) -> Optional[bytes]:
        """Generate a pie chart showing distribution of dependencies by depth."""
        if not HAS_MATPLOTLIB:
            click.echo("Warning: matplotlib not installed. Install with: pip install matplotlib")
            return None
        
        depth_counts: Dict[int, int] = defaultdict(int)
        
        for pkg in self.results.values():
            depth_counts[pkg.depth] += 1
        
        if not depth_counts:
            return None
        
        fig, ax = plt.subplots(figsize=(10, 8))
        
        depths = sorted(depth_counts.keys())
        counts = [depth_counts[d] for d in depths]
        labels = [f"Depth {d}" for d in depths]
        colors = plt.cm.Blues([0.3 + 0.1 * d for d in depths])
        
        wedges, texts, autotexts = ax.pie(counts, labels=labels, autopct='%1.1f%%',
                                           colors=colors, startangle=90)
        
        ax.set_title('Dependency Distribution by Depth')
        
        # Add legend with actual counts
        legend_labels = [f"{l}: {c} packages" for l, c in zip(labels, counts)]
        ax.legend(wedges, legend_labels, loc="center left", bbox_to_anchor=(1, 0.5))
        
        plt.tight_layout()
        
        if output_path:
            plt.savefig(output_path, dpi=150, bbox_inches='tight')
            plt.close()
            return None
        else:
            buf = BytesIO()
            plt.savefig(buf, format='png', dpi=150, bbox_inches='tight')
            plt.close()
            buf.seek(0)
            return buf.read()


def generate_report(results: Dict[str, PackageAnalysis], 
                    dependency_graph: Dict[str, List[str]],
                    root_package: str,
                    output_dir: Path,
                    format: str = "md") -> Path:
    """Generate a comprehensive supply chain report."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir.mkdir(exist_ok=True)
    
    visualizer = SupplyChainVisualizer(results, dependency_graph)
    
    # Calculate summary statistics
    total_packages = len(results)
    total_vulns = sum(len(pkg.security_info) for pkg in results.values())
    packages_with_vulns = sum(1 for pkg in results.values() if pkg.security_info)
    total_contributors = sum(
        pkg.contributor_stats.total_contributors 
        for pkg in results.values() 
        if pkg.contributor_stats
    )
    
    if format == "json":
        # JSON report
        report_path = output_dir / f"supply_chain_{root_package}_{timestamp}.json"
        report_data = {
            "timestamp": timestamp,
            "root_package": root_package,
            "summary": {
                "total_packages": total_packages,
                "total_vulnerabilities": total_vulns,
                "packages_with_vulnerabilities": packages_with_vulns,
                "total_contributors": total_contributors,
            },
            "packages": {name: pkg.to_dict() for name, pkg in results.items()},
            "dependency_graph": dict(dependency_graph),
        }
        
        with open(report_path, "w") as f:
            json.dump(report_data, f, indent=2, default=str)
    
    else:  # Markdown
        report_path = output_dir / f"supply_chain_{root_package}_{timestamp}.md"
        
        # Generate visualizations
        vuln_chart_path = output_dir / f"vulnerabilities_{root_package}_{timestamp}.png"
        contrib_chart_path = output_dir / f"contributors_{root_package}_{timestamp}.png"
        depth_chart_path = output_dir / f"depth_distribution_{root_package}_{timestamp}.png"
        
        visualizer.generate_vulnerability_chart(vuln_chart_path)
        visualizer.generate_contributor_chart(contrib_chart_path)
        visualizer.generate_depth_distribution_chart(depth_chart_path)
        
        # Generate ASCII tree
        ascii_tree = visualizer.generate_dependency_tree_ascii(root_package)
        
        with open(report_path, "w") as f:
            f.write(f"# Supply Chain Analysis: {root_package}\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Summary
            f.write("## Summary\n\n")
            f.write(f"- **Total Packages Analyzed**: {total_packages}\n")
            f.write(f"- **Total Vulnerabilities Found**: {total_vulns}\n")
            f.write(f"- **Packages with Vulnerabilities**: {packages_with_vulns}\n")
            f.write(f"- **Total Contributors**: {total_contributors}\n\n")
            
            # Dependency Tree
            f.write("## Dependency Tree\n\n")
            f.write("```\n")
            f.write(ascii_tree)
            f.write("\n```\n\n")
            
            # Visualizations
            f.write("## Visualizations\n\n")
            if vuln_chart_path.exists():
                f.write(f"### Vulnerabilities by Package\n\n")
                f.write(f"![Vulnerabilities Chart]({vuln_chart_path.name})\n\n")
            if depth_chart_path.exists():
                f.write(f"### Dependency Distribution by Depth\n\n")
                f.write(f"![Depth Distribution]({depth_chart_path.name})\n\n")
            if contrib_chart_path.exists():
                f.write(f"### Top Contributors\n\n")
                f.write(f"![Contributors Chart]({contrib_chart_path.name})\n\n")
            
            # Vulnerability Details
            f.write("## Vulnerability Details\n\n")
            for name, pkg in sorted(results.items(), 
                                    key=lambda x: len(x[1].security_info), 
                                    reverse=True):
                if pkg.security_info:
                    f.write(f"### {name} ({pkg.version})\n\n")
                    f.write(f"**Vulnerabilities**: {len(pkg.security_info)}\n\n")
                    for vuln in pkg.security_info[:5]:  # Show top 5
                        f.write(f"- **{vuln.get('vulnerability_id', 'Unknown')}** ({vuln.get('source', 'Unknown')})\n")
                        advisory = vuln.get('advisory', 'No description')[:200]
                        f.write(f"  - {advisory}...\n")
                    if len(pkg.security_info) > 5:
                        f.write(f"\n*...and {len(pkg.security_info) - 5} more vulnerabilities*\n")
                    f.write("\n")
            
            # Contributor Statistics
            f.write("## Contributor Statistics\n\n")
            for name, pkg in results.items():
                if pkg.contributor_stats and pkg.contributor_stats.top_contributors:
                    f.write(f"### {name}\n\n")
                    f.write(f"**Total Contributors**: {pkg.contributor_stats.total_contributors}\n\n")
                    f.write("| Contributor | Contributions |\n")
                    f.write("|-------------|---------------|\n")
                    for contrib in pkg.contributor_stats.top_contributors[:5]:
                        f.write(f"| {contrib['login']} | {contrib['contributions']} |\n")
                    f.write("\n")
    
    return report_path


async def run_recursive_analysis(package_name: str, 
                                  max_depth: int = 3,
                                  include_contributors: bool = True,
                                  output_format: str = "md",
                                  output_dir: Optional[str] = None) -> Path:
    """
    Run a complete recursive supply chain analysis.
    
    Args:
        package_name: The package to analyze
        max_depth: Maximum depth of dependencies to analyze
        include_contributors: Whether to fetch contributor statistics
        output_format: Output format ("md" or "json")
        output_dir: Output directory for reports
        
    Returns:
        Path to the generated report
    """
    click.echo(f"\n🔍 Starting recursive supply chain analysis for {package_name}")
    click.echo(f"   Max depth: {max_depth}")
    click.echo(f"   Include contributors: {include_contributors}\n")
    
    analyzer = RecursiveAnalyzer(
        max_depth=max_depth,
        include_contributors=include_contributors
    )
    
    results = await analyzer.analyze(package_name)
    
    # Calculate summary
    total_vulns = sum(len(pkg.security_info) for pkg in results.values())
    
    click.echo(f"\n📊 Analysis Complete!")
    click.echo(f"   Packages analyzed: {len(results)}")
    click.echo(f"   Total vulnerabilities: {total_vulns}")
    
    # Generate report
    report_dir = Path(output_dir) if output_dir else Path("reports")
    report_path = generate_report(
        results, 
        analyzer.dependency_graph,
        package_name,
        report_dir,
        output_format
    )
    
    click.echo(f"\n📄 Report saved to: {report_path}")
    
    return report_path


@click.command()
@click.argument("package_name")
@click.option("--max-depth", "-d", default=3, help="Maximum depth to analyze (default: 3)")
@click.option("--no-contributors", is_flag=True, help="Skip fetching contributor statistics")
@click.option("--format", "-f", type=click.Choice(["md", "json"]), default="md",
              help="Output format (default: md)")
@click.option("--output", "-o", type=click.Path(), help="Output directory for reports")
def main(package_name: str, max_depth: int, no_contributors: bool, 
         format: str, output: Optional[str]):
    """
    Recursively analyze a package's entire supply chain.
    
    Includes security vulnerabilities, GitHub metrics, and contributor statistics
    for the package and all its dependencies.
    
    Example:
        bettercheck-recursive flask --max-depth 2 --format md
    """
    try:
        validate_package_name(package_name)
    except SecurityError as e:
        click.echo(f"Error: {e}", err=True)
        return
    
    asyncio.run(run_recursive_analysis(
        package_name,
        max_depth=max_depth,
        include_contributors=not no_contributors,
        output_format=format,
        output_dir=output
    ))


if __name__ == "__main__":
    main()
