import asyncio
import aiohttp
from dataclasses import dataclass
from typing import List, Set, Dict, Optional
import click
from bettercheck.security import validate_package_name
import logging
from packaging.requirements import Requirement
from packaging.version import parse
import json as json_module
from pathlib import Path
import time


@dataclass
class DependencyNode:
    name: str
    version: str
    requires: List["DependencyNode"]
    depth: int
    parent: Optional[str] = None

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "requires": [dep.to_dict() for dep in self.requires],
            "depth": self.depth,
            "parent": self.parent,
        }


class DependencyAnalyzer:
    def __init__(self, cache_dir: Path = None):
        self.seen_packages: Set[str] = set()
        self.cache_dir = cache_dir or Path.home() / ".bettercheck" / "cache"
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.session = None
        self.logger = logging.getLogger(__name__)

    async def init_session(self):
        if not self.session:
            self.session = aiohttp.ClientSession()

    async def close_session(self):
        if self.session:
            await self.session.close()
            self.session = None

    def _get_cache_path(self, package_name: str) -> Path:
        return self.cache_dir / f"{package_name}.json"

    def _cache_deps(self, package_name: str, data: dict):
        cache_path = self._get_cache_path(package_name)
        with open(cache_path, "w") as f:
            json_module.dump(data, f)

    def _get_cached_deps(self, package_name: str) -> Optional[dict]:
        cache_path = self._get_cache_path(package_name)
        if cache_path.exists():
            cache_age = time.time() - cache_path.stat().st_mtime
            if cache_age < 86400:  # 24 hour cache
                with open(cache_path) as f:
                    return json_module.load(f)
        return None

    async def get_package_deps(self, package_name: str) -> Optional[Dict]:
        """Get package dependencies from PyPI"""
        cached = self._get_cached_deps(package_name)
        if cached:
            return cached

        try:
            url = f"https://pypi.org/pypi/{package_name}/json"
            async with self.session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    deps = self._extract_deps(data)
                    self._cache_deps(package_name, deps)
                    return deps
                return None
        except Exception as e:
            self.logger.error(f"Error fetching {package_name}: {e}")
            return None

    def _extract_deps(self, pypi_data: dict) -> Dict:
        """Extract dependencies from PyPI JSON data"""
        info = pypi_data["info"]
        requires = info.get("requires_dist", []) or []

        deps = []
        for req in requires:
            try:
                # Parse requirement string
                requirement = Requirement(req)
                # Skip environment markers
                if requirement.marker is None or requirement.marker.evaluate():
                    deps.append(requirement.name)
            except Exception as e:
                self.logger.warning(f"Could not parse requirement {req}: {e}")

        return {"name": info["name"], "version": info["version"], "dependencies": deps}

    async def build_tree(
        self, package_name: str, max_depth: int = 5, depth: int = 0
    ) -> Optional[DependencyNode]:
        """Build dependency tree recursively"""
        if depth > max_depth:
            return None

        if package_name.lower() in self.seen_packages:
            return DependencyNode(package_name, "circular", [], depth)

        self.seen_packages.add(package_name.lower())

        package_info = await self.get_package_deps(package_name)
        if not package_info:
            return None

        requires = []
        for dep in package_info["dependencies"]:
            child = await self.build_tree(dep, max_depth, depth + 1)
            if child:
                child.parent = package_name
                requires.append(child)

        return DependencyNode(
            name=package_info["name"],
            version=package_info["version"],
            requires=requires,
            depth=depth,
        )


async def analyze_deps(package_name: str, max_depth: int = 5) -> Optional[Dict]:
    """Main function to analyze dependencies"""
    analyzer = DependencyAnalyzer()
    await analyzer.init_session()

    try:
        tree = await analyzer.build_tree(package_name, max_depth)
        return tree.to_dict() if tree else None
    finally:
        await analyzer.close_session()


def print_tree(node: dict, prefix: str = ""):
    """Print dependency tree in a readable format"""
    print(f"{prefix}{'└─' if prefix else ''}{node['name']} ({node['version']})")
    for dep in node["requires"]:
        print_tree(dep, prefix + "  ")


@click.command()
@click.argument("package_name")
@click.option("--max-depth", "-d", default=5, help="Maximum depth to analyze")
@click.option("--json", "-j", is_flag=True, help="Output as JSON")
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    help="Save to file (automatically enables JSON output)",
)
def main(package_name: str, max_depth: int, json: bool, output: str):
    """Analyze package dependencies recursively"""
    # If output is specified, enable JSON mode
    if output:
        json = True

    try:
        validate_package_name(package_name)
    except Exception as e:
        click.echo(f"Invalid package name: {e}")
        return

    tree = asyncio.run(analyze_deps(package_name, max_depth))

    if not tree:
        click.echo("Could not analyze dependencies")
        return

    if json:
        result = json_module.dumps(tree, indent=2)
    else:
        # Print tree structure
        print_tree(tree)
        return

    if output:
        with open(output, "w") as f:
            f.write(result)
        click.echo(f"Results saved to {output}")
    else:
        click.echo(result)


if __name__ == "__main__":
    main()
