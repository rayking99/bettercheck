import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import click

from bettercheck.checker import PackageChecker
from bettercheck.dep_tree import analyze_deps
from bettercheck.security import SecurityError, read_file_chunked, validate_package_name


def get_dependencies() -> List[str]:
    """Extract dependencies from setup.py"""
    # Change path to look in project root instead of src directory
    setup_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "setup.py"
    )
    try:
        content = read_file_chunked(setup_path)
    except SecurityError as e:
        click.echo(f"Error reading setup.py: {str(e)}")
        return []

    # Extract install_requires list
    start = content.find("install_requires=[") + len("install_requires=[")
    end = content.find("]", start)
    deps_block = content[start:end]

    # Parse dependencies
    deps = [
        dep.strip().strip('"').strip("'")
        for dep in deps_block.split(",")
        if dep.strip()
    ]
    return deps


async def get_all_dependencies() -> List[str]:
    """Get direct and transitive dependencies from setup.py"""
    direct_deps = get_dependencies()
    all_deps = set()

    for dep in direct_deps:
        try:
            # Get dependency tree for each direct dependency
            tree = await analyze_deps(dep, max_depth=5)
            if tree:
                # Add the root package
                all_deps.add(tree["name"])

                # Recursively collect all dependencies
                def collect_deps(node):
                    for req in node.get("requires", []):
                        all_deps.add(req["name"])
                        collect_deps(req)

                collect_deps(tree)
        except Exception as e:
            click.echo(f"Warning: Failed to analyze dependencies for {dep}: {str(e)}")
            # Still include the direct dependency even if we can't get its tree
            all_deps.add(dep)

    return list(all_deps)


async def analyze_dependencies(dependencies: List[str]) -> Dict:
    """Analyze each dependency using PackageChecker"""
    # Get all direct and transitive dependencies
    all_deps = await get_all_dependencies()
    click.echo(f"\nAnalyzing {len(all_deps)} total dependencies...")
    results = {}

    for dep in all_deps:
        try:
            validate_package_name(dep)
        except SecurityError as e:
            click.echo(f"Warning: Skipping invalid package {dep}: {str(e)}")
            continue

        click.echo(f"\nAnalyzing {dep}...")
        checker = PackageChecker(dep)

        # Gather all checks concurrently
        pypi_info = checker.check_pypi_info()
        security_info = await checker.check_security()
        github_metrics = None

        if pypi_info and pypi_info["github_url"]:
            github_metrics = checker.check_github_metrics(pypi_info["github_url"])

        results[dep] = {
            "pypi": pypi_info,
            "security": security_info,
            "github": github_metrics,
        }

    return results


def print_analysis(results: Dict):
    """Print analysis results in a structured format"""
    click.echo("\n=== Dependencies Security Analysis ===\n")

    # Count total vulnerabilities
    total_vulns = sum(len(data["security"] or []) for data in results.values())

    click.echo(f"Total packages analyzed: {len(results)}")
    click.echo(f"Total vulnerabilities found: {total_vulns}\n")

    # Print details for each package
    for pkg_name, data in results.items():
        click.echo(f"\n{pkg_name}:")
        click.echo("-------------------")

        if data["pypi"]:
            click.echo(f"Version: {data['pypi']['version']}")
            downloads = data["pypi"].get("downloads")
            if downloads and downloads.get("last_month"):
                click.echo(f"Monthly downloads: {downloads['last_month']:,}")

        if data["security"]:
            click.echo(f"Vulnerabilities: {len(data['security'])}")
            for vuln in data["security"]:
                click.echo(f"- [{vuln['source']}] {vuln['vulnerability_id']}")
        else:
            click.echo("No known vulnerabilities")

        if data["github"]:
            click.echo("\nGitHub Metrics:")
            if data["github"].get("stars") is not None:
                click.echo(f"Stars: {data['github']['stars']:,}")
            if data["github"].get("forks") is not None:
                click.echo(f"Forks: {data['github']['forks']:,}")
            if data["github"].get("open_issues") is not None:
                click.echo(f"Open Issues: {data['github']['open_issues']:,}")
            if data["github"].get("last_commit") is not None:
                click.echo(f"Last Update: {data['github']['last_commit']}")


def save_results(results: Dict):
    """Save analysis results to JSON file"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    # Use project root instead of package directory
    report_dir = Path(__file__).parent.parent.parent / "reports"
    report_dir.mkdir(exist_ok=True)

    filename = f"bettercheck-{timestamp}.json"
    filepath = report_dir / filename

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            # Write JSON in chunks
            for chunk in json.JSONEncoder(indent=2, default=str).iterencode(results):
                f.write(chunk)
    except Exception as e:
        click.echo(f"Error saving results: {str(e)}")

    click.echo(f"\nReport saved to: {filepath}")


@click.command()
@click.option("--direct-only", is_flag=True, help="Only analyze direct dependencies")
def main(direct_only):
    """Analyze all project dependencies for security issues"""
    if direct_only:
        deps = get_dependencies()
        results = asyncio.run(analyze_dependencies(deps))
    else:
        results = asyncio.run(
            analyze_dependencies([])
        )  # Empty list since get_all_dependencies will be called

    # Always save JSON report and print analysis
    save_results(results)
    print_analysis(results)


if __name__ == "__main__":
    main()
