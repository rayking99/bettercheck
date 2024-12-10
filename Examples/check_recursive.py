# Examples/check_recursive.py
import asyncio
from typing import Dict, Set
from bettercheck.checker import PackageChecker
from bettercheck.dep_tree import analyze_deps


async def check_package_recursive(package_name: str, max_depth: int = 3):
    """Example of recursively checking a package and its dependencies"""
    seen_packages: Set[str] = set()
    results: Dict = {}

    async def analyze_package(pkg_name: str, depth: int = 0):
        if depth > max_depth or pkg_name in seen_packages:
            return

        seen_packages.add(pkg_name)
        print(f"\nAnalyzing {pkg_name} (depth {depth})...")

        # Create checker instance
        checker = PackageChecker(pkg_name)

        # Gather package information
        pypi_info = checker.check_pypi_info()
        security_info = await checker.check_security()
        github_metrics = None
        if pypi_info and pypi_info["github_url"]:
            github_metrics = checker.check_github_metrics(pypi_info["github_url"])

        # Store results
        results[pkg_name] = {
            "depth": depth,
            "pypi": pypi_info,
            "security": security_info,
            "github": github_metrics,
        }

        # Get dependencies
        deps_tree = await analyze_deps(pkg_name, max_depth=1)
        if deps_tree:
            for dep in deps_tree.get("requires", []):
                await analyze_package(dep["name"], depth + 1)

    # Start recursive analysis
    await analyze_package(package_name)

    # Print summary
    print("\nAnalysis Summary:")
    print("-" * 50)
    print(f"Total packages analyzed: {len(results)}")
    total_vulns = sum(len(data["security"] or []) for data in results.values())
    print(f"Total vulnerabilities found: {total_vulns}")

    # Print details for each package
    for pkg_name, data in results.items():
        print(f"\n{pkg_name} (depth {data['depth']}):")
        print("-" * 40)

        if data["pypi"]:
            print(f"Version: {data['pypi']['version']}")
            if data["pypi"]["downloads"].get("last_month"):
                print(f"Monthly downloads: {data['pypi']['downloads']['last_month']:,}")

        if data["security"]:
            print(f"Vulnerabilities: {len(data['security'])}")
            for vuln in data["security"]:
                print(f"- [{vuln['source']}] {vuln['vulnerability_id']}")
        else:
            print("No known vulnerabilities")


if __name__ == "__main__":
    package_name = "flask"  # Example package
    asyncio.run(check_package_recursive(package_name, max_depth=2))
