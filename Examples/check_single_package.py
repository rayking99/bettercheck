# Examples/check_single_package.py
import asyncio
from bettercheck.checker import PackageChecker


async def check_package(package_name: str):
    """Example of checking a single package"""
    checker = PackageChecker(package_name)

    # Get basic package info
    pypi_info = checker.check_pypi_info()
    print(f"\nPackage Information for {package_name}:")
    print("-" * 50)
    if pypi_info:
        print(f"Version: {pypi_info['version']}")
        print(f"Monthly Downloads: {pypi_info['downloads']['last_month']:,}")
        print(f"License: {pypi_info['license']}")

    # Check security
    security_info = await checker.check_security()
    print("\nSecurity Information:")
    print("-" * 50)
    if security_info:
        print(f"Found {len(security_info)} vulnerabilities:")
        for vuln in security_info:
            print(f"- [{vuln['source']}] {vuln['vulnerability_id']}")
            print(f"  {vuln['advisory'][:200]}...")
    else:
        print("No known vulnerabilities found")

    # Get GitHub metrics if available
    if pypi_info and pypi_info["github_url"]:
        github_metrics = checker.check_github_metrics(pypi_info["github_url"])
        if github_metrics:
            print("\nGitHub Metrics:")
            print("-" * 50)
            print(f"Stars: {github_metrics['stars']:,}")
            print(f"Forks: {github_metrics['forks']:,}")
            print(f"Open Issues: {github_metrics['open_issues']:,}")
            print(f"Last Update: {github_metrics['last_commit']}")


if __name__ == "__main__":
    package_name = "requests"  # Example package
    asyncio.run(check_package(package_name))
