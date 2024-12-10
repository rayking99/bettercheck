# Examples/report_examples.py
import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Literal
from bettercheck.checker import PackageChecker
from bettercheck.dep_tree import analyze_deps


class PackageReport:
    def __init__(self, package_name: str):
        self.package_name = package_name
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    async def generate_single_report(self) -> Dict[str, Any]:
        checker = PackageChecker(self.package_name)

        pypi_info = checker.check_pypi_info()
        security_info = await checker.check_security()
        github_metrics = None
        if pypi_info and pypi_info["github_url"]:
            github_metrics = checker.check_github_metrics(pypi_info["github_url"])

        return {
            "timestamp": self.timestamp,
            "package": self.package_name,
            "pypi": pypi_info,
            "security": security_info,
            "github": github_metrics,
        }

    async def generate_recursive_report(self, max_depth: int = 2) -> Dict[str, Any]:
        deps_tree = await analyze_deps(self.package_name, max_depth)
        results = {"timestamp": self.timestamp, "dependencies": {}}

        async def analyze_dep(node: Dict):
            name = node["name"]
            checker = PackageChecker(name)

            results["dependencies"][name] = {
                "version": node["version"],
                "depth": node["depth"],
                "pypi": checker.check_pypi_info(),
                "security": await checker.check_security(),
            }

            for dep in node.get("requires", []):
                await analyze_dep(dep)

        await analyze_dep(deps_tree)
        return results

    def save_report(self, data: Dict, format: Literal["json", "md", "txt"] = "json"):
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)

        base_name = f"{self.package_name}_report_{self.timestamp}"

        if format == "json":
            path = reports_dir / f"{base_name}.json"
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)

        elif format == "md":
            path = reports_dir / f"{base_name}.md"
            with open(path, "w") as f:
                f.write(self._format_markdown(data))

        else:  # txt
            path = reports_dir / f"{base_name}.txt"
            with open(path, "w") as f:
                f.write(self._format_text(data))

        return path

    def _format_markdown(self, data: Dict) -> str:
        md = [f"# Security Report: {self.package_name}"]
        md.append(f"\nGenerated: {data['timestamp']}\n")

        if "dependencies" in data:  # Recursive report
            total_vulns = sum(
                len(dep_data["security"] or [])
                for dep_data in data["dependencies"].values()
            )
            md.append(f"## Summary\n")
            md.append(f"- Total Dependencies: {len(data['dependencies'])}")
            md.append(f"- Total Vulnerabilities: {total_vulns}\n")

            for name, dep_data in data["dependencies"].items():
                md.append(f"## {name} (Depth: {dep_data['depth']})")
                if dep_data["security"]:
                    md.append(f"\n### Vulnerabilities ({len(dep_data['security'])})")
                    for vuln in dep_data["security"]:
                        md.append(
                            f"\n- **{vuln['vulnerability_id']}** ({vuln['source']})"
                        )
                        md.append(f"  - {vuln['advisory'][:200]}...")
                else:
                    md.append("\nNo known vulnerabilities")
                md.append("")

        else:  # Single package report
            if data["security"]:
                md.append(f"## Vulnerabilities ({len(data['security'])})\n")
                for vuln in data["security"]:
                    md.append(f"### {vuln['vulnerability_id']} ({vuln['source']})")
                    md.append(f"\n{vuln['advisory']}\n")
            else:
                md.append("\n## Security\nNo known vulnerabilities")

            if data["github"]:
                md.append("\n## GitHub Metrics")
                md.append(f"- Stars: {data['github']['stars']:,}")
                md.append(f"- Forks: {data['github']['forks']:,}")
                md.append(f"- Open Issues: {data['github']['open_issues']:,}")

        return "\n".join(md)

    def _format_text(self, data: Dict) -> str:
        # Similar to markdown but with plain text formatting
        lines = [
            f"Security Report: {self.package_name}",
            f"Generated: {data['timestamp']}",
            "-" * 50,
        ]

        # Add formatting similar to markdown but with plain text
        return "\n".join(lines)


async def main():
    # Example usage
    report = PackageReport("requests")

    # Single package report
    single_data = await report.generate_single_report()
    json_path = report.save_report(single_data, "json")
    md_path = report.save_report(single_data, "md")
    print(f"Reports generated: {json_path}, {md_path}")

    # Recursive report
    recursive_data = await report.generate_recursive_report(max_depth=2)
    rec_json_path = report.save_report(recursive_data, "json")
    rec_md_path = report.save_report(recursive_data, "md")
    print(f"Recursive reports generated: {rec_json_path}, {rec_md_path}")


if __name__ == "__main__":
    asyncio.run(main())
