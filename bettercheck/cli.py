import click
import logging
from bettercheck.checker import PackageChecker
from datetime import datetime
import os
import asyncio


@click.command()
@click.argument("package_name")
@click.option("--json", is_flag=True, help="Output in JSON format")
@click.option("--debug", is_flag=True, help="Enable debug logging")
@click.option(
    "--report", type=click.Choice(["txt", "md"]), help="Generate a report file"
)
def main(package_name, json, debug, report):
    """Check Python package information and metrics"""
    return asyncio.run(_async_main(package_name, json, debug, report))


async def _async_main(package_name, json, debug, report):
    # Setup console logging
    log_level = logging.DEBUG if debug else logging.WARNING
    logging.getLogger().setLevel(log_level)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    logging.getLogger().addHandler(console_handler)

    checker = PackageChecker(package_name)

    pypi_info = checker.check_pypi_info()
    security_info = await checker.check_security()
    github_metrics = None

    if pypi_info and pypi_info["github_url"]:
        github_metrics = checker.check_github_metrics(pypi_info["github_url"])

    if report:
        generate_report(package_name, pypi_info, security_info, github_metrics, report)
    elif json:
        click.echo(
            {"pypi": pypi_info, "security": security_info, "github": github_metrics}
        )
    else:
        _print_formatted_results(pypi_info, security_info, github_metrics)


def _print_formatted_results(pypi_info, security_info, github_metrics):
    logger = logging.getLogger(__name__)

    # Package Information logging
    logger.info("=== Package Information ===")
    if pypi_info:
        logger.info(f"Name: {pypi_info['name']}")
        logger.info(f"Version: {pypi_info['version']}")
        logger.info(f"License: {pypi_info['license']}")
        if pypi_info["downloads"]:
            logger.info(
                f"Downloads (last month): {pypi_info['downloads']['last_month']:,}"
            )
            logger.info(
                f"Downloads (last week): {pypi_info['downloads']['last_week']:,}"
            )

    # GitHub Metrics logging
    if github_metrics:
        logger.info("=== GitHub Metrics ===")
        logger.info(f"Stars: {github_metrics['stars']:,}")
        logger.info(f"Forks: {github_metrics['forks']:,}")
        logger.info(f"Open Issues: {github_metrics['open_issues']:,}")
        logger.info(f"Last Update: {github_metrics['last_commit']}")

    # Security Information logging
    if security_info:
        logger.info("=== Security Information ===")
        if not security_info:
            logger.info("No known vulnerabilities found")
        else:
            # Group vulnerabilities by source
            vulns_by_source = {}
            for vuln in security_info:
                source = vuln["source"]
                vulns_by_source.setdefault(source, []).append(vuln)

            total_vulns = len(security_info)
            logger.info(f"Found {total_vulns} vulnerabilities:")

            # Log summary by source
            for source, vulns in vulns_by_source.items():
                logger.info(f"{source} Vulnerabilities: {len(vulns)}")

            # Original display logic with added logging
            if click.confirm("\nDo you want to see vulnerability details?"):
                logger.info("User requested vulnerability details")
                page_size = 10
                current_page = 0
                total_pages = (total_vulns + page_size - 1) // page_size

                while current_page < total_pages:
                    start_idx = current_page * page_size
                    end_idx = min(start_idx + page_size, total_vulns)

                    page_msg = f"Showing vulnerabilities {start_idx + 1}-{end_idx} of {total_vulns}"
                    logger.info(page_msg)
                    click.echo(f"\n{page_msg}")

                    for vuln in security_info[start_idx:end_idx]:
                        vuln_msg = f"- [{vuln['source']}] {vuln['vulnerability_id']}: {vuln['advisory']}"
                        logger.info(vuln_msg)
                        click.echo(vuln_msg)

                    if current_page < total_pages - 1:
                        if not click.confirm("\nShow next page?"):
                            logger.info("User chose to stop viewing vulnerabilities")
                            break
                        logger.info("User requested next page of vulnerabilities")
                    current_page += 1
            else:
                logger.info("User declined to view vulnerability details")

    # Print to console (keep existing click.echo statements)
    click.echo("\n=== Package Information ===")
    if pypi_info:
        click.echo(f"Name: {pypi_info['name']}")
        click.echo(f"Version: {pypi_info['version']}")
        click.echo(f"License: {pypi_info['license']}")
        if pypi_info["downloads"]:
            click.echo(
                f"Downloads (last month): {pypi_info['downloads']['last_month']:,}"
            )
            click.echo(
                f"Downloads (last week): {pypi_info['downloads']['last_week']:,}"
            )

    if github_metrics:
        click.echo("\n=== GitHub Metrics ===")
        click.echo(f"Stars: {github_metrics['stars']:,}")
        click.echo(f"Forks: {github_metrics['forks']:,}")
        click.echo(f"Open Issues: {github_metrics['open_issues']:,}")
        click.echo(f"Last Update: {github_metrics['last_commit']}")

    if security_info:
        click.echo("\n=== Security Information ===")
        if not security_info:
            click.echo("No known vulnerabilities found")
        else:
            # Group vulnerabilities by source
            vulns_by_source = {}
            for vuln in security_info:
                source = vuln["source"]
                vulns_by_source.setdefault(source, []).append(vuln)

            total_vulns = len(security_info)
            click.echo(f"Found {total_vulns} vulnerabilities:")

            # Print summary by source
            for source, vulns in vulns_by_source.items():
                click.echo(f"\n{source} Vulnerabilities: {len(vulns)}")

            # Ask user if they want to see details
            if click.confirm("\nDo you want to see vulnerability details?"):
                page_size = 10
                current_page = 0
                total_pages = (total_vulns + page_size - 1) // page_size

                while current_page < total_pages:
                    start_idx = current_page * page_size
                    end_idx = min(start_idx + page_size, total_vulns)

                    click.echo(
                        f"\nShowing vulnerabilities {start_idx + 1}-{end_idx} of {total_vulns}"
                    )
                    for vuln in security_info[start_idx:end_idx]:
                        click.echo(
                            f"- [{vuln['source']}] {vuln['vulnerability_id']}: {vuln['advisory']}"
                        )

                    if current_page < total_pages - 1:
                        if not click.confirm("\nShow next page?"):
                            break
                    current_page += 1


def generate_report(package_name, pypi_info, security_info, github_metrics, format):
    """Generate a detailed report in the specified format"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    os.makedirs(report_dir, exist_ok=True)

    filename = f"package_report_{package_name}_{timestamp}.{format}"
    filepath = os.path.join(report_dir, filename)

    content = []
    if format == "md":
        content.extend(
            [
                f"# Package Analysis Report: {package_name}",
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                "## Package Information",
            ]
        )
    else:
        content.extend(
            [
                f"Package Analysis Report: {package_name}",
                f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n",
                "Package Information",
                "-------------------",
            ]
        )

    if pypi_info:
        content.extend(
            [
                f"Name: {pypi_info['name']}",
                f"Version: {pypi_info['version']}",
                f"License: {pypi_info['license']}",
            ]
        )
        if pypi_info["downloads"]:
            content.extend(
                [
                    f"Downloads (last month): {pypi_info['downloads']['last_month']:,}",
                    f"Downloads (last week): {pypi_info['downloads']['last_week']:,}\n",
                ]
            )

    if github_metrics:
        content.extend(
            [
                "GitHub Metrics" if format == "txt" else "## GitHub Metrics",
                f"Stars: {github_metrics['stars']:,}",
                f"Forks: {github_metrics['forks']:,}",
                f"Open Issues: {github_metrics['open_issues']:,}",
                f"Last Update: {github_metrics['last_commit']}\n",
            ]
        )

    if security_info:
        content.extend(
            [
                "Security Analysis" if format == "txt" else "## Security Analysis",
                f"Total Vulnerabilities Found: {len(security_info)}\n",
            ]
        )

        # Group vulnerabilities by source
        vulns_by_source = {}
        for vuln in security_info:
            source = vuln["source"]
            vulns_by_source.setdefault(source, []).append(vuln)

        for source, vulns in vulns_by_source.items():
            content.append(f"{source} Vulnerabilities: {len(vulns)}")
            for vuln in vulns:
                content.append(f"- {vuln['vulnerability_id']}: {vuln['advisory']}")
            content.append("")

    with open(filepath, "w", encoding="utf-8") as f:
        f.write("\n".join(content))

    click.echo(f"Report generated: {filepath}")


if __name__ == "__main__":
    main()
