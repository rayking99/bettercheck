import asyncio
import logging
import os
from datetime import datetime, timezone

import aiohttp
import requests
from github import Github
from packaging.version import parse

from bettercheck.report_utils import get_log_path
from bettercheck.security import (
    NVD_SCHEMA,
    OSV_SCHEMA,
    PYPI_SCHEMA,
    SanitizedFormatter,
    SecurityError,
    validate_json_response,
    validate_package_name,
)


class PackageChecker:
    def __init__(self, package_name):
        # Validate package name before using it
        validate_package_name(package_name)
        self.package_name = package_name
        self.pypi_api = f"https://pypi.org/pypi/{package_name}/json"
        self.github = Github()
        self.osv_api = "https://api.osv.dev/v1/query"
        self.nvd_api = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.session = None  # Will be initialized in async context

        # Setup logging
        log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs")
        os.makedirs(log_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = get_log_path(package_name, timestamp)

        self.logger = logging.getLogger(f"package_checker_{package_name}")
        self.logger.setLevel(logging.INFO)

        formatter = SanitizedFormatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)

    def check_pypi_info(self):
        self.logger.info(f"Checking PyPI information for package: {self.package_name}")
        try:
            response = requests.get(self.pypi_api)
            response.raise_for_status()
            data = response.json()

            # Validate response format
            validate_json_response(data, PYPI_SCHEMA, "PyPI")

            result = {
                "name": data["info"]["name"],
                "version": data["info"]["version"],
                "downloads": self._get_download_stats(),
                "github_url": self._extract_github_url(data["info"]),
                "license": data["info"]["license"],
            }
            self.logger.info(f"PyPI info retrieved successfully: {result}")
            return result
        except SecurityError as e:
            self.logger.error(f"Security validation failed: {str(e)}")
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve PyPI info: {str(e)}")
            return None

    async def _get_osv_details(self, vuln_id):
        """Fetch detailed information for an OSV vulnerability asynchronously."""
        self.logger.info(f"Fetching OSV details for: {vuln_id}")
        try:
            async with self.session.get(
                f"https://api.osv.dev/v1/vulns/{vuln_id}"
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "details": data.get("details", "No description available"),
                        "published": data.get("published"),
                        "modified": data.get("modified"),
                        "aliases": data.get("aliases", []),
                        "references": data.get("references", []),
                    }
        except Exception as e:
            self.logger.error(f"Failed to fetch OSV details for {vuln_id}: {str(e)}")
        return None

    async def check_security(self):
        self.logger.info(
            f"Checking security information for package: {self.package_name}"
        )
        vulnerabilities = []

        # Create aiohttp session
        async with aiohttp.ClientSession() as self.session:
            try:
                # Check OSV database
                self.logger.info("Querying OSV database...")
                query = {"package": {"name": self.package_name, "ecosystem": "PyPI"}}
                async with self.session.post(self.osv_api, json=query) as response:
                    if response.status == 200:
                        data = await response.json()
                        validate_json_response(data, OSV_SCHEMA, "OSV")
                        if "vulns" in data:
                            # Create tasks for concurrent detail fetching
                            detail_tasks = [
                                self._get_osv_details(vuln["id"])
                                for vuln in data["vulns"]
                            ]
                            # Gather all details concurrently
                            details_results = await asyncio.gather(*detail_tasks)

                            # Combine results with original vulnerabilities
                            for vuln, details in zip(data["vulns"], details_results):
                                vulnerabilities.append(
                                    {
                                        "source": "OSV",
                                        "vulnerability_id": vuln["id"],
                                        "advisory": (
                                            details.get("details")
                                            if details
                                            else vuln.get(
                                                "summary", "No description available"
                                            )
                                        ),
                                        "published": (
                                            details.get("published")
                                            if details
                                            else None
                                        ),
                                        "modified": (
                                            details.get("modified") if details else None
                                        ),
                                        "aliases": (
                                            details.get("aliases", [])
                                            if details
                                            else []
                                        ),
                                        "references": (
                                            details.get("references", [])
                                            if details
                                            else []
                                        ),
                                    }
                                )
            except SecurityError as e:
                self.logger.error(f"Security validation failed: {str(e)}")
                return []
            except Exception as e:
                self.logger.error(f"OSV security check failed: {str(e)}", exc_info=True)

            # Check NVD/CVE database
            try:
                self.logger.info("Querying NVD/CVE database...")
                cve_vulns = await self._check_cve()
                if cve_vulns:
                    vulnerabilities.extend(cve_vulns)
            except Exception as e:
                self.logger.error(f"CVE check failed: {str(e)}")

        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    def check_github_metrics(self, repo_url):
        self.logger.info(f"Checking GitHub metrics for repository: {repo_url}")
        if not repo_url:
            self.logger.warning("No GitHub URL provided")
            return None

        try:
            repo = self.github.get_repo(repo_url.replace("https://github.com/", ""))
            metrics = {
                "stars": repo.stargazers_count,
                "forks": repo.forks_count,
                "open_issues": repo.open_issues_count,
                "last_commit": repo.pushed_at,
                "created_at": repo.created_at,
                "updated_at": repo.updated_at,
                "subscribers_count": repo.subscribers_count,
                "network_count": repo.network_count,
                "default_branch": repo.default_branch,
            }
            self.logger.debug(f"Full GitHub Repository Information: {repo.raw_data}")
            self.logger.info(f"GitHub metrics retrieved successfully: {metrics}")
            return metrics
        except Exception as e:
            self.logger.error(
                f"Failed to retrieve GitHub metrics: {str(e)}", exc_info=True
            )
            return None

    def _get_download_stats(self):
        """Get download stats with fallback options"""
        self.logger.info("Retrieving download statistics...")
        stats = {"last_month": None, "last_week": None}

        try:
            # Try pypistats.org first
            stats_url = f"https://pypistats.org/api/packages/{self.package_name}/recent"
            response = requests.get(stats_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                stats.update(
                    {
                        "last_month": data["data"]["last_month"],
                        "last_week": data["data"]["last_week"],
                    }
                )
                return stats

            # Fallback to PyPI simple stats
            simple_url = f"https://pypi.org/pypi/{self.package_name}/json"
            response = requests.get(simple_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                if "info" in data and "downloads" in data["info"]:
                    stats["last_month"] = data["info"]["downloads"].get("last_month")
                    stats["last_week"] = data["info"]["downloads"].get("last_week")

        except Exception as e:
            self.logger.error(f"Failed to get download stats: {str(e)}")

        return stats

    def _extract_github_url(self, info):
        """Extract GitHub URL with better fallbacks and validation"""
        self.logger.info("Extracting GitHub URL from package info...")

        def clean_github_url(url):
            # Remove issue trackers, releases, etc and get main repo URL
            if not url:
                return None
            # Convert URL to main repository URL
            url = url.lower()
            url = url.replace("http://", "https://")
            parts = url.split("github.com/")
            if len(parts) < 2:
                return None
            repo_path = parts[1].split("/")
            if len(repo_path) < 2:
                return None
            return f"https://github.com/{repo_path[0]}/{repo_path[1]}"

        # Check project URLs first
        if project_urls := info.get("project_urls", {}):
            for label, url in project_urls.items():
                if url and "github.com" in url.lower():
                    if clean_url := clean_github_url(url):
                        self.logger.info(f"Found GitHub URL in project_urls[{label}]")
                        return clean_url

        # Check other common fields
        for field in ["home_page", "package_url", "download_url"]:
            if url := info.get(field):
                if "github.com" in url.lower():
                    if clean_url := clean_github_url(url):
                        self.logger.info(f"Found GitHub URL in {field}")
                        return clean_url

        # Check description for GitHub links
        if description := info.get("description", ""):
            import re

            if match := re.search(r"https?://github\.com/[\w-]+/[\w-]+", description):
                if clean_url := clean_github_url(match.group(0)):
                    self.logger.info("Found GitHub URL in description")
                    return clean_url

        self.logger.warning("No GitHub URL found")
        return None

    def _normalize_github_url(self, url: str) -> str:
        """Normalize GitHub URLs to consistent format"""
        url = url.strip().rstrip("/")
        url = url.replace("git+", "").replace(".git", "")
        url = url.replace("git://", "https://")
        if url.startswith("www."):
            url = "https://" + url
        return url

    async def _check_cve(self):
        self.logger.info("Checking CVE database...")
        try:
            # Ensure proper parameter types for NVD API
            params = {
                "keywordSearch": str(self.package_name),
                "keywordExactMatch": "true",  # API expects string "true" not boolean
            }

            async with self.session.get(self.nvd_api, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    validate_json_response(data, NVD_SCHEMA, "NVD")
                    vulnerabilities = []

                    for vuln in data.get("vulnerabilities", []):
                        cve = vuln.get("cve", {})
                        if any(
                            ref.get("url", "").lower().find("pypi") != -1
                            for ref in cve.get("references", [])
                        ):
                            description = "No description available"
                            descriptions = cve.get("descriptions", [])
                            if descriptions and isinstance(descriptions, list):
                                first_desc = descriptions[0]
                                if isinstance(first_desc, dict):
                                    description = first_desc.get("value", description)

                            vulnerabilities.append(
                                {
                                    "source": "CVE",
                                    "vulnerability_id": cve.get("id", "Unknown"),
                                    "advisory": description,
                                }
                            )
                    return vulnerabilities
                else:
                    self.logger.error(
                        f"NVD API returned status code: {response.status}"
                    )
                    return []
        except SecurityError as e:
            self.logger.error(f"Security validation failed: {str(e)}")
            return []
        except Exception as e:
            self.logger.error(f"Error during CVE check: {str(e)}", exc_info=True)
            return []
        return []
