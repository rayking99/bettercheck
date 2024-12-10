import ast
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import logging
import click
import sys


class SecurityFinding:
    # This class represents a single security finding discovered in the source code.
    # Each finding includes information like the type of risk, severity, line number, and context.
    def __init__(
        self,
        risk: str,
        severity: str,
        line_number: int,
        context: str,
        pattern: Optional[str] = None,
        recommendation: Optional[str] = None,
    ):
        self.pattern = pattern
        self.risk = risk
        self.severity = severity
        self.line_number = line_number
        self.context = context
        self.recommendation = recommendation

    def __str__(self):
        return (
            f"Line {self.line_number}: {self.risk} ({self.severity})\n"
            f"Context: {self.context}\n"
            f"Recommendation: {self.recommendation}"
        )


class SecurityScanner:
    """
    Security scanner for Python code that detects common vulnerabilities.
    This tool aims to help identify potential security issues in open-source supply chains
    by scanning Python files for known risky patterns and functions.
    The patterns are defined using regular expressions, and an AST-based approach is used for deeper analysis.
    """

    def __init__(self):
        # Define patterns with risk levels, descriptions, and recommendations
        # The `patterns` dictionary maps regex patterns to their associated risk details.
        # If you find any additional patterns you'd like to check for (e.g., suspicious imports,
        # known vulnerable package usage), you can add them here with appropriate recommendations.
        # These patterns focus on common pitfalls: disabling SSL verification, command injection,
        # unsafe code execution, hardcoded credentials, weak cryptographic hashes, insecure temp file usage,
        # unsafe XML and YAML parsing, and enabling debug mode in production.
        self.patterns = {
            # Network Security
            r"requests.*verify\s*=\s*False": {
                "risk": "SSL verification disabled",
                "severity": "CRITICAL",
                "description": "SSL certificate verification is disabled, enabling MITM attacks",
                "recommendation": "Enable SSL verification by setting `verify=True` in requests calls or specifying a CA bundle.",
            },
            # Additional dangerous URL patterns
            r"(http|ftp)://[^\s'\"]+": {
                "risk": "Insecure Protocol Usage",
                "severity": "HIGH",
                "description": "Using non-HTTPS protocols for data transfer",
                "recommendation": "Use HTTPS for all external connections to prevent data interception.",
            },
            # File Operations
            r"open\([^,)]+\)": {
                "risk": "Unsafe File Operations",
                "severity": "MEDIUM",
                "description": "Potential path traversal via file operations",
                "recommendation": "Validate and sanitize file paths before operations. Use pathlib for safer path handling.",
            },
            # Additional cryptography patterns
            r"random\.": {
                "risk": "Weak Random Number Generation",
                "severity": "MEDIUM",
                "description": "Using standard random module which is not cryptographically secure",
                "recommendation": "Use secrets module for cryptographic operations.",
            },
            # Command Injection
            r"os\.system": {
                "risk": "Command Injection",
                "severity": "HIGH",
                "description": "Use of os.system can lead to command injection if input is not sanitized.",
                "recommendation": "Use `subprocess` module with a list of arguments instead of a single string and avoid using `shell=True`.",
            },
            r"subprocess\..*shell\s*=\s*True": {
                "risk": "Command Injection",
                "severity": "HIGH",
                "description": "Shell command execution with potential injection vulnerabilities",
                "recommendation": "Avoid using `shell=True` in subprocess calls. If necessary, ensure proper input sanitization.",
            },
            # Dangerous Functions
            r"eval\(|exec\(": {
                "risk": "Code Execution",
                "severity": "CRITICAL",
                "description": "Dynamic code execution - potential for arbitrary code execution",
                "recommendation": "Avoid using `eval` and `exec` with untrusted input. Consider safer alternatives like `ast.literal_eval` for simple expressions.",
            },
            # Credential Patterns
            r"(?i)password\s*=\s*['\"][^'\"]+['\"]": {
                "risk": "Hardcoded Credentials",
                "severity": "HIGH",
                "description": "Hardcoded credentials detected",
                "recommendation": "Remove hardcoded credentials. Use environment variables or secure configuration mechanisms.",
            },
            r"(?i)(api_key|secret|token)\s*=\s*['\"][^'\"]+['\"]": {
                "risk": "Hardcoded Credentials",
                "severity": "HIGH",
                "description": "Hardcoded API keys or tokens detected",
                "recommendation": "Remove hardcoded credentials. Use environment variables or secure configuration mechanisms.",
            },
            # Weak Cryptographic Hashes
            r"hashlib\.(md5|sha1)\(": {
                "risk": "Weak Cryptographic Hash",
                "severity": "MEDIUM",
                "description": "Use of weak cryptographic hash functions (MD5, SHA1)",
                "recommendation": "Use stronger hash functions like SHA-256 or SHA-3.",
            },
            # Temporary File Operations
            r"tempfile\.": {
                "risk": "Insecure Temporary File",
                "severity": "MEDIUM",
                "description": "Insecure temporary file creation can lead to race conditions or information disclosure.",
                "recommendation": "Use `tempfile.mkstemp` or `tempfile.TemporaryDirectory` for secure temporary file/directory creation.",
            },
            # XML Parsing
            r"xml\..*\.parse": {
                "risk": "XML External Entity (XXE) Injection",
                "severity": "HIGH",
                "description": "Parsing XML with external entities enabled can lead to XXE attacks.",
                "recommendation": "Disable external entity processing when parsing XML. Use libraries like `defusedxml`.",
            },
            r"xml\.etree\.ElementTree": {
                "risk": "XML External Entity (XXE) Injection",
                "severity": "HIGH",
                "description": "Parsing XML with external entities enabled can lead to XXE attacks.",
                "recommendation": "Disable external entity processing when parsing XML. Use libraries like `defusedxml`.",
            },
            # Unsafe yaml loading
            r"yaml\.load(\(|\s)": {
                "risk": "Unsafe YAML Loading",
                "severity": "HIGH",
                "description": "Unsafe yaml.load() used instead of yaml.safe_load()",
                "recommendation": "Use `yaml.safe_load()` to prevent arbitrary code execution during YAML deserialization.",
            },
            # Hardcoded debug flag
            r"(?i)debug\s*=\s*True": {
                "risk": "Debug Mode Enabled",
                "severity": "LOW",
                "description": "Debug mode is enabled, potentially exposing sensitive information.",
                "recommendation": "Disable debug mode in production environments.",
            },
        }

    def scan_file(self, file_path: Path) -> List[SecurityFinding]:
        """Scan a Python file for security vulnerabilities."""
        findings = []

        try:
            with open(file_path, "r", encoding="utf-8") as file:
                content = file.read()
                lines = content.split("\n")

                # Perform pattern matching
                findings.extend(self._check_patterns(lines))

                # Perform AST-based analysis
                findings.extend(self._check_ast_patterns(content, lines))

                # Additional semantic analysis
                findings.extend(self._check_semantic_patterns(content))

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error scanning {file_path}: {str(e)}")

        return findings

    def _check_patterns(self, lines: List[str]) -> List[SecurityFinding]:
        """Check for regex pattern matches."""
        findings = []
        for i, line in enumerate(lines, 1):
            for pattern, details in self.patterns.items():
                if re.search(pattern, line):
                    findings.append(
                        SecurityFinding(
                            pattern=pattern,
                            risk=details["risk"],
                            severity=details["severity"],
                            line_number=i,
                            context=line.strip(),
                            recommendation=details.get("recommendation"),
                        )
                    )
        return findings

    def _check_ast_patterns(
        self, content: str, lines: List[str]
    ) -> List[SecurityFinding]:
        # Uses Python's AST to detect more complex patterns that are not easily caught by regex alone.
        # This includes checks for potential SQL injection, unsafe YAML loading calls, insecure deserialization (pickle),
        # and path traversal scenarios.
        """
        Perform Abstract Syntax Tree based security checks.

        Args:
            content: Raw source code as string
            lines: List of lines in the file

        Returns:
            List of SecurityFinding objects from AST analysis
        """
        findings = []
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                # SQL Injection
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                    # Check for string formatting with %
                    if isinstance(node.left, ast.Str) and "%s" in node.left.s:
                        findings.append(
                            SecurityFinding(
                                risk="Potential SQL Injection",
                                severity="HIGH",
                                line_number=node.lineno,
                                context=lines[node.lineno - 1].strip(),
                                recommendation="Use parameterized queries or an ORM to prevent SQL injection.",
                            )
                        )
                if isinstance(node, ast.Call):
                    # Unsafe YAML Loading
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "load"
                        and hasattr(node.func.value, "id")
                        and node.func.value.id == "yaml"
                    ):
                        findings.append(
                            SecurityFinding(
                                risk="Unsafe YAML Loading",
                                severity="HIGH",
                                line_number=node.lineno,
                                context=lines[node.lineno - 1].strip(),
                                recommendation="Use `yaml.safe_load()` to prevent arbitrary code execution during YAML deserialization.",
                            )
                        )

                    # Insecure Deserialization (pickle.loads)
                    if (
                        isinstance(node.func, ast.Attribute)
                        and node.func.attr == "loads"
                        and hasattr(node.func.value, "id")
                        and node.func.value.id == "pickle"
                    ):
                        findings.append(
                            SecurityFinding(
                                risk="Insecure Deserialization",
                                severity="HIGH",
                                line_number=node.lineno,
                                context=lines[node.lineno - 1].strip(),
                                recommendation="Avoid using `pickle` for deserialization of untrusted data. Consider safer alternatives like JSON.",
                            )
                        )

                    # Path Traversal
                    if isinstance(node.func, ast.Name) and node.func.id == "open":
                        if any(
                            isinstance(arg, ast.BinOp)
                            and isinstance(arg.op, ast.Add)
                            and (
                                isinstance(arg.left, ast.Str)
                                or isinstance(arg.right, ast.Str)
                            )
                            for arg in node.args
                        ):
                            findings.append(
                                SecurityFinding(
                                    risk="Potential Path Traversal",
                                    severity="MEDIUM",
                                    line_number=node.lineno,
                                    context=lines[node.lineno - 1].strip(),
                                    recommendation="Validate and sanitize user-supplied file paths to prevent path traversal.",
                                )
                            )

        except Exception as e:
            print(f"Error in AST analysis: {e}")

        return findings

    def _check_semantic_patterns(self, content: str) -> List[SecurityFinding]:
        """Perform semantic analysis for complex patterns."""
        findings = []
        tree = ast.parse(content)

        # Check for dangerous import combinations
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    imports.add(name.name)
            elif isinstance(node, ast.ImportFrom):
                imports.add(f"{node.module}.{node.names[0].name}")

        # Check dangerous combinations
        dangerous_combos = [
            ({"os", "subprocess"}, "Command Injection Risk", "HIGH"),
            ({"pickle", "requests"}, "Remote Code Execution Risk", "CRITICAL"),
        ]

        for modules, risk, severity in dangerous_combos:
            if modules.issubset(imports):
                findings.append(
                    SecurityFinding(
                        risk=risk,
                        severity=severity,
                        line_number=1,  # Use first line as this is a module-level finding
                        context=f"Dangerous module combination: {', '.join(modules)}",
                        recommendation=f"Avoid combining {', '.join(modules)} due to potential security risks.",
                    )
                )

        return findings


def scan_directory(directory: Path) -> Dict[str, List[SecurityFinding]]:
    """
    Recursively scan a directory for Python files.

    Args:
        directory: Path object of directory to scan

    Returns:
        Dict mapping file paths to lists of security findings
    """
    scanner = SecurityScanner()
    results = {}

    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                file_path = Path(root) / file
                findings = scanner.scan_file(file_path)
                if findings:
                    results[str(file_path)] = findings

    return results


def scan_single_file(file_path: str, output_dir: str = "reports") -> Tuple[str, str]:
    """
    Scan a single Python file and generate both Markdown and JSON reports.

    Args:
        file_path: Path to the Python file to scan
        output_dir: Directory to save reports (default: 'reports')

    Returns:
        Tuple of (markdown_path, json_path) for the generated reports
    """
    # Initialize scanner
    scanner = SecurityScanner()
    file_path = Path(file_path)

    # Ensure file exists and is Python file
    if not file_path.exists() or file_path.suffix != ".py":
        raise ValueError("Invalid Python file path")

    # Scan file
    findings = scanner.scan_file(file_path)

    # Create output directory
    output_dir = Path(output_dir)
    output_dir.mkdir(exist_ok=True)

    # Generate timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"security_scan_{file_path.stem}_{timestamp}"

    # Generate JSON report
    json_path = output_dir / f"{base_name}.json"
    json_report = {
        "scan_time": datetime.now().isoformat(),
        "file_scanned": str(file_path),
        "findings": [
            {
                "risk": f.risk,
                "severity": f.severity,
                "line_number": f.line_number,
                "context": f.context,
                "recommendation": f.recommendation,
            }
            for f in findings
        ],
    }

    with open(json_path, "w") as f:
        json.dump(json_report, f, indent=2)

    # Generate Markdown report
    md_path = output_dir / f"{base_name}.md"

    # Group findings by severity
    severity_groups: Dict[str, List[SecurityFinding]] = {
        "CRITICAL": [],
        "HIGH": [],
        "MEDIUM": [],
        "LOW": [],
    }

    for finding in findings:
        severity_groups[finding.severity].append(finding)

    with open(md_path, "w") as f:
        f.write(f"# Security Scan Report\n\n")
        f.write(f"**File Scanned**: `{file_path}`  \n")
        f.write(f"**Scan Time**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write(f"## Summary\n\n")
        f.write("| Severity | Count |\n")
        f.write("|----------|-------|\n")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = len(severity_groups[severity])
            f.write(f"| {severity} | {count} |\n")

        f.write("\n## Detailed Findings\n\n")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            findings = severity_groups[severity]
            if findings:
                f.write(f"\n### {severity} Severity\n\n")
                for finding in findings:
                    f.write(f"#### Line {finding.line_number}: {finding.risk}\n\n")
                    f.write(f"```python\n{finding.context}\n```\n\n")
                    f.write(f"**Recommendation**: {finding.recommendation}\n\n")
                    f.write("---\n")

    return md_path, json_path


@click.group()
def cli():
    """Security scanner for Python code."""
    pass


@cli.command()
@click.argument("file_path")
@click.option(
    "--output-dir", "-o", default="reports", help="Output directory for reports"
)
def scan_file(file_path, output_dir):
    """Scan a single Python file for security issues."""
    try:
        md_path, json_path = scan_single_file(file_path, output_dir)
        click.echo(f"Reports generated:")
        click.echo(f"Markdown: {md_path}")
        click.echo(f"JSON: {json_path}")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command()
@click.argument("directory", type=click.Path(exists=True))
def scan_dir(directory):
    """Scan a directory recursively for Python files."""
    try:
        results = scan_directory(Path(directory))
        if not results:
            click.echo("No security issues found.")
            return

        for file_path, findings in results.items():
            click.echo(f"\nFindings for {file_path}:")
            for finding in findings:
                click.echo(str(finding))
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


def main():
    """Entry point for CLI."""
    cli()


if __name__ == "__main__":
    main()
