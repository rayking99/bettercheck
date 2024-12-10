import os
from datetime import datetime
from pathlib import Path

from bettercheck.security import validate_safe_path


def get_report_path(package_name: str, timestamp: str, format: str) -> Path:
    """Get a safe path for report files"""
    # Use project root instead of package directory
    project_root = Path(__file__).parent.parent.parent
    report_dir = project_root / "reports"
    report_dir.mkdir(exist_ok=True)

    filename = f"package_report_{package_name}_{timestamp}.{format}"
    return validate_safe_path(report_dir / filename, str(report_dir))


def get_log_path(package_name: str, timestamp: str) -> Path:
    """Get a safe path for log files"""
    # Use project root instead of package directory
    project_root = Path(__file__).parent.parent.parent
    log_dir = project_root / "logs"
    log_dir.mkdir(exist_ok=True)

    filename = f"package_check_{package_name}_{timestamp}.log"
    return validate_safe_path(log_dir / filename, str(log_dir))
