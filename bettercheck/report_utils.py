import os
from pathlib import Path
from datetime import datetime
from bettercheck.security import validate_safe_path


def get_report_path(package_name: str, timestamp: str, format: str) -> Path:
    """Get a safe path for report files"""
    report_dir = Path(__file__).parent.parent / "reports"
    report_dir.mkdir(exist_ok=True)

    filename = f"package_report_{package_name}_{timestamp}.{format}"
    return validate_safe_path(report_dir / filename, str(report_dir))


def get_log_path(package_name: str, timestamp: str) -> Path:
    """Get a safe path for log files"""
    log_dir = Path(__file__).parent.parent / "logs"
    log_dir.mkdir(exist_ok=True)

    filename = f"package_check_{package_name}_{timestamp}.log"
    return validate_safe_path(log_dir / filename, str(log_dir))
