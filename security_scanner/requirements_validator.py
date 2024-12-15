"""
Automated Security Requirements Validation Scanner

Scans codebases and configurations against SDL security requirements.
Identifies gaps in security controls and produces validation reports.
"""

import os
import re
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


class SecurityRequirementsValidator:
    """Validates projects against defined security requirements."""

    def __init__(self, target_path: str = "."):
        self.target_path = Path(target_path)
        self.findings: List[Dict[str, Any]] = []
        self.requirements_config = self._load_requirements()

    def _load_requirements(self) -> Dict[str, Any]:
        """Load security requirements configuration."""
        return {
            "secrets_detection": {
                "enabled": True,
                "patterns": [
                    (r'(?i)(api_key|apikey)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded API key"),
                    (r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded password"),
                    (r'(?i)(secret|token)\s*[=:]\s*["\'][^"\']+["\']', "Hardcoded secret"),
                    (r'[A-Za-z0-9+/]{40,}={0,2}', "Potential base64 encoded secret"),
                ]
            },
            "insecure_config": {
                "enabled": True,
                "patterns": [
                    (r'debug\s*=\s*true', "Debug mode enabled in production"),
                    (r'DEBUG\s*=\s*True', "Debug mode enabled"),
                    (r'ssl\s*=\s*false', "SSL/TLS disabled"),
                    (r'verify_ssl\s*=\s*false', "SSL verification disabled"),
                ]
            },
            "dependency_checks": {
                "enabled": True,
                "extensions": [".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env"]
            }
        }

    def scan_for_secrets(self) -> None:
        """Scan for hardcoded secrets and credentials."""
        if not self.requirements_config["secrets_detection"]["enabled"]:
            return

        for file_path in self._get_scannable_files():
            try:
                content = file_path.read_text(errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern, finding_type in self.requirements_config["secrets_detection"]["patterns"]:
                        if re.search(pattern, line) and not line.strip().startswith("#"):
                            self.findings.append({
                                "type": finding_type,
                                "severity": "high",
                                "file": str(file_path.relative_to(self.target_path)),
                                "line": line_num,
                                "requirement": "CRED-001: No hardcoded secrets"
                            })
                            break
            except Exception:
                pass

    def scan_for_insecure_config(self) -> None:
        """Scan for insecure configuration patterns."""
        if not self.requirements_config["insecure_config"]["enabled"]:
            return

        for file_path in self._get_scannable_files():
            try:
                content = file_path.read_text(errors="ignore")
                for line_num, line in enumerate(content.splitlines(), 1):
                    for pattern, finding_type in self.requirements_config["insecure_config"]["patterns"]:
                        if re.search(pattern, line, re.IGNORECASE):
                            self.findings.append({
                                "type": finding_type,
                                "severity": "medium",
                                "file": str(file_path.relative_to(self.target_path)),
                                "line": line_num,
                                "requirement": "CONFIG-001: Secure default configuration"
                            })
                            break
            except Exception:
                pass

    def _get_scannable_files(self) -> List[Path]:
        """Get list of files to scan based on configuration."""
        extensions = self.requirements_config["dependency_checks"]["extensions"]
        files = []
        for ext in extensions:
            files.extend(self.target_path.rglob(f"*{ext}"))

        exclude = {".git", "node_modules", "__pycache__", ".venv", "venv"}
        return [f for f in files if not any(ex in f.parts for ex in exclude)]

    def validate_requirements(self) -> Dict[str, Any]:
        """Run full security requirements validation."""
        self.findings = []
        self.scan_for_secrets()
        self.scan_for_insecure_config()

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "target": str(self.target_path),
            "total_findings": len(self.findings),
            "by_severity": self._count_by_severity(),
            "requirements_validated": True,
            "findings": self.findings,
            "status": "PASS" if not self.findings else "REVIEW_REQUIRED"
        }

    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"high": 0, "medium": 0, "low": 0}
        for f in self.findings:
            counts[f.get("severity", "low")] = counts.get(f.get("severity", "low"), 0) + 1
        return counts

    def generate_report(self, output_path: str = "security_validation_report.json") -> str:
        """Generate and save validation report."""
        results = self.validate_requirements()
        report_path = self.target_path / output_path
        report_path.write_text(json.dumps(results, indent=2))
        return str(report_path)


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Security Requirements Validator")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan")
    parser.add_argument("-o", "--output", default="security_validation_report.json", help="Output report path")
    args = parser.parse_args()

    validator = SecurityRequirementsValidator(args.path)
    report_path = validator.generate_report(args.output)
    print(f"Validation complete. Report saved to: {report_path}")
    print(f"Total findings: {validator.validate_requirements()['total_findings']}")


if __name__ == "__main__":
    main()
