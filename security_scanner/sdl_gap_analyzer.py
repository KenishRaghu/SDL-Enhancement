"""
SDL Process Gap Analyzer

Analyzes SDL processes against industry standards and identifies gaps
in security requirements implementation.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any


class SDLGapAnalyzer:
    """Identifies gaps in Security Development Lifecycle implementation."""

    SDL_REQUIREMENTS = {
        "training": {
            "id": "SDL-001",
            "name": "Security Training",
            "controls": [
                "Developer security awareness training completed",
                "Secure coding practices documented",
                "Annual training refresh"
            ]
        },
        "requirements": {
            "id": "SDL-002",
            "name": "Security Requirements",
            "controls": [
                "Security requirements defined in design phase",
                "Privacy requirements documented",
                "Compliance requirements mapped"
            ]
        },
        "design": {
            "id": "SDL-003",
            "name": "Secure Design",
            "controls": [
                "Threat model completed",
                "Security architecture reviewed",
                "Attack surface minimized"
            ]
        },
        "implementation": {
            "id": "SDL-004",
            "name": "Secure Implementation",
            "controls": [
                "Static analysis integrated",
                "No known vulnerable dependencies",
                "Secrets managed securely"
            ]
        },
        "verification": {
            "id": "SDL-005",
            "name": "Security Verification",
            "controls": [
                "Dynamic testing performed",
                "Penetration testing for critical components",
                "Security sign-off documented"
            ]
        },
        "release": {
            "id": "SDL-006",
            "name": "Secure Release",
            "controls": [
                "Incident response plan in place",
                "Security update process defined",
                "Vulnerability disclosure process"
            ]
        }
    }

    def __init__(self):
        self.gaps: List[Dict[str, Any]] = []

    def analyze(self, current_state: Dict[str, List[str]] = None) -> Dict[str, Any]:
        """
        Analyze SDL implementation against requirements.
        current_state: Dict mapping phase to list of implemented controls
        """
        if current_state is None:
            current_state = {}

        self.gaps = []
        for phase, spec in self.SDL_REQUIREMENTS.items():
            implemented = set(current_state.get(phase, []))
            required = set(spec["controls"])

            for control in required:
                if control not in implemented:
                    self.gaps.append({
                        "phase": phase,
                        "requirement_id": spec["id"],
                        "phase_name": spec["name"],
                        "gap": control,
                        "priority": self._get_priority(phase)
                    })

        return {
            "timestamp": datetime.utcnow().isoformat(),
            "total_requirements": sum(len(s["controls"]) for s in self.SDL_REQUIREMENTS.values()),
            "identified_gaps": len(self.gaps),
            "gaps": self.gaps,
            "phases_analyzed": list(self.SDL_REQUIREMENTS.keys())
        }

    def _get_priority(self, phase: str) -> str:
        """Assign priority based on SDL phase."""
        priority_order = {"design": "high", "implementation": "high", "verification": "high",
                         "requirements": "medium", "release": "medium", "training": "medium"}
        return priority_order.get(phase, "low")

    def generate_report(self, output_path: str = "sdl_gap_analysis.json") -> str:
        """Generate gap analysis report."""
        results = self.analyze()
        Path(output_path).write_text(json.dumps(results, indent=2))
        return output_path


if __name__ == "__main__":
    analyzer = SDLGapAnalyzer()
    report_path = analyzer.generate_report()
    print(f"SDL Gap Analysis complete. Report: {report_path}")
    print(f"Identified gaps: {len(analyzer.gaps)}")
