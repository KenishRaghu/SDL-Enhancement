"""
Threat Modeling Framework - STRIDE Methodology

Provides structured approach to threat identification and risk assessment
for applications and systems.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from enum import Enum


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "Information Disclosure"
    DENIAL_OF_SERVICE = "Denial of Service"
    ELEVATION_OF_PRIVILEGE = "Elevation of Privilege"


class ThreatModelingFramework:
    """STRIDE-based threat modeling framework."""

    STRIDE_CHECKLISTS = {
        STRIDECategory.SPOOFING: [
            "Authentication mechanism bypass",
            "Credential theft or replay",
            "Session hijacking",
            "Identity impersonation"
        ],
        STRIDECategory.TAMPERING: [
            "Data modification in transit",
            "Data modification at rest",
            "Configuration tampering",
            "Code or binary modification"
        ],
        STRIDECategory.REPUDIATION: [
            "Lack of audit logging",
            "Log tampering or deletion",
            "Non-repudiation controls missing"
        ],
        STRIDECategory.INFORMATION_DISCLOSURE: [
            "Sensitive data in logs",
            "Inadequate access controls",
            "Information leakage in errors",
            "Insecure data transmission"
        ],
        STRIDECategory.DENIAL_OF_SERVICE: [
            "Resource exhaustion",
            "Lack of rate limiting",
            "Single points of failure",
            "No graceful degradation"
        ],
        STRIDECategory.ELEVATION_OF_PRIVILEGE: [
            "Privilege escalation paths",
            "Insufficient authorization checks",
            "Default credentials",
            "Overly permissive defaults"
        ]
    }

    def __init__(self, component_name: str = "System"):
        self.component_name = component_name
        self.threats: List[Dict[str, Any]] = []
        self.mitigations: Dict[str, List[str]] = {}

    def identify_threats(self, component: str = None, data_flow: str = None) -> List[Dict[str, Any]]:
        """
        Identify threats using STRIDE methodology.
        component: Name of component/data store/process
        data_flow: Description of data flow being analyzed
        """
        target = component or self.component_name
        self.threats = []

        for category, threats in self.STRIDE_CHECKLISTS.items():
            for threat_desc in threats:
                self.threats.append({
                    "id": f"T-{len(self.threats) + 1:04d}",
                    "category": category.value,
                    "description": threat_desc,
                    "component": target,
                    "data_flow": data_flow or "N/A",
                    "risk_level": self._assess_risk(threat_desc),
                    "status": "Open"
                })

        return self.threats

    def _assess_risk(self, threat: str) -> str:
        """Assign initial risk level based on threat type."""
        high_risk = ["Credential theft", "Privilege escalation", "Data modification at rest"]
        return "High" if any(h in threat for h in high_risk) else "Medium"

    def add_mitigation(self, threat_id: str, mitigation: str) -> None:
        """Add mitigation for identified threat."""
        if threat_id not in self.mitigations:
            self.mitigations[threat_id] = []
        self.mitigations[threat_id].append(mitigation)

    def generate_threat_model(self, output_path: str = "threat_model.json") -> str:
        """Generate complete threat model document."""
        if not self.threats:
            self.identify_threats()

        model = {
            "component": self.component_name,
            "timestamp": datetime.utcnow().isoformat(),
            "methodology": "STRIDE",
            "total_threats": len(self.threats),
            "threats": self.threats,
            "mitigations": self.mitigations,
            "summary": {
                "by_category": self._summary_by_category(),
                "by_risk": self._summary_by_risk()
            }
        }

        Path(output_path).write_text(json.dumps(model, indent=2))
        return output_path

    def _summary_by_category(self) -> Dict[str, int]:
        counts = {}
        for t in self.threats:
            cat = t["category"]
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _summary_by_risk(self) -> Dict[str, int]:
        counts = {}
        for t in self.threats:
            risk = t["risk_level"]
            counts[risk] = counts.get(risk, 0) + 1
        return counts


def create_threat_model(component: str, output_dir: str = ".") -> str:
    """Convenience function to create threat model for a component."""
    framework = ThreatModelingFramework(component)
    framework.identify_threats()
    output_path = Path(output_dir) / f"threat_model_{component.lower().replace(' ', '_')}.json"
    return framework.generate_threat_model(str(output_path))


if __name__ == "__main__":
    framework = ThreatModelingFramework("Web Application")
    framework.identify_threats()
    path = framework.generate_threat_model()
    print(f"Threat model generated: {path}")
    print(f"Total threats identified: {len(framework.threats)}")
