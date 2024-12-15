"""
Security Roadmap - Continuous Improvement Framework

Structured roadmap for security posture enhancement with
prioritization and tracking capabilities.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum


class Priority(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Status(str, Enum):
    PLANNED = "Planned"
    IN_PROGRESS = "In Progress"
    COMPLETED = "Completed"
    DEFERRED = "Deferred"


class SecurityRoadmap:
    """Manages security improvement roadmap and continuous enhancement tracking."""

    def __init__(self):
        self.initiatives: List[Dict[str, Any]] = []
        self.milestones: List[Dict[str, Any]] = []

    def add_initiative(
        self,
        name: str,
        description: str,
        priority: str = Priority.HIGH.value,
        target_quarter: str = None,
        dependencies: List[str] = None
    ) -> str:
        """Add security improvement initiative."""
        initiative_id = f"I-{len(self.initiatives) + 1:03d}"
        self.initiatives.append({
            "id": initiative_id,
            "name": name,
            "description": description,
            "priority": priority,
            "status": Status.PLANNED.value,
            "target_quarter": target_quarter,
            "dependencies": dependencies or [],
            "created": datetime.utcnow().isoformat(),
            "completed_date": None
        })
        return initiative_id

    def add_milestone(self, initiative_id: str, milestone: str, due_date: str = None) -> None:
        """Add milestone to initiative."""
        self.milestones.append({
            "initiative_id": initiative_id,
            "milestone": milestone,
            "due_date": due_date,
            "completed": False
        })

    def update_status(self, initiative_id: str, status: str) -> bool:
        """Update initiative status."""
        for i in self.initiatives:
            if i["id"] == initiative_id:
                i["status"] = status
                if status == Status.COMPLETED.value:
                    i["completed_date"] = datetime.utcnow().isoformat()
                return True
        return False

    def get_default_roadmap(self) -> "SecurityRoadmap":
        """Get roadmap with standard SDL improvement initiatives."""
        roadmap = SecurityRoadmap()

        roadmap.add_initiative(
            "Automated Security Scanning",
            "Implement automated scanning for secrets, vulnerable dependencies, and config validation",
            Priority.HIGH.value,
            "Q1"
        )
        roadmap.add_initiative(
            "Threat Modeling Integration",
            "Integrate threat modeling into design phase for all new features",
            Priority.HIGH.value,
            "Q1"
        )
        roadmap.add_initiative(
            "Security Training Program",
            "Establish mandatory security awareness and secure coding training",
            Priority.MEDIUM.value,
            "Q2"
        )
        roadmap.add_initiative(
            "Incident Response Readiness",
            "Document and test incident response procedures",
            Priority.HIGH.value,
            "Q2"
        )
        roadmap.add_initiative(
            "Continuous Compliance Monitoring",
            "Automate compliance checks and reporting",
            Priority.MEDIUM.value,
            "Q3"
        )

        return roadmap

    def export_roadmap(self, output_path: str = "security_roadmap.json") -> str:
        """Export roadmap to JSON."""
        data = {
            "last_updated": datetime.utcnow().isoformat(),
            "initiatives": self.initiatives,
            "milestones": self.milestones,
            "summary": {
                "total_initiatives": len(self.initiatives),
                "by_priority": self._count_by_priority(),
                "by_status": self._count_by_status()
            }
        }
        Path(output_path).write_text(json.dumps(data, indent=2))
        return output_path

    def _count_by_priority(self) -> Dict[str, int]:
        counts = {}
        for i in self.initiatives:
            p = i["priority"]
            counts[p] = counts.get(p, 0) + 1
        return counts

    def _count_by_status(self) -> Dict[str, int]:
        counts = {}
        for i in self.initiatives:
            s = i["status"]
            counts[s] = counts.get(s, 0) + 1
        return counts


if __name__ == "__main__":
    roadmap = SecurityRoadmap().get_default_roadmap()
    path = roadmap.export_roadmap()
    print(f"Security roadmap exported: {path}")
    print(f"Initiatives: {len(roadmap.initiatives)}")
