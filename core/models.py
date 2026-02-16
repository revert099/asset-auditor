# core/models.py
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Literal, Any

Status = Literal["PASS", "WARN", "FAIL", "INFO", "NOT_CHECKED"]
Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]

@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    remediation: str

@dataclass
class AuditResult:
    id: str
    name: str
    weight: int
    status: Status
    score_factor: float
    evidence: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

@dataclass
class AuditReport:
    meta: dict[str, Any]
    host: dict[str, Any]
    checks: list[AuditResult]
    score: int