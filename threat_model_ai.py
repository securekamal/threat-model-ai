"""
threat_model_ai.py — LLM-powered STRIDE threat modeling engine
Author: securekamal
"""

import json
import argparse
import logging
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFO_DISCLOSURE = "Information Disclosure"
    DOS = "Denial of Service"
    ELEVATION = "Elevation of Privilege"


SEVERITY_MAP = {
    STRIDECategory.SPOOFING: "HIGH",
    STRIDECategory.TAMPERING: "HIGH",
    STRIDECategory.REPUDIATION: "MEDIUM",
    STRIDECategory.INFO_DISCLOSURE: "HIGH",
    STRIDECategory.DOS: "MEDIUM",
    STRIDECategory.ELEVATION: "CRITICAL",
}

MITRE_MAPPINGS = {
    STRIDECategory.SPOOFING: ["T1078", "T1134", "T1539"],
    STRIDECategory.TAMPERING: ["T1190", "T1565", "T1059"],
    STRIDECategory.REPUDIATION: ["T1070", "T1562"],
    STRIDECategory.INFO_DISCLOSURE: ["T1082", "T1213", "T1530"],
    STRIDECategory.DOS: ["T1499", "T1498"],
    STRIDECategory.ELEVATION: ["T1548", "T1611", "T1068"],
}

NIST_CONTROLS = {
    STRIDECategory.SPOOFING: ["IA-2", "IA-8", "SC-8"],
    STRIDECategory.TAMPERING: ["SI-10", "SI-7", "AC-3"],
    STRIDECategory.REPUDIATION: ["AU-2", "AU-9", "AU-12"],
    STRIDECategory.INFO_DISCLOSURE: ["SC-8", "AC-3", "SI-12"],
    STRIDECategory.DOS: ["SC-5", "SC-7", "CP-10"],
    STRIDECategory.ELEVATION: ["AC-6", "AC-3", "CM-7"],
}

COMPONENT_THREATS = {
    "api_gateway": {
        STRIDECategory.SPOOFING: "Forged or replayed authentication tokens bypass gateway",
        STRIDECategory.TAMPERING: "Request smuggling or parameter pollution alters routing logic",
        STRIDECategory.DOS: "Unauthenticated endpoints exposed to volumetric abuse",
        STRIDECategory.ELEVATION: "Misconfigured rate limits allow backend enumeration",
    },
    "database": {
        STRIDECategory.TAMPERING: "SQL/NoSQL injection via unsanitized user input",
        STRIDECategory.INFO_DISCLOSURE: "Excessive query results expose unintended records",
        STRIDECategory.ELEVATION: "Over-privileged DB user allows schema modification",
        STRIDECategory.DOS: "Unparameterized queries enable resource exhaustion",
    },
    "microservice": {
        STRIDECategory.SPOOFING: "Service-to-service calls lack mTLS — spoofable",
        STRIDECategory.INFO_DISCLOSURE: "Stack traces in error responses leak internals",
        STRIDECategory.ELEVATION: "IDOR in resource endpoints enables horizontal privilege escalation",
        STRIDECategory.REPUDIATION: "Insufficient logging — actions cannot be attributed",
    },
    "storage": {
        STRIDECategory.INFO_DISCLOSURE: "Misconfigured bucket ACL exposes sensitive files",
        STRIDECategory.TAMPERING: "Lack of object integrity checks enables substitution",
        STRIDECategory.ELEVATION: "Overly broad IAM policies allow cross-account access",
    },
    "ingress": {
        STRIDECategory.DOS: "No WAF or rate limiting — DDoS amplification possible",
        STRIDECategory.TAMPERING: "TLS termination without re-encryption to backend",
        STRIDECategory.INFO_DISCLOSURE: "Verbose server headers reveal technology stack",
    },
}

MITIGATIONS = {
    STRIDECategory.SPOOFING: [
        "Enforce RS256 JWT validation with key rotation",
        "Implement token binding (DPoP) for high-value sessions",
        "Use mTLS for service-to-service authentication",
    ],
    STRIDECategory.TAMPERING: [
        "Parameterized queries / ORM for all DB access",
        "Deploy WAF with OWASP Core Rule Set",
        "Input validation on all trust boundaries",
    ],
    STRIDECategory.REPUDIATION: [
        "Centralized immutable audit log (CloudTrail / SIEM)",
        "Cryptographic signing of critical events",
        "Log correlation with request IDs",
    ],
    STRIDECategory.INFO_DISCLOSURE: [
        "Generic error messages; detailed logs server-side only",
        "Encrypt data at rest (AES-256) and in transit (TLS 1.3)",
        "Scope API responses to minimum necessary fields",
    ],
    STRIDECategory.DOS: [
        "Rate limiting + throttling at API gateway",
        "Circuit breakers in microservice mesh",
        "CDN + DDoS scrubbing (Cloudflare / AWS Shield)",
    ],
    STRIDECategory.ELEVATION: [
        "Object-level authorization checks on every request",
        "Principle of least privilege for all IAM roles",
        "Enforce RBAC / ABAC consistently across services",
    ],
}


@dataclass
class Threat:
    component: str
    category: STRIDECategory
    description: str
    severity: str
    mitre_ttps: list[str]
    nist_controls: list[str]
    mitigations: list[str]


@dataclass
class ThreatModel:
    system_name: str
    threats: list[Threat] = field(default_factory=list)

    def summary(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for t in self.threats:
            counts[t.severity] = counts.get(t.severity, 0) + 1
        return counts

    def to_report(self) -> str:
        lines = [
            f"\n{'='*60}",
            f"  STRIDE THREAT MODEL — {self.system_name}",
            f"{'='*60}",
        ]
        summary = self.summary()
        lines.append(f"\nSummary: {summary}")

        for threat in self.threats:
            lines += [
                f"\n[{threat.severity}] {threat.category.value} — {threat.component}",
                f"  Description : {threat.description}",
                f"  MITRE TTPs  : {', '.join(threat.mitre_ttps)}",
                f"  NIST        : {', '.join(threat.nist_controls)}",
                f"  Mitigations :",
            ]
            for m in threat.mitigations:
                lines.append(f"    • {m}")

        return "\n".join(lines)

    def to_sarif(self) -> dict:
        rules = []
        results = []
        for i, t in enumerate(self.threats):
            rule_id = f"STRIDE-{t.category.name}-{i:03d}"
            rules.append({
                "id": rule_id,
                "name": t.category.value,
                "shortDescription": {"text": t.description},
                "properties": {"severity": t.severity, "mitre": t.mitre_ttps},
            })
            results.append({
                "ruleId": rule_id,
                "level": "error" if t.severity in ("CRITICAL", "HIGH") else "warning",
                "message": {"text": t.description},
                "locations": [{"logicalLocations": [{"name": t.component}]}],
            })
        return {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{"tool": {"driver": {"name": "ThreatModelAI", "rules": rules}}, "results": results}],
        }


class ThreatModeler:
    """Core STRIDE threat modeling engine."""

    def analyze(self, architecture: dict) -> ThreatModel:
        model = ThreatModel(system_name=architecture.get("system", "Unknown System"))

        for component in architecture.get("components", []):
            comp_name = component.get("name", "unknown")
            comp_type = component.get("type", "microservice").lower().replace(" ", "_")
            threat_set = COMPONENT_THREATS.get(comp_type, COMPONENT_THREATS["microservice"])

            for category, description in threat_set.items():
                model.threats.append(Threat(
                    component=comp_name,
                    category=category,
                    description=description,
                    severity=SEVERITY_MAP[category],
                    mitre_ttps=MITRE_MAPPINGS[category],
                    nist_controls=NIST_CONTROLS[category],
                    mitigations=MITIGATIONS[category],
                ))

        # Sort by severity
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        model.threats.sort(key=lambda t: sev_order.get(t.severity, 9))
        return model


def main():
    parser = argparse.ArgumentParser(description="ThreatModelAI — Automated STRIDE Analysis")
    parser.add_argument("--input", required=True, help="Architecture JSON file or text description")
    parser.add_argument("--format", choices=["stride", "sarif", "json"], default="stride")
    parser.add_argument("--out", help="Output file path")
    parser.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM"], help="Exit non-zero if findings at this level")
    args = parser.parse_args()

    with open(args.input) as f:
        architecture = json.load(f)

    modeler = ThreatModeler()
    model = modeler.analyze(architecture)

    if args.format == "stride":
        output = model.to_report()
    elif args.format == "sarif":
        output = json.dumps(model.to_sarif(), indent=2)
    else:
        output = json.dumps({"system": model.system_name, "summary": model.summary(),
                             "threats": [t.__dict__ for t in model.threats]}, indent=2, default=str)

    if args.out:
        with open(args.out, "w") as f:
            f.write(output)
        logger.info(f"Report written to {args.out}")
    else:
        print(output)

    if args.fail_on:
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        threshold = sev_order[args.fail_on]
        for t in model.threats:
            if sev_order.get(t.severity, 9) <= threshold:
                logger.error(f"Failing: found {t.severity} threat — {t.description}")
                raise SystemExit(1)


if __name__ == "__main__":
    main()
