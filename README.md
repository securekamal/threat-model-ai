# 🎯 ThreatModelAI

> LLM-powered automated threat modeling — generates STRIDE analysis, attack trees, data flow diagrams, and MITRE ATT&CK mappings from architecture descriptions or code.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue)](https://python.org)
[![STRIDE](https://img.shields.io/badge/methodology-STRIDE-orange)](https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org)

## What It Does

Traditional threat modeling is time-consuming and inconsistent. ThreatModelAI:

1. **Accepts input** — architecture diagrams (text/JSON), infrastructure-as-code, or natural language descriptions
2. **Generates STRIDE** — automatically enumerates Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation of Privilege per component
3. **Maps to MITRE ATT&CK** — links each threat to relevant TTP IDs
4. **Builds attack trees** — hierarchical visualization of attack paths
5. **Outputs mitigations** — actionable controls with NIST 800-53 references
6. **CI/CD ready** — run in PR pipelines to threat-model every architecture change

## Quickstart

```bash
pip install -r requirements.txt
export OPENAI_API_KEY=sk-...   # or use --local for Ollama

# Threat model from architecture description
python threat_model_ai.py --input arch.json --format stride

# From Terraform/IaC
python threat_model_ai.py --input infra/main.tf --format attack-tree

# Full report with MITRE mapping
python threat_model_ai.py --input system.md --format full --out report.html

# Interactive session
python threat_model_ai.py --interactive
```

## Input Formats

```json
{
  "system": "E-commerce checkout service",
  "components": [
    {"name": "API Gateway", "type": "ingress", "auth": "JWT"},
    {"name": "Order Service", "type": "microservice", "db": "PostgreSQL"},
    {"name": "Payment Service", "type": "microservice", "external": "Stripe API"},
    {"name": "S3 Bucket", "type": "storage", "public": false}
  ],
  "data_flows": [
    {"from": "Browser", "to": "API Gateway", "protocol": "HTTPS", "data": "PII+PCI"},
    {"from": "Order Service", "to": "Payment Service", "protocol": "gRPC", "data": "PCI"}
  ]
}
```

## Sample Output

```
STRIDE ANALYSIS — Order Service
══════════════════════════════════════════════════════════
[S] SPOOFING       | Forged JWT tokens → bypass auth
                   | Mitigate: RS256 validation, token binding
                   | MITRE: T1078 Valid Accounts
                   | NIST: IA-2, IA-8

[T] TAMPERING      | SQL injection via order_id param
                   | Mitigate: Parameterized queries, WAF
                   | MITRE: T1190 Exploit Public-Facing App
                   | NIST: SI-10

[I] INFO DISC.     | Stack traces in 500 errors expose internals
                   | Mitigate: Generic error handling, log scrubbing
                   | MITRE: T1082 System Information Discovery
                   | NIST: SI-11

[E] ELEVATION      | IDOR in /orders/{id} — horizontal privesc
                   | Mitigate: Object-level authorization checks
                   | MITRE: T1548
                   | NIST: AC-3
```

## CI/CD Integration

```yaml
# .github/workflows/threat-model.yml
- name: Threat Model Check
  run: |
    python threat_model_ai.py \
      --input architecture/system.json \
      --fail-on HIGH \
      --format sarif \
      --out threat-model.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: threat-model.sarif
```

## Architecture

```
threat_model_ai/
├── parsers/          # IaC, JSON, text parsers
├── analyzers/        # STRIDE, PASTA, LINDDUN engines
├── llm/              # OpenAI / Ollama integration
├── mappings/         # MITRE ATT&CK, NIST 800-53, CWE
├── renderers/        # HTML, SARIF, Markdown, JSON output
└── cli.py            # Entry point
```
