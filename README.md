# vardrscanner-docs
Architecture and design documentation for VardrScanner, an OWASP API Top 3–focused security testing framework. Implementation is private.
# VardrScanner - API Security Testing Framework

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-OWASP%20API%20Security-green.svg)](https://owasp.org/API-Security/)
[![Version](https://img.shields.io/badge/Version-2.1.0--enhanced-purple.svg)](README.md)

> **⚠️ Availability Notice**  
> The full implementation of VardrScanner is intentionally private. This repository documents architecture, workflow, and sample output only. Operational details, payload logic, and execution instructions are withheld for safety and responsible disclosure reasons.

---

## What This Is

VardrScanner is a modular API security testing framework built for professional penetration testing. It implements the **OWASP API Security Top 3** using a plugin-based architecture that prioritizes clean abstractions, evidence quality, and ethical testing practices.

This is **architecture documentation**, not a runnable tool. It exists to demonstrate:
- Framework design and system architecture skills
- Security domain knowledge (OWASP alignment, vulnerability patterns)
- Professional engineering practices (modularity, clean code, testing)
- Ethical considerations in security tooling

**Target Audience:** Hiring managers, security professionals, and technical reviewers evaluating architecture and design capabilities.

---

## Architecture Overview

### High-Level Design

```
┌──────────────────────────────────────────────┐
│              VardrScanner                     │
├──────────────────────────────────────────────┤
│                                              │
│  ┌────────────────────────────────────┐    │
│  │   Core Engine (Transport Layer)    │    │
│  │   • HTTP session management        │    │
│  │   • Authentication handlers        │    │
│  │   • Rate limiting & retry logic    │    │
│  └────────────┬───────────────────────┘    │
│               │                              │
│               ▼                              │
│  ┌────────────────────────────────────┐    │
│  │   ScanContext (Abstraction)        │    │
│  │   • Isolates modules from engine   │    │
│  │   • Clean interface: request(),    │    │
│  │     add_finding(), logger          │    │
│  └────────────┬───────────────────────┘    │
│               │                              │
│               ▼                              │
│  ┌────────────────────────────────────┐    │
│  │   Security Modules (Plugins)       │    │
│  │   • API1: BOLA/IDOR                │    │
│  │   • API2: Broken Authentication    │    │
│  │   • API3: Property-Level Authz     │    │
│  └────────────┬───────────────────────┘    │
│               │                              │
│               ▼                              │
│  ┌────────────────────────────────────┐    │
│  │   Reporting Engine                 │    │
│  │   • Text, JSON, HTML outputs       │    │
│  │   • Evidence collection            │    │
│  └────────────────────────────────────┘    │
│                                              │
└──────────────────────────────────────────────┘
```

**Key Design Decisions:**

1. **Modular Plugins** - Each OWASP category is an independent module that implements a standard interface
2. **ScanContext Abstraction** - Modules never access engine internals directly (thread-safe, testable)
3. **Evidence-First** - Every finding includes full request/response evidence and confidence scoring
4. **Defensive Testing** - JWT hygiene checks without exploit techniques (legally defensible)

---

## Core Components

### 1. Parameter Discovery Engine (v2.1.0 Enhancement)

**Problem:** Most scanners hardcode parameter patterns, missing 80% of real-world APIs.

**Solution:** Dynamic discovery from multiple sources.

```python
# Discovers from:
├── JSON responses (nested fields: user.profile.id)
├── URL paths (numeric, UUID, hash patterns)
├── OpenAPI specs (if available)
└── Query parameters and body fields

# Categorizes by:
├── ID patterns (numeric, UUID, hash, opaque)
├── Sensitivity (critical, elevated, PII, internal)
└── Context (public, admin, standard endpoints)
```

This single enhancement transforms coverage from "toy demo" to "production scanner."

### 2. Security Module Interface

```python
class SecurityModule:
    name: str           # "API1: BOLA"
    owasp_id: str       # "API1:2023"
    phase: int          # Execution order
    
    def run(self, ctx: ScanContext):
        """Access engine ONLY through context"""
        response = ctx.request('GET', endpoint)
        ctx.add_finding(category, severity, title, details, evidence)
```

**Benefits:**
- Clean separation: modules are isolated from engine implementation
- Easy testing: mock ScanContext for unit tests
- Thread-safe: no shared mutable state
- Extensible: add API4-API10 as new plugins

### 3. Evidence Collection

Every finding includes structured evidence:

```yaml
Finding:
  owasp_id: API1:2023
  severity: Critical
  confidence: High
  
  Evidence:
    baseline_request: { method, url, status, hash }
    test_request: { method, url, status, hash }
    analysis:
      similarity_ratio: 0.87
      pii_differences: [email, username]
      detection_method: "Differential analysis"
    
  Recommendation: "Implement object-level authorization checks..."
```

This mirrors how professional penetration testing reports are structured.

---

## OWASP API Security Top 3

### API1:2023 - Broken Object Level Authorization

**Traditional Approach:**
- Hardcode patterns (user, account, order)
- Try sequential IDs (1, 2, 3...)
- Flag if responses differ

**VardrScanner Approach:**
- **Discover** all ID locations dynamically
- **Infer** access control via differential analysis
- **Score** confidence (High/Medium/Low) based on evidence strength

**Detection Logic:**

| Evidence | Confidence | Example |
|----------|-----------|---------|
| Different PII returned | High | email: alice@ vs bob@ |
| Authorization bypass | Critical | 401 → 200 with different ID |
| Similar structure, different content | Medium | 75% similarity, different values |

### API2:2023 - Broken Authentication

**Core Tests:**
- No authentication bypass
- Invalid token validation
- **JWT Hygiene** (defensive only):
  - ✅ Expired token handling
  - ✅ Malformed JWT rejection
  - ✅ Enforcement consistency
  - ❌ No `alg:none`, key confusion, or exploit techniques

**Why Defensive Only?**
- Keeps tool ethical and legally defensible
- Focuses on helping defenders
- Suitable for professional engagements
- Prevents misuse

### API3:2023 - Broken Object Property Level Authorization

**Context-Aware Testing:**

```
Public Endpoints (/public/):
└── ANY sensitive field → Critical

Admin Endpoints (/admin/):
└── Critical fields OK IF admin check present

Standard Endpoints:
├── Critical (password, secret) → Critical
└── Elevated (role, permissions) → High
```

**Safe Mass Assignment:**
- Requires explicit `--sandbox` flag
- Benign test fields only (`_vardr_test: "safe"`)
- Immediate rollback verification
- Conservative by default

---

## Sample Output

### Finding Example (Sanitized)

```
┌───────────────────────────────────────────────┐
│ [CRITICAL] BOLA Vulnerability Detected        │
├───────────────────────────────────────────────┤
│ Endpoint: /api/users/profile                  │
│ OWASP: API1:2023                              │
│ Confidence: High                              │
│                                               │
│ Detection:                                    │
│   Different PII returned for sequential IDs   │
│                                               │
│ Evidence:                                     │
│   Original ID: 123 → alice@example.com        │
│   Test ID: 124 → bob@example.com              │
│   Similarity: 87% (same structure)            │
│                                               │
│ Recommendation:                               │
│   Implement object-level authorization.       │
│   Verify user owns requested resource.        │
└───────────────────────────────────────────────┘
```

### Report Formats

- **Text**: Executive summary with severity breakdown
- **JSON**: Machine-readable for CI/CD integration
- **HTML**: Interactive dashboard with filtering

---

## Technical Highlights

### Version Evolution

```
v1.0.0 (Monolithic) → 2,516 lines
├── All vulnerability tests in one file
├── Hardcoded patterns
└── Direct engine access throughout

v2.0.0 (Framework) → 1,987 lines (-21%)
├── Modular plugin architecture
├── ScanContext abstraction
└── OWASP Top 3 focus

v2.1.0 (Enhanced) → 2,511 lines (+26% for features)
├── Parameter discovery engine
├── Access control inference
├── JWT hygiene testing
└── Context-aware analysis
```

### Code Distribution

```
Core Engine (32%)          ████████████
Parameter Discovery (13%)  █████
OWASP Modules (24%)        ████████
Reporting (16%)            ██████
Framework (10%)            ████
CLI/Utils (5%)             ██
```

---

## Professional Use Cases

**Enterprise Security Assessment:**
- Annual API audits with comprehensive reporting
- Evidence-backed findings for compliance

**CI/CD Integration:**
- Automated security gates in deployment pipelines
- Fail builds on critical findings

**Penetration Testing:**
- Structured methodology aligned with OWASP
- Confidence scoring reduces false positive triage time

**Bug Bounty Research:**
- Identify high-confidence findings for validation
- Focus manual effort on promising leads

---

## Design Philosophy

### What Makes This Different

**1. Inference Over Enumeration**
- Don't just guess IDs - detect missing authorization checks
- Confidence scoring based on evidence strength
- Works with UUIDs, hashes, and opaque IDs (not just sequential)

**2. Clean Architecture**
- Modules isolated from engine via ScanContext
- Easy to test, extend, and maintain
- No tight coupling or shared mutable state

**3. Evidence Quality**
- Professional-grade reporting with full evidence chains
- Differential analysis with similarity scoring
- Clear reasoning for each finding

**4. Ethical Boundaries**
- JWT hygiene without exploit techniques
- Safe mass assignment with rollback
- Conservative defaults, explicit opt-ins for risky tests

---

## Security & Ethics

### Authorization Requirements

```
✅ REQUIRED:
├── Written authorization from asset owner
├── Clear scope definition
├── Explicit permission for testing methods
└── Emergency contact information

❌ NEVER:
├── Test without legal authorization
├── Exceed agreed scope
├── Ignore rate limits
└── Deploy without owner awareness
```

### Built-in Safeguards

- **Rate Limiting**: Default 1.0s delay between requests
- **Credential Sanitization**: Automatic redaction in logs
- **Read-Only Default**: Write tests require `--sandbox` flag
- **Defensive Testing**: No exploit chains or bypass techniques

---

## Why This Exists

This project demonstrates:

**Technical Skills:**
- Framework design and modular architecture
- Clean code principles and abstractions
- Security domain expertise (OWASP, vulnerability patterns)
- Professional tooling (reporting, evidence, CI/CD)

**Professional Maturity:**
- Ethical considerations in security tools
- Responsible disclosure practices
- Balance between capability and safety
- Documentation quality and presentation

**Engineering Practices:**
- Iterative improvement (v1.0 → v2.1)
- Design decisions with clear trade-offs
- Testability and maintainability
- Extensibility and future-proofing

---

## Further Reading

**[DESIGN.md](DESIGN.md)** - Deep technical dive
- Complete parameter discovery pipeline
- Detailed BOLA inference algorithms
- Full reporting schema specifications
- LOC analysis and component breakdown

**[ENHANCEMENT_IMPLEMENTATION.md](ENHANCEMENT_IMPLEMENTATION.md)** - v2.1.0 details
- Implementation guide for all enhancements
- Before/after comparisons
- Future roadmap

---

## About

**Author:** Vidarr (VardrSec)  
**Version:** 2.1.0-enhanced  
**Purpose:** Portfolio demonstration of security framework design  
**Status:** Private implementation, public architecture documentation

**Contact:** Available for architecture discussions, portfolio reviews, and professional inquiries.

---

## License & Disclaimer

**License:** Proprietary - Private Implementation  
**Documentation:** Public for portfolio/review purposes

**Disclaimer:**
```
This tool is designed for authorized security testing only. Unauthorized 
testing is illegal and unethical. The author assumes no liability for misuse. 
Always obtain written authorization before conducting security assessments.
```

---

<div align="center">

**VardrScanner**

*Architecture without operational details.*  
*Design without exploitation code.*  
*For hiring managers and security professionals.*

[View Architecture Details](DESIGN.md) • [Enhancement Guide](ENHANCEMENT_IMPLEMENTATION.md)

</div>
