# VardrScanner - Technical Design Documentation

> **For technical reviewers who want the full details**

This document contains the complete technical architecture, implementation details, and design decisions for VardrScanner. If you're looking for a quick overview, see [README.md](README.md) instead.

---

## Table of Contents

- [Complete Parameter Discovery Pipeline](#complete-parameter-discovery-pipeline)
- [BOLA Detection Algorithm](#bola-detection-algorithm)
- [Differential Analysis Engine](#differential-analysis-engine)
- [Reporting Schema Specifications](#reporting-schema-specifications)
- [Component Breakdown (LOC Analysis)](#component-breakdown-loc-analysis)
- [CI/CD Integration Examples](#cicd-integration-examples)
- [Performance Characteristics](#performance-characteristics)
- [Development Roadmap](#development-roadmap)

---

## Complete Parameter Discovery Pipeline

### Multi-Source Discovery Strategy

```
Parameter Discovery Pipeline:
┌──────────────────────────────────────────────────────┐
│  Input: API Response + Endpoint + Optional Spec     │
└───────────────────┬──────────────────────────────────┘
                    │
        ┌───────────┴───────────┐
        │                       │
        ▼                       ▼
┌──────────────┐       ┌──────────────┐
│ JSON Response│       │  URL Path    │
│   Analysis   │       │  Extraction  │
└──────┬───────┘       └──────┬───────┘
       │                      │
       ▼                      ▼
┌─────────────────────────────────┐
│   ParameterDiscovery Class      │
├─────────────────────────────────┤
│ • Nested field extraction       │
│ • ID pattern classification     │
│ • Sensitivity categorization    │
│ • Context inference             │
└─────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│          Output                 │
├─────────────────────────────────┤
│ identifiers: [user.profile.id]  │
│ sensitive_fields: {              │
│   critical: [password, secret]  │
│   elevated: [role, permissions] │
│   pii: [email, ssn]             │
│ }                               │
│ patterns: {                     │
│   user_id: 'numeric'            │
│   account_id: 'uuid'            │
│ }                               │
└─────────────────────────────────┘
```

### Implementation Details

**Nested Field Extraction:**
```python
def _extract_fields_recursive(data, path='', result={}, max_depth=5):
    """
    Recursively traverse JSON structure
    
    Examples:
    - {"user": {"id": 123}} → "user.id"
    - {"items": [{"id": 1}]} → "items[].id"
    """
    if max_depth == 0:
        return
    
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            result['all_fields'].append(current_path)
            
            if _is_identifier_field(key):
                result['identifiers'].append(current_path)
            
            _extract_fields_recursive(value, current_path, result, max_depth-1)
    
    elif isinstance(data, list) and len(data) > 0:
        sample = data[0]
        array_path = f"{path}[]" if path else "[]"
        _extract_fields_recursive(sample, array_path, result, max_depth-1)
```

**ID Pattern Classification:**
```python
Pattern Types:
├── numeric: "123", "456" → Sequential testing strategy
├── uuid: "a1b2c3d4-..." → Common UUID probing
├── hash: "a1b2c3d4e5f6..." → Limited brute-force
├── opaque: "xY9zW..." → Inference-based testing
└── base64: "dGVzdA==" → Decode + analyze
```

**Sensitivity Categorization:**
```python
SENSITIVE_PATTERNS = {
    'critical': [
        'password', 'secret', 'token', 'api_key',
        'private_key', 'salt', 'hash', 'credit_card', 
        'ssn', 'cvv', 'pin'
    ],
    'elevated': [
        'role', 'permission', 'privilege', 'is_admin',
        'access_level', 'tier', 'salary', 'balance'
    ],
    'internal': [
        '_internal', 'debug', '_debug', 'test',
        'created_by_id', '__', 'metadata'
    ],
    'pii': [
        'email', 'phone', 'address', 'ssn',
        'date_of_birth', 'drivers_license', 'passport'
    ]
}
```

---

## BOLA Detection Algorithm

### Complete Detection Flow

```
BOLA Detection Algorithm:

1. DISCOVER Phase
   ├── Parse response JSON for ID fields
   ├── Extract IDs from URL path segments
   ├── Classify each ID pattern (numeric/UUID/hash/opaque)
   └── Store baseline response

2. TEST Phase
   For each ID location:
   ├── Generate test values based on pattern
   │   ├── Numeric: [current+1, current-1, 1, 999]
   │   ├── UUID: [common patterns, all-zeros]
   │   ├── Hash: [short variations]
   │   └── Opaque: [admin, test, root]
   │
   ├── Make test request with modified ID
   ├── Capture test response
   └── Store for analysis

3. ANALYZE Phase
   ├── Compare status codes
   │   └── 401/403 → 200 = Authorization bypass (High confidence)
   │
   ├── Compare response hashes
   │   ├── Identical → Possible caching (Medium confidence)
   │   └── Different → Continue analysis
   │
   ├── Extract PII fields
   │   └── email, username, phone, etc.
   │
   ├── Detect PII differences
   │   └── Different values in PII fields = BOLA (High confidence)
   │
   ├── Calculate similarity ratio
   │   ├── 0.95-1.00 → Identical (flag if has PII)
   │   ├── 0.30-0.95 → Similar structure (Medium confidence)
   │   └── 0.00-0.30 → Different (Low confidence or false positive)
   │
   └── Score confidence: High | Medium | Low

4. REPORT Phase
   ├── Generate finding with confidence score
   ├── Include full evidence chain
   ├── Provide differential analysis details
   └── Suggest remediation
```

### Confidence Scoring Logic

```python
def _analyze_bola_indicators(baseline, test, baseline_data, test_data):
    """
    Returns: (confidence_level, reason)
    """
    
    # HIGH CONFIDENCE cases:
    
    # 1. Different PII returned
    if baseline_data and test_data:
        pii_fields = ['email', 'username', 'phone', 'name']
        differing_pii = []
        
        for field in pii_fields:
            if (baseline_data.get(field) != test_data.get(field) and
                baseline_data.get(field) and test_data.get(field)):
                differing_pii.append(field)
        
        if differing_pii:
            return ('high', f'Different PII: {", ".join(differing_pii)}')
    
    # 2. Authorization bypass
    if baseline.status_code in [401, 403] and test.status_code == 200:
        return ('high', 'Authorization bypass detected')
    
    # MEDIUM CONFIDENCE cases:
    
    # 3. Similar structure, different content
    if baseline.status_code == 200 and test.status_code == 200:
        similarity = response_similarity_ratio(baseline.text, test.text)
        
        if 0.3 < similarity < 0.95:
            return ('medium', f'Similar structure, different content ({similarity:.2%})')
        
        # 4. Identical response with PII
        if similarity >= 0.95 and contains_pii(baseline_data):
            return ('medium', 'Same user data for different IDs')
    
    return ('none', 'No BOLA indicators found')
```

### Example Detection Scenario

```
Scenario: User profile endpoint

Request 1 (Baseline):
  GET /api/users/123
  Authorization: Bearer <valid_token>
  
  Response:
    Status: 200 OK
    Body: {
      "id": 123,
      "email": "alice@example.com",
      "username": "alice",
      "role": "user"
    }

Request 2 (Test):
  GET /api/users/124  # Different ID
  Authorization: Bearer <valid_token>
  
  Response:
    Status: 200 OK
    Body: {
      "id": 124,
      "email": "bob@example.com",
      "username": "bob",
      "role": "user"
    }

Analysis:
  ├── Status: Both 200 ✓
  ├── Structure similarity: 98% (same JSON schema)
  ├── PII differences detected:
  │   ├── email: alice@example.com ≠ bob@example.com
  │   └── username: alice ≠ bob
  │
  └── Conclusion: BOLA vulnerability (HIGH confidence)
      Reason: Different PII returned for different IDs
      Impact: Unauthorized access to user profiles
```

---

## Differential Analysis Engine

### Response Comparison Methods

**1. Hash-Based Comparison:**
```python
def calculate_content_hash(text: str) -> str:
    """SHA256 hash for exact match detection"""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

# Use case: Detect identical responses (caching, static errors)
```

**2. Similarity Ratio:**
```python
def response_similarity_ratio(resp1: str, resp2: str) -> float:
    """
    Uses SequenceMatcher for fuzzy comparison
    
    Returns 0.0-1.0:
    - 0.95-1.00: Identical
    - 0.70-0.95: Similar structure
    - 0.30-0.70: Different content, same template
    - 0.00-0.30: Completely different
    """
    return SequenceMatcher(None, resp1, resp2).ratio()
```

**3. Field-Level Comparison:**
```python
def compare_json_fields(baseline: dict, test: dict) -> dict:
    """
    Returns:
    {
        'added': [...],      # Fields in test but not baseline
        'removed': [...],    # Fields in baseline but not test
        'changed': [...]     # Fields with different values
    }
    """
    baseline_keys = set(baseline.keys())
    test_keys = set(test.keys())
    
    return {
        'added': list(test_keys - baseline_keys),
        'removed': list(baseline_keys - test_keys),
        'changed': [
            k for k in baseline_keys & test_keys
            if baseline[k] != test[k]
        ]
    }
```

**4. Content Indicators:**
```python
def contains_data_indicators(response) -> bool:
    """
    Distinguish data responses from error pages
    
    Positive indicators:
    - JSON with data structures
    - Arrays with items
    - User-identifying fields
    
    Negative indicators:
    - Error keywords (error, exception, fail)
    - Empty arrays/objects
    - 4xx/5xx status codes
    """
    if response.status_code >= 400:
        return False
    
    data, _ = safe_json_parse(response)
    if not data:
        return False
    
    # Check for data vs error structure
    if isinstance(data, dict):
        error_keys = ['error', 'message', 'exception']
        if any(key in data for key in error_keys):
            return False
        
        # Has actual data fields
        if len(data) > 2:  # More than just status/message
            return True
    
    elif isinstance(data, list):
        return len(data) > 0
    
    return False
```

---

## Reporting Schema Specifications

### JSON Report Structure

```json
{
  "scan_metadata": {
    "scan_id": "UUID",
    "framework_version": "2.1.0-enhanced",
    "target": "https://api.example.com",
    "start_time": "ISO8601",
    "end_time": "ISO8601",
    "duration_seconds": 123.45,
    "owasp_coverage": ["API1:2023", "API2:2023", "API3:2023"]
  },
  
  "findings": [
    {
      "id": "UUID",
      "timestamp": "ISO8601",
      "owasp_id": "API1:2023",
      "module": "API1: BOLA (Enhanced)",
      "category": "Authorization",
      "severity": "Critical" | "High" | "Medium" | "Low",
      "confidence": "high" | "medium" | "low",
      
      "title": "Brief description",
      "endpoint": "/api/path",
      
      "details": {
        "description": "Full explanation",
        "recommendation": "How to fix",
        "test_methodology": "How it was found"
      },
      
      "evidence": {
        "baseline_request": {
          "method": "GET",
          "url": "...",
          "status": 200,
          "length": 1234,
          "hash": "..."
        },
        "test_request": {
          "method": "GET",
          "url": "...",
          "status": 200,
          "length": 1245,
          "hash": "..."
        },
        "analysis": {
          "similarity_ratio": 0.87,
          "pii_differences": ["email", "username"],
          "detection_reason": "Different PII returned"
        }
      }
    }
  ],
  
  "statistics": {
    "endpoints_discovered": 47,
    "endpoints_tested": 15,
    "requests_sent": 487,
    "findings_by_severity": {
      "Critical": 2,
      "High": 4,
      "Medium": 3,
      "Low": 1
    },
    "findings_by_owasp": {
      "API1:2023": 3,
      "API2:2023": 4,
      "API3:2023": 2
    }
  }
}
```

### HTML Report Features

**Dashboard Components:**
- Executive summary cards (findings count, severity breakdown)
- Sortable findings table (severity, OWASP ID, confidence)
- Filterable by: severity, OWASP category, confidence
- Expandable evidence panels (click to reveal full details)
- OWASP mapping visualization (coverage chart)
- Timeline view (when findings were discovered)

**Interactive Elements:**
- Color-coded severity badges (red/orange/yellow/blue)
- Confidence indicators (High ★★★ / Medium ★★ / Low ★)
- Copy-to-clipboard for evidence blocks
- Export filtered results as JSON

---

## Component Breakdown (LOC Analysis)

### Version Comparison

| Version | Total Lines | Change | Key Features |
|---------|------------|--------|--------------|
| v1.0.0 | 2,516 | Baseline | Monolithic, all tests in one file |
| v2.0.0 | 1,987 | -529 (-21%) | Framework conversion, modular |
| v2.1.0 | 2,511 | +524 (+26%) | Parameter discovery, enhancements |

### Component Distribution (v2.1.0)

```
Core Engine (800 lines - 32%)
├── HTTP Transport (250)
│   ├── Session management
│   ├── Connection pooling
│   └── SSL/TLS config
├── Authentication (150)
│   ├── Bearer token
│   ├── API key
│   ├── Basic auth
│   └── Override mechanism
├── Request Handler (200)
│   ├── Retry logic
│   ├── Rate limiting
│   └── Error handling
└── State Management (200)
    ├── Persistent storage
    ├── Resume capability
    └── Atomic writes

Parameter Discovery (320 lines - 13%)
├── JSON Parser (120)
│   └── Recursive field extraction
├── Pattern Classifier (80)
│   ├── ID type detection
│   └── Sensitivity categorization
├── Context Analyzer (70)
│   └── Endpoint classification
└── OpenAPI Importer (50)
    └── Spec parsing

OWASP Modules (600 lines - 24%)
├── API1_BOLA_Enhanced (280)
│   ├── ID location detection
│   ├── Test value generation
│   ├── Differential analysis
│   └── Confidence scoring
├── API2_BrokenAuth (200)
│   ├── No-auth testing
│   ├── Invalid token testing
│   └── JWT hygiene (defensive)
└── API3_BOPLA (120)
    ├── Sensitivity analysis
    ├── Context-aware rules
    └── Safe mass assignment

Reporting (400 lines - 16%)
├── Text Generator (150)
│   └── Executive summary format
├── JSON Generator (100)
│   └── Structured output
├── HTML Generator (120)
│   └── Interactive dashboard
└── Evidence Formatter (30)
    └── Request/response details

Framework Infrastructure (250 lines - 10%)
├── ScanContext (80)
│   ├── request() interface
│   ├── add_finding() interface
│   └── State accessors
├── SecurityModule (40)
│   └── Base interface
├── Module Registry (60)
│   ├── Dynamic loading
│   └── Phase ordering
└── Orchestration (70)
    └── run_framework()

CLI & Utilities (141 lines - 5%)
├── Argument Parser (60)
├── Banner/Logging (30)
└── Helper Functions (51)
    ├── safe_json_parse()
    ├── calculate_content_hash()
    └── sanitize_sensitive_data()
```

---

## CI/CD Integration Examples

### GitHub Actions

```yaml
name: API Security Scan
on:
  pull_request:
    branches: [main, staging]
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v3
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Run VardrScanner
        run: |
          vardr scan \
            -u ${{ secrets.STAGING_API_URL }} \
            -t bearer \
            -k ${{ secrets.API_TEST_TOKEN }} \
            --openapi-spec ./api/openapi.json \
            --format json \
            --output security-scan.json
      
      - name: Parse Results
        run: |
          CRITICAL=$(jq '.statistics.findings_by_severity.Critical // 0' security-scan.json)
          HIGH=$(jq '.statistics.findings_by_severity.High // 0' security-scan.json)
          
          echo "Critical findings: $CRITICAL"
          echo "High findings: $HIGH"
          
          if [ "$CRITICAL" -gt 0 ]; then
            echo "::error::Critical security findings detected"
            exit 1
          elif [ "$HIGH" -gt 5 ]; then
            echo "::warning::High number of high-severity findings"
          fi
      
      - name: Upload Report
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-report
          path: |
            security-scan.json
            security-scan.html
      
      - name: Comment PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v6
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('security-scan.json'));
            const stats = report.statistics.findings_by_severity;
            
            const comment = `
            ## 🔒 API Security Scan Results
            
            | Severity | Count |
            |----------|-------|
            | 🔴 Critical | ${stats.Critical || 0} |
            | 🟠 High | ${stats.High || 0} |
            | 🟡 Medium | ${stats.Medium || 0} |
            | 🔵 Low | ${stats.Low || 0} |
            
            OWASP Coverage: ${report.scan_metadata.owasp_coverage.join(', ')}
            `;
            
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: comment
            });
```

### GitLab CI

```yaml
stages:
  - security

api-security-scan:
  stage: security
  image: python:3.9
  script:
    - pip install vardrscanner
    - |
      vardr scan \
        -u $STAGING_API_URL \
        -t bearer \
        -k $API_TEST_TOKEN \
        --format json \
        --output security-scan.json
    - |
      CRITICAL=$(jq '.statistics.findings_by_severity.Critical // 0' security-scan.json)
      if [ "$CRITICAL" -gt 0 ]; then
        echo "Critical security findings detected"
        exit 1
      fi
  artifacts:
    when: always
    paths:
      - security-scan.json
      - security-scan.html
    reports:
      junit: security-scan.json
  only:
    - merge_requests
    - schedules
```

---

## Performance Characteristics

### Throughput Metrics

```
Typical Performance (default config):
├── Endpoint Discovery: 50-100 endpoints/min
├── BOLA Testing: 5-10 endpoints/min
│   └── Limited by differential analysis depth
├── Authentication Testing: 10-15 endpoints/min
│   └── Fewer tests per endpoint
└── BOPLA Testing: 15-20 endpoints/min
    └── Single request analysis

Request Rate (configurable):
├── Conservative: 1 req / 2 seconds (0.5 req/s)
├── Default: 1 req / second
├── Aggressive: 10 req / second
└── Custom: --delay <float> seconds
```

### Resource Usage

```
Memory Profile:
├── Baseline: ~50MB (framework + Python runtime)
├── Per Endpoint: ~1KB (endpoint metadata)
├── Per Finding: ~5KB (evidence storage)
└── Large Scan (500 endpoints): ~150MB peak

Example Calculations:
- 50 endpoints, 10 findings: ~70MB
- 200 endpoints, 50 findings: ~120MB
- 500 endpoints, 100 findings: ~180MB

Disk Usage:
├── State Files: < 1MB per scan
├── Text Reports: 10-50KB
├── JSON Reports: 50-200KB (varies with findings)
├── HTML Reports: 100-500KB (includes CSS/JS)
└── Traffic Logs: 1-10MB (if --traffic-log enabled)
```

### Scalability Limits

```
Practical Limits (tested):
├── Max Endpoints: 1,000 (discovery phase)
├── Max Findings: 500 (without performance degradation)
├── Max Concurrent Tests: 1 (sequential by design for safety)
└── Max Report Size: ~5MB JSON (10,000 findings theoretical)

Bottlenecks:
├── Network latency (primary factor)
├── Rate limiting (intentional throttle)
├── Differential analysis (CPU-bound for similarity calculations)
└── JSON parsing (minimal impact with modern Python)
```

---

## Development Roadmap

### Near-Term (v2.2.0 - Next 3 Months)

**Priority Items:**
1. **JWT Hygiene Implementation** (2 weeks)
   - Expired token detection
   - Malformed JWT handling
   - Enforcement consistency checks

2. **API3 Context-Aware Rules** (2 weeks)
   - Public endpoint strict mode
   - Admin endpoint conditional logic
   - Safe mass assignment with rollback

3. **OpenAPI Auto-Import** (1 week)
   - URL-based spec fetching
   - Automatic parameter extraction
   - Schema-based test generation

**Estimated Timeline:** 5-6 weeks development + 2 weeks testing

### Mid-Term (v2.3.0-v2.4.0 - 6-12 Months)

**Feature Additions:**
- Multi-user BOLA testing (requires 2+ test accounts)
- GraphQL endpoint support
- API4-API7 OWASP modules (Security Misconfiguration, BFLA, SSRF, etc.)
- External module loading (plugin marketplace architecture)
- Machine learning for false positive reduction

**Timeline:** Quarterly releases

### Long-Term (v3.0.0+ - 12+ Months)

**Major Enhancements:**
- Distributed scanning (horizontal scaling)
- Real-time collaborative testing
- Integration API for custom tooling
- Web UI for scan management
- Automated exploitation chaining (for authorized tests)

**Strategic Direction:** Enterprise-grade platform for continuous API security

---

## Additional Technical Notes

### Thread Safety

Current implementation is single-threaded by design:
- Prevents accidental DoS on target systems
- Simplifies state management
- Easier debugging and evidence collection

Future: Thread pool for independent endpoint testing (opt-in).

### Error Handling Strategy

```
Error Handling Tiers:

1. Network Errors (transient):
   ├── Action: Retry with exponential backoff
   ├── Max Retries: 2
   └── Log: Warning level

2. Authentication Errors (configuration):
   ├── Action: Fail fast
   ├── Retry: No
   └── Log: Error level + immediate exit

3. Parsing Errors (malformed responses):
   ├── Action: Skip endpoint, continue scan
   ├── Retry: No
   └── Log: Debug level

4. Framework Errors (bugs):
   ├── Action: Capture stack trace, save state
   ├── Resume: Supported
   └── Log: Error level + state dump
```

### State Persistence Format

```json
{
  "scan_id": "UUID",
  "target": "https://api.example.com",
  "checkpoint_time": "ISO8601",
  "discovered_endpoints": [...],
  "tested_endpoints": [...],
  "findings_so_far": [...],
  "current_phase": 2,
  "current_module": "API2",
  "current_endpoint_index": 15
}
```

Enables:
- Resume after interruption
- Incremental testing (add new endpoints)
- Audit trail for compliance

---

## References & Further Reading

**OWASP Resources:**
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/)
- [OWASP Testing Guide v4](https://owasp.org/www-project-web-security-testing-guide/)

**Related Tools (Architectural Inspiration):**
- OWASP ZAP: Proxy architecture and extensibility model
- Burp Suite: Module system and evidence collection
- Nuclei: Template-based scanning approach

**Academic Papers:**
- "Breaking and Fixing Object-Level Authorization in Web Applications" (USENIX Security 2019)
- "Authentication Vulnerabilities in Web Applications" (IEEE S&P 2020)

---

<div align="center">

**VardrScanner Technical Design Documentation**

*Complete technical specifications for reviewers who want the details*

[Back to README](README.md)

</div>
