# pytm Integration - Deterministic Threat Modeling

## Overview

Argus integrates [OWASP pytm](https://github.com/OWASP/pytm) to provide **always-available, deterministic threat modeling** without requiring API keys or external services. This ensures every security analysis includes threat context for AI agents, even when running offline or without API access.

## What is pytm?

pytm is a Pythonic framework for threat modeling that uses a **code-as-data** approach:

- **Declarative**: Define your system architecture in Python code
- **Deterministic**: Same input always produces same output
- **STRIDE-based**: Automatic threat identification using Microsoft's STRIDE methodology
- **Open Source**: No API keys, no costs, no external dependencies
- **Reproducible**: Perfect for CI/CD pipelines and compliance audits

## Why pytm in Argus?

### The Problem
Previously, Argus threat modeling relied solely on Anthropic's Claude API:
- ❌ Required API key ($$$)
- ❌ Silent degradation when unavailable
- ❌ No threat context for agents
- ❌ Empty metrics block
- ❌ Non-deterministic results

### The Solution: Hybrid Approach
Argus now uses a **hybrid threat modeling strategy**:

```
┌─────────────────────────────────────────────────────────────┐
│                  Hybrid Threat Model Generator              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  Step 1: pytm Baseline (ALWAYS RUNS)                       │
│  ├─ Architecture detection (web app, API, microservices)   │
│  ├─ STRIDE threat analysis                                 │
│  ├─ Attack surface identification                          │
│  └─ Trust boundary mapping                                 │
│                                                             │
│  Step 2: Anthropic Enhancement (OPTIONAL)                  │
│  ├─ Context-aware threats                                  │
│  ├─ Business logic vulnerabilities                         │
│  ├─ Framework-specific issues                              │
│  └─ Supply chain risks                                     │
│                                                             │
│  Result: Comprehensive Threat Model                        │
│  ├─ Deterministic baseline (pytm)                          │
│  └─ AI-enhanced insights (Anthropic, if available)         │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Benefits

**Before (Anthropic-only)**:
- ❌ Requires API key
- ❌ Costs $0.10-0.50 per analysis
- ❌ Silent failure without key
- ❌ Non-deterministic

**After (pytm + Anthropic hybrid)**:
- ✅ Always generates threat model
- ✅ Zero cost for baseline
- ✅ Agents always have context
- ✅ Deterministic + reproducible
- ✅ Optional AI enhancement
- ✅ Offline-capable

## Architecture Detection

Argus automatically detects your application architecture and applies appropriate threat modeling templates:

### Supported Architectures

| Architecture | Detection Criteria | pytm Model |
|-------------|-------------------|------------|
| **Web Application** | React, Vue, Angular, Django, Flask | 3-tier (Web → App → DB) |
| **API Service** | FastAPI, GraphQL, REST frameworks | API Gateway → Service → Data |
| **Microservices** | docker-compose.yml, multiple services | Service mesh + message queue |
| **CLI Tool** | Command-line application | User → CLI → Filesystem |
| **Library** | Package/module (default) | Application → Library |

### Detection Logic

```python
# Example: Web App Detection
if any(fw in frameworks for fw in ['React', 'Django', 'Flask', 'Express']):
    architecture = 'web_app'
    # Generates: Internet → DMZ → Internal Network
    # Components: Web Server, App Server, Database
    # Threats: XSS, CSRF, SQL Injection, Session hijacking
```

## STRIDE Threat Categories

pytm automatically generates threats based on the STRIDE methodology:

| Category | Description | Example Threats |
|----------|-------------|-----------------|
| **S**poofing | Impersonation attacks | Weak authentication, session hijacking |
| **T**ampering | Data modification | SQL injection, parameter tampering |
| **R**epudiation | Denying actions | Missing audit logs, unsigned transactions |
| **I**nformation Disclosure | Data leakage | Exposed secrets, verbose errors |
| **D**enial of Service | Availability attacks | Resource exhaustion, rate limiting |
| **E**levation of Privilege | Unauthorized access | Privilege escalation, broken access control |

## Usage

### Basic Usage (pytm only)

```bash
# No API key needed - pytm baseline only
cd /path/to/your/repo
python3 /path/to/argus/scripts/threat_model_generator.py
```

Output:
```
ℹ️  No ANTHROPIC_API_KEY provided - using pytm baseline only
   (Set API key for AI-enhanced threat modeling)
✅ pytm baseline: 6 threats
✅ Threat model generated: .argus/threat-model.json
   Generator: pytm
```

### Enhanced Usage (pytm + Anthropic)

```bash
# With API key - pytm baseline + AI enhancement
export ANTHROPIC_API_KEY=sk-ant-...
python3 /path/to/argus/scripts/threat_model_generator.py
```

Output:
```
✅ pytm baseline: 6 threats
✅ AI enhancement: 14 total threats
✅ Threat model generated: .argus/threat-model.json
   Generator: pytm + anthropic
```

### Programmatic Usage

```python
from threat_model_generator import HybridThreatModelGenerator

# Initialize (API key optional)
generator = HybridThreatModelGenerator(api_key=None)  # pytm only
# or
generator = HybridThreatModelGenerator(api_key="sk-ant-...")  # pytm + AI

# Analyze repository
repo_context = generator.analyze_repository("/path/to/repo")

# Generate threat model
threat_model = generator.generate_threat_model(repo_context)

# Save
generator.save_threat_model(threat_model, ".argus/threat-model.json")

print(f"Threats: {len(threat_model['threats'])}")
print(f"Generator: {threat_model['generator']}")  # "pytm" or "pytm + anthropic"
```

## Threat Model Output Format

```json
{
  "name": "Argus Threat Model: my-app",
  "description": "Automated threat model for my-app (web_app)",
  "generated_at": "2025-11-07T10:30:00Z",
  "generator": "pytm",
  "version": "1.0",
  "architecture_type": "web_app",
  
  "attack_surface": {
    "entry_points": [
      "Web Server",
      "HTTP/HTTPS endpoints",
      "Web forms",
      "API endpoints"
    ],
    "external_dependencies": [
      "React",
      "Express",
      "PostgreSQL"
    ],
    "authentication_methods": [
      "Web Server authentication",
      "Session-based",
      "Cookie-based"
    ],
    "data_stores": [
      "Database (SQL Database)"
    ]
  },
  
  "trust_boundaries": [
    {
      "id": "BOUNDARY-001",
      "name": "Internet",
      "trust_level": "untrusted",
      "description": "Trust boundary: Internet"
    },
    {
      "id": "BOUNDARY-002",
      "name": "DMZ",
      "trust_level": "semi-trusted",
      "description": "Trust boundary: DMZ"
    },
    {
      "id": "BOUNDARY-003",
      "name": "Internal Network",
      "trust_level": "trusted",
      "description": "Trust boundary: Internal Network"
    }
  ],
  
  "assets": [
    {
      "id": "ASSET-001",
      "name": "Database",
      "type": "data",
      "sensitivity": "high",
      "description": "Data store: Database"
    }
  ],
  
  "threats": [
    {
      "id": "THREAT-001",
      "name": "Spoofing Threat",
      "description": "Attacker impersonates a legitimate user or system component",
      "category": "Spoofing",
      "target": "Web Server",
      "likelihood": "medium",
      "impact": "medium",
      "risk_rating": "medium",
      "mitigation": "Implement controls to prevent spoofing",
      "stride_category": "Spoofing"
    },
    {
      "id": "THREAT-002",
      "name": "Tampering Threat",
      "description": "Attacker modifies data or code without authorization",
      "category": "Tampering",
      "target": "System",
      "likelihood": "high",
      "impact": "high",
      "risk_rating": "high",
      "mitigation": "Implement controls to prevent tampering",
      "stride_category": "Tampering"
    }
  ],
  
  "security_objectives": [
    "Protect confidentiality of sensitive data",
    "Ensure integrity of system components and data",
    "Maintain availability of services",
    "Implement strong authentication and authorization",
    "Enable audit logging and monitoring",
    "Prevent XSS and CSRF attacks",
    "Secure session management",
    "Protect against SQL injection"
  ]
}
```

## AI Enhancement

When an Anthropic API key is provided, the hybrid generator enhances the pytm baseline with context-aware threats:

### What AI Adds

1. **Business Logic Vulnerabilities**
   - Authorization flaws
   - Race conditions
   - State management issues

2. **Framework-Specific Issues**
   - Known CVEs in detected frameworks
   - Misconfiguration patterns
   - Security anti-patterns

3. **Configuration Problems**
   - Exposed secrets
   - Weak cryptography
   - Insecure defaults

4. **Third-Party Risks**
   - Supply chain vulnerabilities
   - Outdated dependencies
   - Malicious packages

5. **Data Flow Vulnerabilities**
   - PII leakage
   - Insecure storage
   - Unencrypted transmission

### Example Enhancement

**pytm baseline (6 threats)**:
- Generic STRIDE threats for web application architecture

**+ AI enhancement (8 additional threats)**:
- React-specific XSS via `dangerouslySetInnerHTML`
- Express session fixation vulnerability
- PostgreSQL connection string in environment variables
- Missing rate limiting on authentication endpoint
- CORS misconfiguration allowing credential theft
- JWT token without expiration
- Unvalidated redirect in OAuth callback
- Dependency with known CVE (express@4.16.0)

**= Total: 14 threats**

## Integration with Argus

### Automatic Threat Context

When Argus runs a security analysis, AI agents automatically receive threat model context:

```markdown
## THREAT MODEL CONTEXT

You have access to the following threat model for this codebase:

### Attack Surface
- **Entry Points**: Web Server, HTTP/HTTPS endpoints, Web forms, API endpoints
- **External Dependencies**: React, Express, PostgreSQL
- **Authentication Methods**: Session-based, Cookie-based
- **Data Stores**: Database (SQL Database)

### Critical Assets
- **Database** (Sensitivity: high): Data store: Database

### Trust Boundaries
- **Internet** (untrusted): Trust boundary: Internet
- **DMZ** (semi-trusted): Trust boundary: DMZ
- **Internal Network** (trusted): Trust boundary: Internal Network

### Known Threats
- **Spoofing Threat** (Spoofing, Likelihood: medium, Impact: medium)
- **Tampering Threat** (Tampering, Likelihood: high, Impact: high)
- **Information Disclosure Threat** (Information Disclosure, Likelihood: high, Impact: high)

### Security Objectives
- Protect confidentiality of sensitive data
- Ensure integrity of system components and data
- Maintain availability of services
- Implement strong authentication and authorization
- Enable audit logging and monitoring

**Use this threat model to:**
1. Focus your analysis on the identified attack surfaces
2. Prioritize vulnerabilities that affect critical assets
3. Consider trust boundary violations
4. Look for instances of the known threat categories
5. Validate that security objectives are being met
```

This context helps AI agents:
- Focus on relevant attack surfaces
- Prioritize high-impact vulnerabilities
- Understand trust boundaries
- Align findings with security objectives

## Customization

### Custom Architecture Templates

You can create custom pytm templates for your specific architecture:

```python
# config/pytm_templates/my_custom_arch.py
from pytm import TM, Server, Datastore, Dataflow, Boundary, Actor

def build_custom_model(tm, repo_context):
    """Custom architecture template"""
    # Define your boundaries
    public_zone = Boundary("Public Zone")
    secure_zone = Boundary("Secure Zone")
    
    # Define actors
    user = Actor("User")
    user.inBoundary = public_zone
    
    # Define components
    api = Server("API Gateway")
    api.inBoundary = public_zone
    api.providesAuthentication = True
    
    service = Server("Backend Service")
    service.inBoundary = secure_zone
    
    # Define dataflows
    user_to_api = Dataflow(user, api, "API Request")
    user_to_api.protocol = "HTTPS"
    user_to_api.isEncrypted = True
    
    api_to_service = Dataflow(api, service, "Internal Call")
    
    return tm
```

### Override Architecture Detection

```python
# Force specific architecture type
from pytm_threat_model import PytmThreatModelGenerator

generator = PytmThreatModelGenerator()

# Override detection
repo_context['architecture_override'] = 'microservices'

threat_model = generator.generate_from_repo_context(repo_context)
```

## Troubleshooting

### Issue: "pytm not available"

```bash
# Install pytm
pip install pytm>=1.3.0

# Verify installation
python3 -c "import pytm; print(pytm.__version__)"
```

### Issue: "No threats generated"

This can happen if pytm's threat analysis fails. Check:

1. **Architecture detection**: Ensure your repo has recognizable files (package.json, requirements.txt, etc.)
2. **pytm version**: Update to latest version
3. **Fallback**: The generator will use generic STRIDE threats as fallback

```python
# Debug architecture detection
from threat_model_generator import HybridThreatModelGenerator

generator = HybridThreatModelGenerator(api_key=None)
repo_context = generator.analyze_repository("/path/to/repo")

print(f"Languages: {repo_context['languages']}")
print(f"Frameworks: {repo_context['frameworks']}")
print(f"Technologies: {repo_context['technologies']}")
```

### Issue: "Anthropic enhancement not working"

Verify your API key:

```bash
# Test API key
export ANTHROPIC_API_KEY=sk-ant-...
python3 -c "from anthropic import Anthropic; print(Anthropic().messages.create(model='claude-sonnet-4-5-20250929', max_tokens=10, messages=[{'role':'user','content':'test'}]))"
```

## Performance

### Benchmarks

| Operation | pytm only | pytm + Anthropic | Anthropic only |
|-----------|-----------|------------------|----------------|
| Threat model generation | ~2 seconds | ~8 seconds | ~6 seconds |
| Cost | $0.00 | ~$0.05 | ~$0.10 |
| Threats (typical) | 6-12 | 12-20 | 15-25 |
| Offline capable | ✅ Yes | ❌ No | ❌ No |

### Caching

Threat models are cached in `.argus/threat-model.json`. To regenerate:

```bash
# Force regeneration
rm .argus/threat-model.json
python3 /path/to/argus/scripts/threat_model_generator.py --force
```

## Best Practices

### 1. Use pytm for CI/CD
```yaml
# .github/workflows/security.yml
- name: Generate Threat Model
  run: |
    pip install pytm
    python3 scripts/threat_model_generator.py
    # No API key needed - deterministic results
```

### 2. Enhance for Production
```bash
# Development: Fast, free
python3 scripts/threat_model_generator.py

# Production: Comprehensive, AI-enhanced
ANTHROPIC_API_KEY=${{ secrets.ANTHROPIC_API_KEY }} \
  python3 scripts/threat_model_generator.py
```

### 3. Version Control Threat Models
```bash
# Commit threat models for audit trail
git add .argus/threat-model.json
git commit -m "chore: update threat model"
```

### 4. Review Regularly
```bash
# Regenerate on architecture changes
python3 scripts/threat_model_generator.py --force

# Compare with previous version
git diff .argus/threat-model.json
```

## Comparison: pytm vs DefectDojo

| Feature | pytm | DefectDojo |
|---------|------|------------|
| **Purpose** | Threat modeling | Vulnerability management |
| **Deployment** | Library (pip install) | Self-hosted service |
| **Cost** | Free | Free (self-hosted) |
| **Setup** | 1 minute | 30+ minutes |
| **Maintenance** | None | Database, updates, backups |
| **API** | Python API | REST API |
| **Integration** | Direct (code) | HTTP requests |
| **Offline** | ✅ Yes | ❌ No (requires server) |
| **CI/CD** | ✅ Perfect | ⚠️ Complex |

**Recommendation**: Use pytm for threat modeling, consider DefectDojo for vulnerability management (deduplication, SLA tracking, triage workflows).

## FAQ

**Q: Do I need an API key?**  
A: No. pytm works without any API key. Anthropic API key is optional for AI enhancement.

**Q: Is pytm as good as AI threat modeling?**  
A: pytm provides deterministic STRIDE analysis. AI adds context-aware threats. Use both for best results.

**Q: Can I use this offline?**  
A: Yes. pytm works completely offline. Only AI enhancement requires internet.

**Q: How often should I regenerate?**  
A: Regenerate when architecture changes (new services, frameworks, data stores).

**Q: Can I customize the threat model?**  
A: Yes. Create custom pytm templates or override architecture detection.

**Q: What if pytm misses threats?**  
A: Use AI enhancement (Anthropic) for context-aware threats. Or manually add threats to the JSON file.

## References

- [OWASP pytm GitHub](https://github.com/OWASP/pytm)
- [STRIDE Threat Modeling](https://docs.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats)
- [Argus Documentation](../README.md)
- [Threat Modeling Best Practices](https://owasp.org/www-community/Threat_Modeling)

## Support

For issues or questions:
- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Email: developer@secure.com
- Documentation: https://github.com/devatsecure/Argus-Security#readme

