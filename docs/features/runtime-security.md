# Container Runtime Security

## Overview

Container Runtime Security provides real-time threat detection for running containers. It monitors system calls, network activity, and file access to detect malicious behavior that static analysis cannot catch.

**Note:** This feature is **disabled by default** and requires Docker/Kubernetes environment to run.

## How It Works

The runtime security monitor:

1. **Monitors System Behavior**:
   - System calls (syscalls)
   - Process execution
   - Network connections
   - File system access
   - Privilege escalation attempts

2. **Detects Anomalies**:
   - Unexpected processes (shells in containers)
   - Suspicious network activity
   - File access outside expected paths
   - Crypto mining indicators
   - Data exfiltration patterns

3. **Alerts on Threats**:
   - Real-time threat notifications
   - Severity-based classification
   - Recommended response actions

## Usage

### CLI Usage

```bash
# Monitor runtime security for 60 seconds
./scripts/argus runtime-security monitor --duration 60 --path /path/to/app

# Enable during full scan (disabled by default)
python scripts/run_ai_audit.py --enable-runtime-security --runtime-monitoring-duration 60
```

### Python API

```python
from hybrid_analyzer import HybridSecurityAnalyzer

# Create analyzer with runtime security enabled
analyzer = HybridSecurityAnalyzer(
    enable_runtime_security=True,
    runtime_monitoring_duration=60  # Monitor for 60 seconds
)

# Run analysis - runtime security monitors during scan
result = analyzer.analyze(target_path="/path/to/app")
```

### Standalone Usage

```python
from runtime_security_monitor import RuntimeSecurityMonitor

monitor = RuntimeSecurityMonitor(duration_seconds=60)

# Monitor runtime security
findings = monitor.monitor(target_path="/path/to/app")

for finding in findings:
    print(f"{finding['severity']}: {finding['title']}")
    print(f"Description: {finding['description']}")
    print(f"Recommendation: {finding['recommendation']}")
```

## Configuration

Runtime security is **disabled by default**. To enable:

```bash
python scripts/run_ai_audit.py \
  --enable-runtime-security \
  --runtime-monitoring-duration 120  # Monitor for 2 minutes
```

### Environment Variables

- `FALCO_ENABLED`: Enable Falco integration (default: false)
- `RUNTIME_MONITOR_DURATION`: Default monitoring duration in seconds

## Output Format

```json
{
  "finding_id": "runtime-001",
  "source_tool": "runtime-security",
  "severity": "critical",
  "category": "runtime",
  "title": "Unexpected Shell Execution in Container",
  "description": "Shell process (/bin/bash) spawned in container nginx-app. This may indicate compromise.",
  "file_path": "/bin/bash",
  "cwe_id": "CWE-78",
  "recommendation": "Investigate process origin. Review container logs. Consider container restart.",
  "confidence": 0.9
}
```

## Integration

Runtime security monitoring integrates with:

- **Falco**: CNCF runtime security project (recommended)
- **Docker Events API**: Container lifecycle monitoring
- **Kubernetes Audit Logs**: K8s API activity monitoring
- **System Call Tracing**: Direct syscall monitoring

## Detected Threats

### 1. Unexpected Process Execution

**Detected:**
- Shells spawned in containers (`/bin/bash`, `/bin/sh`)
- Package managers (`apt`, `yum`, `pip`)
- Network tools (`curl`, `wget`, `netcat`)
- Debuggers (`gdb`, `strace`)

**Why It's Suspicious:**
Production containers shouldn't spawn interactive shells or install packages at runtime.

### 2. Suspicious Network Activity

**Detected:**
- Connections to known malicious IPs
- Data exfiltration to unknown hosts
- Cryptocurrency mining pool connections
- Unusual port scanning activity

**Why It's Suspicious:**
Containers typically communicate with known services. Unexpected outbound connections may indicate compromise.

### 3. File System Anomalies

**Detected:**
- Writes to `/etc`, `/usr/bin`, `/lib`
- Access to sensitive files (`/etc/shadow`, `/etc/passwd`)
- Creation of hidden files (`.bashrc` modifications)
- Executable file creation in `/tmp`

**Why It's Suspicious:**
Production containers have read-only file systems. Writes to system directories indicate tampering.

### 4. Privilege Escalation

**Detected:**
- `sudo` or `su` execution
- Setuid bit changes
- Capability escalation attempts
- Container escape attempts

**Why It's Suspicious:**
Containers should run with minimal privileges. Privilege escalation is a red flag.

### 5. Crypto Mining Indicators

**Detected:**
- High CPU usage patterns
- Connections to mining pools (xmrig, monero)
- Mining binary execution (`xmr-stak`, `ethminer`)

**Why It's Suspicious:**
Cryptocurrency mining is a common post-compromise activity.

## Best Practices

1. **Monitor Production**: Enable runtime security in production environments
2. **Baseline Normal Behavior**: Establish baseline before alerting on anomalies
3. **Integrate with SIEM**: Forward alerts to security information and event management systems
4. **Automated Response**: Configure automated container restart/isolation on critical threats
5. **Regular Review**: Review runtime alerts weekly to tune detection rules

## Performance Impact

- **CPU Overhead**: ~2-5% (with Falco)
- **Memory Overhead**: ~50-100MB per monitored container
- **Network Overhead**: Negligible (alerts only)

## Troubleshooting

**Q: Why am I not seeing any findings?**

A: Ensure containers are running and Falco is properly configured. Check logs: `/var/log/falco.log`

**Q: Too many false positives?**

A: Tune Falco rules to match your environment. Add exceptions for legitimate tools.

**Q: Can I monitor non-containerized applications?**

A: Yes, but feature is optimized for containers. For VMs/bare metal, use endpoint detection tools.

**Q: Does this work with Docker Swarm/K8s?**

A: Yes! Falco supports Docker, Kubernetes, and other container runtimes.

## Example Output

```
🐳 Runtime Security Monitoring:
   Duration: 60s
   Starting monitor...

   Threats detected: 3

   Runtime threats:
   - CRITICAL: Unexpected Shell Execution in Container
     Container: nginx-app-789abc
     Process: /bin/bash
     Action: Container likely compromised - investigate immediately

   - HIGH: Suspicious Network Connection
     Container: api-server-456def
     Destination: 192.168.1.100:8888 (mining pool)
     Action: Block connection, restart container

   - MEDIUM: File Write to /etc Directory
     Container: worker-123abc
     File: /etc/cron.d/malicious-job
     Action: Review file contents, restore from image
```

## Deployment

### Docker

```bash
# Run Falco in Docker
docker run --rm -i -t \
  --privileged \
  -v /var/run/docker.sock:/host/var/run/docker.sock \
  -v /dev:/host/dev \
  -v /proc:/host/proc:ro \
  falcosecurity/falco:latest
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: falco
spec:
  selector:
    matchLabels:
      app: falco
  template:
    metadata:
      labels:
        app: falco
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: falco
        image: falcosecurity/falco:latest
        securityContext:
          privileged: true
```

## Integration with Argus

Runtime security findings are treated like other scanner findings:

1. **Detection**: Runtime monitor detects threat
2. **Normalization**: Converted to `HybridFinding` format
3. **Triage**: AI analyzes context and severity
4. **Reporting**: Included in scan results and PR comments
5. **Policy Enforcement**: Can block deployments on critical runtime threats

---

**Related Documentation:**
- [Falco Documentation](https://falco.org/docs/)
- [CNCF Runtime Security](https://www.cncf.io/projects/falco/)
- [Container Security Best Practices](../best-practices.md)
- [Hybrid Analyzer](../architecture/overview.md)
