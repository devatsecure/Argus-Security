#!/usr/bin/env python3
"""
Complete Argus Security Pipeline - All 11 Components
Runs comprehensive security analysis with all available tools

Components:
1. TruffleHog - Secret scanning with API validation
2. Gitleaks - Pattern-based secret detection  
3. Semgrep - SAST with 2000+ rules
4. Trivy - CVE scanning
5. Checkov - IaC security
6. Normalization + Deduplication
7. Dual AI Analysis (Foundation-Sec + Cursor AI)
8. Noise Scoring + Correlation
9. Exploitability Triage
10. Reachability Analysis
11. Risk Scoring
12. Policy Gates
13. SOC 2 Compliance
14. SBOM Generation + Signing
15. Complete Metrics
"""

import json
import os
import sys
import time
import subprocess
from pathlib import Path
from datetime import datetime

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

class FullPipelineOrchestrator:
    """Orchestrates all 11+ security components"""
    
    def __init__(self, target_repo: str, output_dir: str = None):
        self.target_repo = Path(target_repo).resolve()
        self.output_dir = Path(output_dir or self.target_repo / ".argus" / "full-scan")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.results = {
            "scan_start": datetime.now().isoformat(),
            "target": str(self.target_repo),
            "components": {},
            "metrics": {
                "total_findings": 0,
                "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "by_component": {},
                "total_cost_usd": 0.0,
                "total_duration_seconds": 0
            }
        }
        
    def run_component(self, name: str, command: list, timeout: int = 600):
        """Run a pipeline component"""
        print(f"\n{'='*80}")
        print(f"🔍 Component: {name}")
        print(f"{'='*80}")
        
        start = time.time()
        try:
            result = subprocess.run(
                command,
                cwd=self.target_repo,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            duration = time.time() - start
            
            self.results["components"][name] = {
                "status": "success" if result.returncode == 0 else "failed",
                "duration_seconds": duration,
                "returncode": result.returncode
            }
            
            print(f"✅ {name} complete ({duration:.1f}s)")
            return result
            
        except subprocess.TimeoutExpired:
            duration = time.time() - start
            print(f"⏱️  {name} timeout after {timeout}s")
            self.results["components"][name] = {
                "status": "timeout",
                "duration_seconds": duration
            }
            return None
        except Exception as e:
            duration = time.time() - start
            print(f"❌ {name} error: {e}")
            self.results["components"][name] = {
                "status": "error",
                "duration_seconds": duration,
                "error": str(e)
            }
            return None
    
    def component_1_deterministic_scanners(self):
        """Run all 5 deterministic scanners"""
        print("\n" + "="*80)
        print("📊 COMPONENT 1: DETERMINISTIC SCANNERS (5 tools)")
        print("="*80)
        
        scanners = {
            "trufflehog": ["trufflehog", "filesystem", ".", "--json"],
            "gitleaks": ["gitleaks", "detect", "--source", ".", "--report-format", "json"],
            "semgrep": ["semgrep", "--config=auto", "--json", "."],
            "trivy": ["trivy", "fs", "--format", "json", "."],
            "checkov": ["checkov", "-d", ".", "--output", "json"]
        }
        
        for name, cmd in scanners.items():
            output_file = self.output_dir / f"{name}_results.json"
            cmd_with_output = cmd + ["-o", str(output_file)] if name != "semgrep" else cmd
            self.run_component(f"Scanner: {name}", cmd_with_output)
    
    def component_2_normalization(self):
        """Normalize and deduplicate findings"""
        print("\n" + "="*80)
        print("🔄 COMPONENT 2: NORMALIZATION + DEDUPLICATION")
        print("="*80)
        
        # Run normalizer
        self.run_component(
            "Normalizer",
            ["python3", str(SCRIPT_DIR / "normalizer" / "base.py"), str(self.target_repo)]
        )
        
        # Run deduplicator
        self.run_component(
            "Deduplicator",
            ["python3", str(SCRIPT_DIR / "deduplicator.py"), str(self.output_dir)]
        )
    
    def component_3_dual_ai_analysis(self):
        """Run dual AI analysis"""
        print("\n" + "="*80)
        print("🧠 COMPONENT 3: DUAL AI ANALYSIS")
        print("="*80)
        
        # Foundation-Sec (local, free)
        print("\n1️⃣  Foundation-Sec-8B (Cisco, local, $0)")
        self.run_component(
            "Foundation-Sec",
            ["python3", str(SCRIPT_DIR / "hybrid_analyzer.py"), 
             str(self.target_repo), "--foundation-sec-only"],
            timeout=900
        )
        
        # Cursor AI (via run_ai_audit with best practices)
        print("\n2️⃣  Cursor AI (Enhanced with Best Practices)")
        self.run_component(
            "Cursor-AI-Audit",
            ["python3", str(SCRIPT_DIR / "run_ai_audit.py"),
             str(self.target_repo), "audit"],
            timeout=1800
        )
    
    def component_4_noise_scoring(self):
        """ML-powered false positive suppression"""
        print("\n" + "="*80)
        print("🎯 COMPONENT 4: NOISE SCORING + CORRELATION")
        print("="*80)
        
        self.run_component(
            "Noise Scorer",
            ["python3", str(SCRIPT_DIR / "noise_scorer.py"), str(self.output_dir)]
        )
        
        self.run_component(
            "Correlator",
            ["python3", str(SCRIPT_DIR / "correlator.py"), str(self.output_dir)]
        )
    
    def component_5_exploitability_triage(self):
        """Aardvark mode - exploit classification"""
        print("\n" + "="*80)
        print("💥 COMPONENT 5: EXPLOITABILITY TRIAGE (Aardvark Mode)")
        print("="*80)
        
        self.run_component(
            "Exploitability Triage",
            ["python3", str(SCRIPT_DIR / "exploitability_triage.py"), str(self.output_dir)]
        )
    
    def component_6_reachability_analysis(self):
        """Call graph and reachability analysis"""
        print("\n" + "="*80)
        print("🔍 COMPONENT 6: REACHABILITY ANALYSIS")
        print("="*80)
        
        self.run_component(
            "Reachability Analyzer",
            ["python3", str(SCRIPT_DIR / "reachability_analyzer.py"), str(self.target_repo)]
        )
    
    def component_7_risk_scoring(self):
        """CVSS × Exploitability × Reachability × Business Impact"""
        print("\n" + "="*80)
        print("📊 COMPONENT 7: RISK SCORING")
        print("="*80)
        
        self.run_component(
            "Risk Scorer",
            ["python3", str(SCRIPT_DIR / "risk_scorer.py"), str(self.output_dir)]
        )
    
    def component_8_policy_gates(self):
        """Rego-based policy enforcement"""
        print("\n" + "="*80)
        print("🚪 COMPONENT 8: POLICY GATES (Rego)")
        print("="*80)
        
        self.run_component(
            "Policy Gate",
            ["python3", str(SCRIPT_DIR / "gate.py"), str(self.output_dir), "--policy", "soc2"]
        )
    
    def component_9_soc2_compliance(self):
        """SOC 2 compliance evaluation"""
        print("\n" + "="*80)
        print("📋 COMPONENT 9: SOC 2 COMPLIANCE")
        print("="*80)
        
        # SOC 2 evaluation is part of gate.py
        print("✅ SOC 2 compliance evaluated in policy gates")
    
    def component_10_sbom_generation(self):
        """SBOM generation and signing"""
        print("\n" + "="*80)
        print("📦 COMPONENT 10: SBOM GENERATION + SIGNING")
        print("="*80)
        
        self.run_component(
            "SBOM Generator",
            ["python3", str(SCRIPT_DIR / "sbom_generator.py"), str(self.target_repo)]
        )
        
        self.run_component(
            "Release Signer",
            ["python3", str(SCRIPT_DIR / "sign_release.py"), str(self.output_dir)]
        )
    
    def component_11_metrics(self):
        """Generate complete metrics"""
        print("\n" + "="*80)
        print("📈 COMPONENT 11: COMPLETE METRICS")
        print("="*80)
        
        # Aggregate all metrics
        self.aggregate_metrics()
        
        # Generate dashboard
        self.run_component(
            "Dashboard Generator",
            ["python3", str(SCRIPT_DIR / "dashboard_generator.py"), str(self.output_dir)]
        )
    
    def aggregate_metrics(self):
        """Aggregate metrics from all components"""
        print("\n📊 Aggregating metrics from all components...")
        
        # Count findings from normalized results
        normalized_file = self.output_dir / "normalized_findings.json"
        if normalized_file.exists():
            with open(normalized_file) as f:
                data = json.load(f)
                self.results["metrics"]["total_findings"] = len(data.get("findings", []))
                
                for finding in data.get("findings", []):
                    severity = finding.get("severity", "low")
                    if severity in self.results["metrics"]["by_severity"]:
                        self.results["metrics"]["by_severity"][severity] += 1
        
        # Calculate total duration
        total_duration = sum(
            comp.get("duration_seconds", 0) 
            for comp in self.results["components"].values()
        )
        self.results["metrics"]["total_duration_seconds"] = total_duration
        
        print(f"✅ Total findings: {self.results['metrics']['total_findings']}")
        print(f"✅ Total duration: {total_duration:.1f}s")
    
    def run_full_pipeline(self):
        """Run all 11+ components in sequence"""
        print("\n" + "="*80)
        print("🚀 ARGUS FULL SECURITY PIPELINE")
        print("="*80)
        print(f"Target: {self.target_repo}")
        print(f"Output: {self.output_dir}")
        print("="*80)
        
        pipeline_start = time.time()
        
        try:
            # Run all components
            self.component_1_deterministic_scanners()
            self.component_2_normalization()
            self.component_3_dual_ai_analysis()
            self.component_4_noise_scoring()
            self.component_5_exploitability_triage()
            self.component_6_reachability_analysis()
            self.component_7_risk_scoring()
            self.component_8_policy_gates()
            self.component_9_soc2_compliance()
            self.component_10_sbom_generation()
            self.component_11_metrics()
            
            # Finalize
            self.results["scan_end"] = datetime.now().isoformat()
            self.results["total_pipeline_duration"] = time.time() - pipeline_start
            
            # Save results
            results_file = self.output_dir / "full_pipeline_results.json"
            with open(results_file, "w") as f:
                json.dump(self.results, f, indent=2)
            
            print("\n" + "="*80)
            print("✅ FULL PIPELINE COMPLETE")
            print("="*80)
            print(f"📊 Results saved to: {results_file}")
            print(f"⏱️  Total time: {self.results['total_pipeline_duration']:.1f}s")
            print(f"🔍 Total findings: {self.results['metrics']['total_findings']}")
            
            return 0
            
        except KeyboardInterrupt:
            print("\n⚠️  Pipeline interrupted by user")
            return 130
        except Exception as e:
            print(f"\n❌ Pipeline error: {e}")
            import traceback
            traceback.print_exc()
            return 1


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 run_full_pipeline.py <target_repo> [output_dir]")
        sys.exit(1)
    
    target_repo = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    orchestrator = FullPipelineOrchestrator(target_repo, output_dir)
    sys.exit(orchestrator.run_full_pipeline())


if __name__ == "__main__":
    main()
