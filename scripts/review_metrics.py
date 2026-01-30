#!/usr/bin/env python3
"""
Review Metrics Module

Track observability metrics for security reviews including:
- File and line counts
- LLM token usage and costs
- Finding severity and category counts
- Exploitability classifications
- Agent execution times
- Threat model and sandbox validation metrics

Extracted from analysis_helpers.py for better modularity.
"""

import json
import os
import time
from datetime import datetime, timezone

__all__ = ["ReviewMetrics"]


class ReviewMetrics:
    """Track observability metrics for the review"""

    def __init__(self):
        self.start_time = time.time()
        self.metrics = {
            "version": "1.0.16",
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "unknown"),
            "commit": os.environ.get("GITHUB_SHA", "unknown"),
            "files_reviewed": 0,
            "lines_analyzed": 0,
            "tokens_input": 0,
            "tokens_output": 0,
            "cost_usd": 0.0,
            "duration_seconds": 0,
            "model": "",
            "provider": "",
            "findings": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "categories": {"security": 0, "performance": 0, "testing": 0, "quality": 0},
            # Exploit analysis metrics
            "exploitability": {"trivial": 0, "moderate": 0, "complex": 0, "theoretical": 0},
            "exploit_chains_found": 0,
            "tests_generated": 0,
            # Agent execution tracking
            "agents_executed": [],
            "agent_execution_times": {},
            # Threat modeling metrics
            "threat_model": {
                "generated": False,
                "threats_identified": 0,
                "attack_surface_size": 0,
                "trust_boundaries": 0,
                "assets_cataloged": 0,
            },
            # Sandbox validation metrics
            "sandbox": {
                "validations_run": 0,
                "exploitable": 0,
                "not_exploitable": 0,
                "false_positives_eliminated": 0,
                "validation_errors": 0,
            },
        }

    def record_file(self, lines):
        self.metrics["files_reviewed"] += 1
        self.metrics["lines_analyzed"] += lines

    def record_llm_call(self, input_tokens, output_tokens, provider):
        self.metrics["tokens_input"] += input_tokens
        self.metrics["tokens_output"] += output_tokens

        # Calculate cost based on provider
        if provider == "anthropic":
            # Claude Sonnet 4: $3/1M input, $15/1M output
            input_cost = (input_tokens / 1_000_000) * 3.0
            output_cost = (output_tokens / 1_000_000) * 15.0
        elif provider == "openai":
            # GPT-4: $10/1M input, $30/1M output
            input_cost = (input_tokens / 1_000_000) * 10.0
            output_cost = (output_tokens / 1_000_000) * 30.0
        else:
            # Ollama and other local models: Free
            input_cost = 0.0
            output_cost = 0.0

        self.metrics["cost_usd"] += input_cost + output_cost

    def record_finding(self, severity, category):
        if severity in self.metrics["findings"]:
            self.metrics["findings"][severity] += 1
        if category in self.metrics["categories"]:
            self.metrics["categories"][category] += 1

    def record_exploitability(self, exploitability_level):
        """Record exploitability classification

        Args:
            exploitability_level: One of 'trivial', 'moderate', 'complex', 'theoretical'
        """
        level = exploitability_level.lower()
        if level in self.metrics["exploitability"]:
            self.metrics["exploitability"][level] += 1

    def record_exploit_chain(self):
        """Record that an exploit chain was identified"""
        self.metrics["exploit_chains_found"] += 1

    def record_test_generated(self, count=1):
        """Record number of security tests generated

        Args:
            count: Number of test files generated (default: 1)
        """
        self.metrics["tests_generated"] += count

    def record_agent_execution(self, agent_name, duration_seconds):
        """Record agent execution for observability

        Args:
            agent_name: Name of the agent (e.g., 'exploit-analyst')
            duration_seconds: Time taken to execute the agent
        """
        if agent_name not in self.metrics["agents_executed"]:
            self.metrics["agents_executed"].append(agent_name)
        self.metrics["agent_execution_times"][agent_name] = duration_seconds

    def record_threat_model(self, threat_model):
        """Record threat model metrics

        Args:
            threat_model: Threat model dictionary
        """
        self.metrics["threat_model"]["generated"] = True
        self.metrics["threat_model"]["threats_identified"] = len(threat_model.get("threats", []))
        self.metrics["threat_model"]["attack_surface_size"] = len(
            threat_model.get("attack_surface", {}).get("entry_points", [])
        )
        self.metrics["threat_model"]["trust_boundaries"] = len(threat_model.get("trust_boundaries", []))
        self.metrics["threat_model"]["assets_cataloged"] = len(threat_model.get("assets", []))

    def record_sandbox_validation(self, result: str):
        """Record sandbox validation result

        Args:
            result: ValidationResult value ('exploitable', 'not_exploitable', 'error', etc.)
        """
        self.metrics["sandbox"]["validations_run"] += 1
        if result == "exploitable":
            self.metrics["sandbox"]["exploitable"] += 1
        elif result == "not_exploitable":
            self.metrics["sandbox"]["not_exploitable"] += 1
        elif result == "error":
            self.metrics["sandbox"]["validation_errors"] += 1

    def record_false_positive_eliminated(self):
        """Record that a false positive was eliminated via sandbox validation"""
        self.metrics["sandbox"]["false_positives_eliminated"] += 1

    def finalize(self):
        self.metrics["duration_seconds"] = int(time.time() - self.start_time)
        return self.metrics

    def save(self, path):
        with open(path, "w") as f:
            json.dump(self.metrics, f, indent=2)
        print(f"📊 Metrics saved to: {path}")
