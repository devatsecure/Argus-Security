#!/usr/bin/env python3
"""
Metrics collection and tracking module for AI-powered audits.

Tracks observability metrics including:
- Files reviewed and lines analyzed
- Token usage and costs (per provider)
- Findings by severity and category
- Exploitability classifications
- Agent execution times
- Threat model metrics
- Sandbox validation results
"""

import json
import os
import time
from datetime import datetime, timezone


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
            # NEW: Exploit analysis metrics
            "exploitability": {"trivial": 0, "moderate": 0, "complex": 0, "theoretical": 0},
            "exploit_chains_found": 0,
            "tests_generated": 0,
            # NEW: Agent execution tracking
            "agents_executed": [],
            "agent_execution_times": {},
            # NEW: Threat modeling metrics
            "threat_model": {
                "generated": False,
                "threats_identified": 0,
                "attack_surface_size": 0,
                "trust_boundaries": 0,
                "assets_cataloged": 0,
            },
            # NEW: Sandbox validation metrics
            "sandbox": {
                "validations_run": 0,
                "exploitable": 0,
                "not_exploitable": 0,
                "false_positives_eliminated": 0,
                "validation_errors": 0,
            },
        }

    def record_file(self, lines):
        """Record a file review

        Args:
            lines: Number of lines in the file
        """
        self.metrics["files_reviewed"] += 1
        self.metrics["lines_analyzed"] += lines

    def record_llm_call(self, input_tokens, output_tokens, provider):
        """Record an LLM API call with tokens and cost

        Args:
            input_tokens: Number of input tokens used
            output_tokens: Number of output tokens generated
            provider: AI provider name (anthropic, openai, etc.)
        """
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
        elif provider == "foundation-sec":
            # Foundation-Sec: Zero cost (local inference)
            input_cost = 0.0
            output_cost = 0.0
        else:
            # Ollama and other local models: Free
            input_cost = 0.0
            output_cost = 0.0

        self.metrics["cost_usd"] += input_cost + output_cost

    def record(self, key, value=1):
        """Record an arbitrary metric by key.

        If the key already exists and is numeric, adds value to it.
        Otherwise sets the key to value.
        """
        if key in self.metrics and isinstance(self.metrics[key], (int, float)):
            self.metrics[key] += value
        else:
            self.metrics[key] = value

    def record_finding(self, severity, category):
        """Record a security finding

        Args:
            severity: Finding severity (critical, high, medium, low, info)
            category: Finding category (security, performance, testing, quality)
        """
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
        """Finalize metrics and calculate duration

        Returns:
            dict: The complete metrics dictionary
        """
        self.metrics["duration_seconds"] = int(time.time() - self.start_time)
        return self.metrics

    def save(self, path):
        """Save metrics to a JSON file

        Args:
            path: File path to save metrics to
        """
        with open(path, "w") as f:
            json.dump(self.metrics, f, indent=2)
        print(f"Metrics saved to: {path}")

    def to_dict(self):
        """Get metrics as a dictionary

        Returns:
            dict: The metrics dictionary
        """
        return self.metrics

    def get_summary(self):
        """Get a summary of key metrics

        Returns:
            dict: Summary of important metrics
        """
        return {
            "files_reviewed": self.metrics["files_reviewed"],
            "lines_analyzed": self.metrics["lines_analyzed"],
            "tokens_input": self.metrics["tokens_input"],
            "tokens_output": self.metrics["tokens_output"],
            "cost_usd": self.metrics["cost_usd"],
            "duration_seconds": self.metrics["duration_seconds"],
            "total_findings": sum(self.metrics["findings"].values()),
            "critical_findings": self.metrics["findings"]["critical"],
            "high_findings": self.metrics["findings"]["high"],
        }
