#!/usr/bin/env python3
"""
Analysis Helper Classes Module

Contains utility classes for context tracking, finding summarization,
output validation, timeout management, codebase chunking, and context cleanup.

Extracted from run_ai_audit.py for better maintainability.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class ContextTracker:
    """Track and manage context size across LLM operations
    
    Feature: Deliberate Context Management (Best Practice #2)
    This class monitors context accumulation, detects potential contradictions,
    and provides visibility into what information is being passed to the LLM.
    """
    
    def __init__(self):
        """Initialize context tracker"""
        self.phases = []  # Track each phase's context
        self.current_phase = None
        self.total_chars = 0
        self.total_tokens_estimate = 0
        
    def start_phase(self, phase_name: str):
        """Start tracking a new phase
        
        Args:
            phase_name: Name of the phase (e.g., 'research', 'planning', 'implementation')
        """
        self.current_phase = {
            "name": phase_name,
            "start_time": time.time(),
            "components": [],
            "total_chars": 0,
            "estimated_tokens": 0
        }
        logger.info(f"📊 Context Phase Started: {phase_name}")
        
    def add_context(self, component_name: str, content: str, metadata: dict = None):
        """Add a context component to current phase
        
        Args:
            component_name: Name of the component (e.g., 'codebase', 'threat_model', 'previous_findings')
            content: The actual content being added
            metadata: Optional metadata about this component
        """
        if not self.current_phase:
            logger.warning("No active phase - call start_phase() first")
            return
            
        char_count = len(content)
        token_estimate = char_count // 4  # Rough estimate: 4 chars per token
        
        component = {
            "name": component_name,
            "chars": char_count,
            "tokens_estimate": token_estimate,
            "metadata": metadata or {}
        }
        
        self.current_phase["components"].append(component)
        self.current_phase["total_chars"] += char_count
        self.current_phase["estimated_tokens"] += token_estimate
        self.total_chars += char_count
        self.total_tokens_estimate += token_estimate
        
        logger.info(f"   📝 Added context: {component_name} ({char_count:,} chars, ~{token_estimate:,} tokens)")
        
    def end_phase(self):
        """End current phase and log summary"""
        if not self.current_phase:
            return
            
        duration = time.time() - self.current_phase["start_time"]
        self.current_phase["duration_seconds"] = duration
        
        logger.info(f"✅ Context Phase Complete: {self.current_phase['name']}")
        logger.info(f"   Total: {self.current_phase['total_chars']:,} chars, ~{self.current_phase['estimated_tokens']:,} tokens")
        logger.info(f"   Components: {len(self.current_phase['components'])}")
        
        self.phases.append(self.current_phase)
        self.current_phase = None
        
    def get_summary(self) -> dict:
        """Get summary of all context tracking
        
        Returns:
            Dictionary with context tracking summary
        """
        return {
            "total_phases": len(self.phases),
            "total_chars": self.total_chars,
            "total_tokens_estimate": self.total_tokens_estimate,
            "phases": [
                {
                    "name": p["name"],
                    "chars": p["total_chars"],
                    "tokens_estimate": p["estimated_tokens"],
                    "components": len(p["components"])
                }
                for p in self.phases
            ]
        }
        
    def detect_contradictions(self, new_instructions: str, existing_context: str) -> list:
        """Detect potential contradictions in prompts
        
        Args:
            new_instructions: New instructions being added
            existing_context: Existing context/instructions
            
        Returns:
            List of potential contradiction warnings
        """
        warnings = []
        
        # Check for conflicting directives
        conflicting_patterns = [
            (r"focus\s+only\s+on\s+(\w+)", r"also\s+analyze\s+(\w+)"),
            (r"ignore\s+(\w+)", r"include\s+(\w+)"),
            (r"skip\s+(\w+)", r"review\s+(\w+)"),
        ]
        
        new_lower = new_instructions.lower()
        existing_lower = existing_context.lower()
        
        for pattern1, pattern2 in conflicting_patterns:
            matches1 = re.findall(pattern1, existing_lower)
            matches2 = re.findall(pattern2, new_lower)
            
            # Check for overlapping terms
            overlap = set(matches1) & set(matches2)
            if overlap:
                warnings.append(f"Potential contradiction: existing context mentions '{pattern1}' while new instructions mention '{pattern2}' for: {overlap}")
        
        return warnings


class FindingSummarizer:
    """Summarize agent findings to pass distilled conclusions
    
    Feature: Discrete Sessions with Distilled Conclusions (Best Practice #1)
    This class extracts key insights from agent reports and creates concise
    summaries to pass between phases, preventing context contamination.
    """
    
    def __init__(self):
        """Initialize finding summarizer"""
        pass
        
    def summarize_findings(self, findings: list, max_findings: int = 10) -> str:
        """Summarize a list of findings into concise format
        
        Args:
            findings: List of finding dictionaries
            max_findings: Maximum number of findings to include in detail
            
        Returns:
            Concise summary string
        """
        if not findings:
            return "No significant findings."
            
        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        category_counts = {}
        
        for finding in findings:
            severity = finding.get("severity", "low")
            category = finding.get("category", "unknown")
            
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            category_counts[category] = category_counts.get(category, 0) + 1
        
        # Build summary
        summary_parts = []
        
        # Overall stats
        summary_parts.append(f"**Summary**: {len(findings)} total findings")
        summary_parts.append(f"- Critical: {severity_counts['critical']}, High: {severity_counts['high']}, Medium: {severity_counts['medium']}, Low: {severity_counts['low']}")
        
        # Category breakdown
        if category_counts:
            category_str = ", ".join([f"{cat}: {count}" for cat, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)])
            summary_parts.append(f"- Categories: {category_str}")
        
        # Top findings (critical and high only)
        top_findings = [f for f in findings if f.get("severity") in ["critical", "high"]]
        top_findings = sorted(top_findings, key=lambda x: 0 if x.get("severity") == "critical" else 1)[:max_findings]
        
        if top_findings:
            summary_parts.append("\n**Key Issues**:")
            for i, finding in enumerate(top_findings, 1):
                severity = finding.get("severity", "unknown").upper()
                message = finding.get("message", "No description")
                file_path = finding.get("file_path", "unknown")
                line = finding.get("line_number", "?")
                
                # Truncate long messages
                if len(message) > 100:
                    message = message[:97] + "..."
                
                summary_parts.append(f"{i}. [{severity}] {message} (`{file_path}:{line}`)")
        
        return "\n".join(summary_parts)
        
    def summarize_report(self, report_text: str, max_length: int = 1000) -> str:
        """Summarize a full report text into key points
        
        Args:
            report_text: Full report text
            max_length: Maximum character length for summary
            
        Returns:
            Concise summary of the report
        """
        # Extract key sections
        lines = report_text.split("\n")
        
        key_points = []
        in_summary = False
        in_critical = False
        
        for line in lines:
            line_lower = line.lower().strip()
            
            # Capture summary sections
            if "summary" in line_lower or "executive summary" in line_lower:
                in_summary = True
                continue
            elif "critical" in line_lower and ("issue" in line_lower or "finding" in line_lower):
                in_critical = True
                in_summary = False
                continue
            elif line.startswith("#") and not line.startswith("###"):
                in_summary = False
                in_critical = False
                
            # Collect important lines
            if in_summary or in_critical:
                if line.strip() and not line.startswith("#"):
                    key_points.append(line.strip())
                    
            # Stop if we have enough
            if len("\n".join(key_points)) > max_length:
                break
        
        if not key_points:
            # Fallback: take first N chars
            return report_text[:max_length] + "..." if len(report_text) > max_length else report_text
        
        summary = "\n".join(key_points)
        if len(summary) > max_length:
            summary = summary[:max_length] + "..."
            
        return summary


class AgentOutputValidator:
    """Validate agent output format and relevance
    
    Feature: Agent Output Validation (Best Practice - Medium Priority)
    This class checks agent outputs after generation to ensure they're
    properly formatted and relevant, catching issues early.
    """
    
    def __init__(self):
        """Initialize output validator"""
        self.validation_history = []
        
    def validate_output(self, agent_name: str, output: str, expected_sections: list = None) -> dict:
        """Validate agent output format and content
        
        Args:
            agent_name: Name of the agent that produced output
            output: The output text to validate
            expected_sections: List of expected section headers
            
        Returns:
            Dictionary with validation results
        """
        validation = {
            "agent": agent_name,
            "timestamp": time.time(),
            "valid": True,
            "warnings": [],
            "errors": [],
            "metrics": {}
        }
        
        # Check minimum length
        if len(output) < 100:
            validation["errors"].append("Output too short (< 100 chars)")
            validation["valid"] = False
        
        # Check for expected sections
        if expected_sections:
            missing_sections = []
            for section in expected_sections:
                if section.lower() not in output.lower():
                    missing_sections.append(section)
            
            if missing_sections:
                validation["warnings"].append(f"Missing sections: {', '.join(missing_sections)}")
        
        # Check for markdown formatting
        if output.count("#") < 2:
            validation["warnings"].append("Minimal markdown structure (< 2 headers)")
        
        # Check for code references (file:line format)
        code_refs = re.findall(r'`[^`]+\.\w+:\d+`', output)
        validation["metrics"]["code_references"] = len(code_refs)
        
        if len(code_refs) == 0:
            validation["warnings"].append("No code references found (expected file:line format)")
        
        # Check for severity markers
        severity_markers = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        severity_counts = {marker: output.upper().count(marker) for marker in severity_markers}
        validation["metrics"]["severity_markers"] = severity_counts
        
        total_severity = sum(severity_counts.values())
        if total_severity == 0:
            validation["warnings"].append("No severity markers found")
        
        # Check for empty findings (agent found nothing)
        empty_indicators = [
            "no issues found",
            "no findings",
            "no problems detected",
            "0 issues",
            "clean codebase"
        ]
        
        is_empty = any(indicator in output.lower() for indicator in empty_indicators)
        validation["metrics"]["appears_empty"] = is_empty
        
        # Check for generic/template responses
        template_indicators = [
            "[insert",
            "[add",
            "[describe",
            "TODO:",
            "FIXME:",
            "placeholder"
        ]
        
        has_templates = any(indicator in output.lower() for indicator in template_indicators)
        if has_templates:
            validation["warnings"].append("Output contains template placeholders")
        
        # Store validation history
        self.validation_history.append(validation)
        
        return validation
        
    def should_retry(self, validation: dict) -> bool:
        """Determine if agent should retry based on validation
        
        Args:
            validation: Validation result dictionary
            
        Returns:
            True if agent should retry
        """
        # Retry if there are errors
        if validation["errors"]:
            return True
        
        # Retry if output appears to be a template
        if any("template" in w.lower() for w in validation["warnings"]):
            return True
        
        return False
        
    def get_validation_summary(self) -> dict:
        """Get summary of all validations
        
        Returns:
            Summary dictionary
        """
        if not self.validation_history:
            return {"total": 0}
        
        total = len(self.validation_history)
        valid = sum(1 for v in self.validation_history if v["valid"])
        
        return {
            "total_validations": total,
            "valid_outputs": valid,
            "invalid_outputs": total - valid,
            "total_warnings": sum(len(v["warnings"]) for v in self.validation_history),
            "total_errors": sum(len(v["errors"]) for v in self.validation_history)
        }


class TimeoutManager:
    """Manage timeouts for agent execution
    
    Feature: Timeout Limits (Best Practice - Medium Priority)
    This class enforces time limits on agent execution to prevent
    runaway processes and ensure timely completion.
    """
    
    def __init__(self, default_timeout: int = 300):
        """Initialize timeout manager
        
        Args:
            default_timeout: Default timeout in seconds (default: 5 minutes)
        """
        self.default_timeout = default_timeout
        self.agent_timeouts = {}
        self.execution_history = []
        
    def set_agent_timeout(self, agent_name: str, timeout: int):
        """Set custom timeout for specific agent
        
        Args:
            agent_name: Name of the agent
            timeout: Timeout in seconds
        """
        self.agent_timeouts[agent_name] = timeout
        
    def get_timeout(self, agent_name: str) -> int:
        """Get timeout for agent
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Timeout in seconds
        """
        return self.agent_timeouts.get(agent_name, self.default_timeout)
        
    def check_timeout(self, agent_name: str, start_time: float) -> tuple:
        """Check if agent has exceeded timeout
        
        Args:
            agent_name: Name of the agent
            start_time: Start time (from time.time())
            
        Returns:
            Tuple of (exceeded: bool, elapsed: float, remaining: float)
        """
        elapsed = time.time() - start_time
        timeout = self.get_timeout(agent_name)
        remaining = timeout - elapsed
        exceeded = elapsed > timeout
        
        return exceeded, elapsed, remaining
        
    def record_execution(self, agent_name: str, duration: float, completed: bool):
        """Record agent execution for monitoring
        
        Args:
            agent_name: Name of the agent
            duration: Execution duration in seconds
            completed: Whether agent completed successfully
        """
        self.execution_history.append({
            "agent": agent_name,
            "duration": duration,
            "completed": completed,
            "timeout": self.get_timeout(agent_name),
            "exceeded_timeout": duration > self.get_timeout(agent_name),
            "timestamp": time.time()
        })
        
    def get_summary(self) -> dict:
        """Get execution summary
        
        Returns:
            Summary dictionary
        """
        if not self.execution_history:
            return {"total_executions": 0}
        
        total = len(self.execution_history)
        completed = sum(1 for e in self.execution_history if e["completed"])
        timeouts = sum(1 for e in self.execution_history if e["exceeded_timeout"])
        
        return {
            "total_executions": total,
            "completed": completed,
            "timeout_exceeded": timeouts,
            "avg_duration": sum(e["duration"] for e in self.execution_history) / total,
            "max_duration": max(e["duration"] for e in self.execution_history)
        }


class CodebaseChunker:
    """Chunk codebase context intelligently
    
    Feature: Chunk Codebase Context (Best Practice - Low Priority)
    This class breaks large codebases into manageable chunks based on
    file relationships, size, and priority.
    """
    
    def __init__(self, max_chunk_size: int = 50000):
        """Initialize codebase chunker
        
        Args:
            max_chunk_size: Maximum characters per chunk (default: 50K)
        """
        self.max_chunk_size = max_chunk_size
        
    def chunk_files(self, files: list, priority_files: list = None) -> list:
        """Chunk files into manageable groups
        
        Args:
            files: List of file dictionaries with 'path' and 'content'
            priority_files: List of priority file paths
            
        Returns:
            List of chunks, each containing related files
        """
        chunks = []
        current_chunk = {"files": [], "size": 0, "priority": False}
        
        # Sort files: priority first, then by size
        priority_set = set(priority_files or [])
        sorted_files = sorted(
            files,
            key=lambda f: (f['path'] not in priority_set, len(f.get('content', '')))
        )
        
        for file_info in sorted_files:
            file_size = len(file_info.get('content', ''))
            
            # If adding this file would exceed chunk size, start new chunk
            if current_chunk["size"] + file_size > self.max_chunk_size and current_chunk["files"]:
                chunks.append(current_chunk)
                current_chunk = {"files": [], "size": 0, "priority": False}
            
            # Add file to current chunk
            current_chunk["files"].append(file_info)
            current_chunk["size"] += file_size
            
            # Mark chunk as priority if it contains priority files
            if file_info['path'] in priority_set:
                current_chunk["priority"] = True
        
        # Add last chunk
        if current_chunk["files"]:
            chunks.append(current_chunk)
        
        return chunks
        
    def get_chunk_summary(self, chunks: list) -> dict:
        """Get summary of chunks
        
        Args:
            chunks: List of chunks
            
        Returns:
            Summary dictionary
        """
        return {
            "total_chunks": len(chunks),
            "priority_chunks": sum(1 for c in chunks if c.get("priority")),
            "total_files": sum(len(c["files"]) for c in chunks),
            "total_size": sum(c["size"] for c in chunks),
            "avg_chunk_size": sum(c["size"] for c in chunks) / len(chunks) if chunks else 0,
            "max_chunk_size": max(c["size"] for c in chunks) if chunks else 0
        }


class ContextCleanup:
    """Clean up and deduplicate context
    
    Feature: Context Cleanup Utilities (Best Practice - Low Priority)
    This class removes redundant information from context to reduce
    token usage and improve focus.
    """
    
    def __init__(self):
        """Initialize context cleanup"""
        pass
        
    def remove_duplicates(self, text: str) -> str:
        """Remove duplicate lines from text
        
        Args:
            text: Input text
            
        Returns:
            Text with duplicates removed
        """
        lines = text.split('\n')
        seen = set()
        unique_lines = []
        
        for line in lines:
            # Keep empty lines and headers
            if not line.strip() or line.strip().startswith('#'):
                unique_lines.append(line)
                continue
            
            # Remove duplicate content lines
            if line not in seen:
                seen.add(line)
                unique_lines.append(line)
        
        return '\n'.join(unique_lines)
        
    def compress_whitespace(self, text: str) -> str:
        """Compress excessive whitespace
        
        Args:
            text: Input text
            
        Returns:
            Text with compressed whitespace
        """
        # Replace multiple blank lines with max 2
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        # Remove trailing whitespace
        lines = [line.rstrip() for line in text.split('\n')]
        
        return '\n'.join(lines)
        
    def remove_comments(self, text: str, language: str = None) -> str:
        """Remove code comments to reduce token usage
        
        Args:
            text: Input text
            language: Programming language (for language-specific comment removal)
            
        Returns:
            Text with comments removed
        """
        # Generic comment removal (works for most languages)
        # Remove single-line comments
        text = re.sub(r'//.*$', '', text, flags=re.MULTILINE)
        text = re.sub(r'#.*$', '', text, flags=re.MULTILINE)
        
        # Remove multi-line comments (/* */ style)
        text = re.sub(r'/\*.*?\*/', '', text, flags=re.DOTALL)
        
        return text
        
    def extract_signatures_only(self, code: str, language: str = 'python') -> str:
        """Extract only function/class signatures, removing implementation
        
        Args:
            code: Source code
            language: Programming language
            
        Returns:
            Code with only signatures
        """
        if language == 'python':
            # Extract class and function definitions
            lines = code.split('\n')
            signatures = []
            
            for line in lines:
                stripped = line.strip()
                if stripped.startswith('class ') or stripped.startswith('def ') or stripped.startswith('async def '):
                    signatures.append(line)
                elif stripped.startswith('@'):  # decorators
                    signatures.append(line)
            
            return '\n'.join(signatures)
        
        # For other languages, return as-is for now
        return code
        
    def cleanup_context(self, context: str, aggressive: bool = False) -> tuple:
        """Clean up context with multiple strategies
        
        Args:
            context: Input context
            aggressive: If True, use more aggressive cleanup (may lose info)
            
        Returns:
            Tuple of (cleaned_context, reduction_percentage)
        """
        original_size = len(context)
        
        # Always apply these
        context = self.compress_whitespace(context)
        context = self.remove_duplicates(context)
        
        if aggressive:
            # More aggressive cleanup
            context = self.remove_comments(context)
        
        cleaned_size = len(context)
        reduction = ((original_size - cleaned_size) / original_size * 100) if original_size > 0 else 0
        
        return context, reduction


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


class CostLimitExceededError(Exception):
    """Raised when cost limit would be exceeded by an operation"""
    pass


# Alias for backwards compatibility
CostLimitExceeded = CostLimitExceededError
