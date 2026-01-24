#!/usr/bin/env python3
"""
I/O Utilities for Argus
Safe file operations with validation for JSON, SARIF, and Markdown.

This module provides standardized I/O operations to eliminate duplicate
JSON/SARIF reading/writing code across scripts.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class IOError(Exception):
    """Custom exception for I/O operations"""
    pass


class SafeIO:
    """Safe I/O operations with validation and error handling"""

    @staticmethod
    def read_json(
        file_path: Union[str, Path],
        validate_schema: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Read and validate JSON file

        Args:
            file_path: Path to JSON file
            validate_schema: Optional validation function (e.g., Pydantic model)

        Returns:
            Parsed JSON data

        Raises:
            FileNotFoundError: If file doesn't exist
            json.JSONDecodeError: If invalid JSON
            ValidationError: If schema validation fails

        Example:
            data = SafeIO.read_json("findings.json")
            data = SafeIO.read_json("config.json", validate_schema=ConfigModel)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Validate against schema if provided
            if validate_schema:
                if callable(validate_schema):
                    validate_schema(**data)  # Pydantic model validation
                else:
                    raise ValueError("validate_schema must be callable")

            logger.debug(f"Successfully read JSON from {file_path}")
            return data

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in {file_path}: {e}")
            raise

        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            raise IOError(f"Failed to read {file_path}: {e}") from e

    @staticmethod
    def write_json(
        file_path: Union[str, Path],
        data: Union[Dict, List],
        indent: int = 2,
        sort_keys: bool = True,
        ensure_ascii: bool = False
    ) -> None:
        """
        Write JSON file with formatting

        Args:
            file_path: Path to output file
            data: Data to write (dict or list)
            indent: Indentation level (default: 2)
            sort_keys: Sort dictionary keys (default: True)
            ensure_ascii: Escape non-ASCII characters (default: False)

        Raises:
            IOError: If write fails

        Example:
            SafeIO.write_json("output.json", {"findings": [...]})
        """
        file_path = Path(file_path)

        try:
            # Create parent directory if it doesn't exist
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(
                    data,
                    f,
                    indent=indent,
                    sort_keys=sort_keys,
                    ensure_ascii=ensure_ascii
                )

            logger.debug(f"Successfully wrote JSON to {file_path}")

        except Exception as e:
            logger.error(f"Failed to write {file_path}: {e}")
            raise IOError(f"Failed to write {file_path}: {e}") from e

    @staticmethod
    def read_sarif(file_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Read and validate SARIF file

        Args:
            file_path: Path to SARIF file

        Returns:
            Parsed SARIF data

        Raises:
            IOError: If file is invalid SARIF format

        Example:
            sarif = SafeIO.read_sarif("semgrep-results.sarif")
        """
        data = SafeIO.read_json(file_path)

        # Validate SARIF structure
        if not isinstance(data, dict):
            raise IOError(f"Invalid SARIF format: root must be object")

        if "version" not in data:
            raise IOError(f"Invalid SARIF format: missing 'version' field")

        if "runs" not in data or not isinstance(data["runs"], list):
            raise IOError(f"Invalid SARIF format: missing or invalid 'runs' field")

        logger.debug(f"Successfully read SARIF from {file_path} ({len(data['runs'])} runs)")
        return data

    @staticmethod
    def write_sarif(
        file_path: Union[str, Path],
        runs: List[Dict],
        tool_name: str = "argus",
        tool_version: str = "1.0.0"
    ) -> None:
        """
        Write SARIF file with proper structure

        Args:
            file_path: Path to output file
            runs: List of SARIF run objects
            tool_name: Name of the tool (default: "argus")
            tool_version: Version of the tool (default: "1.0.0")

        Example:
            SafeIO.write_sarif("results.sarif", runs=[...])
        """
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": runs
        }

        SafeIO.write_json(file_path, sarif_data, sort_keys=False)
        logger.info(f"Wrote SARIF with {len(runs)} run(s) to {file_path}")

    @staticmethod
    def merge_sarif_files(
        sarif_files: List[Union[str, Path]],
        output_file: Optional[Union[str, Path]] = None
    ) -> Dict[str, Any]:
        """
        Merge multiple SARIF files into one

        Args:
            sarif_files: List of SARIF file paths to merge
            output_file: Optional output file path

        Returns:
            Merged SARIF data

        Example:
            merged = SafeIO.merge_sarif_files(
                ["semgrep.sarif", "trivy.sarif"],
                "combined.sarif"
            )
        """
        merged = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": []
        }

        for file_path in sarif_files:
            try:
                sarif = SafeIO.read_sarif(file_path)
                merged["runs"].extend(sarif["runs"])
                logger.debug(f"Merged {len(sarif['runs'])} runs from {file_path}")
            except Exception as e:
                logger.warning(f"Failed to merge {file_path}: {e}")

        logger.info(
            f"Merged {len(sarif_files)} SARIF files into {len(merged['runs'])} runs"
        )

        if output_file:
            SafeIO.write_json(output_file, merged, sort_keys=False)

        return merged

    @staticmethod
    def read_lines(
        file_path: Union[str, Path],
        strip: bool = True,
        skip_empty: bool = False
    ) -> List[str]:
        """
        Read file as list of lines

        Args:
            file_path: Path to file
            strip: Strip whitespace from lines (default: True)
            skip_empty: Skip empty lines (default: False)

        Returns:
            List of lines

        Example:
            lines = SafeIO.read_lines("requirements.txt", skip_empty=True)
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            if strip:
                lines = [line.strip() for line in lines]

            if skip_empty:
                lines = [line for line in lines if line]

            return lines

        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            raise IOError(f"Failed to read {file_path}: {e}") from e

    @staticmethod
    def write_lines(
        file_path: Union[str, Path],
        lines: List[str],
        append: bool = False
    ) -> None:
        """
        Write list of lines to file

        Args:
            file_path: Path to output file
            lines: List of lines to write
            append: Append to file instead of overwriting (default: False)

        Example:
            SafeIO.write_lines("output.txt", ["line 1", "line 2"])
        """
        file_path = Path(file_path)
        mode = 'a' if append else 'w'

        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, mode, encoding='utf-8') as f:
                for line in lines:
                    f.write(f"{line}\n")

            logger.debug(f"Successfully wrote {len(lines)} lines to {file_path}")

        except Exception as e:
            logger.error(f"Failed to write {file_path}: {e}")
            raise IOError(f"Failed to write {file_path}: {e}") from e


class MarkdownGenerator:
    """Generate formatted Markdown reports"""

    def __init__(self, title: str):
        """
        Initialize Markdown generator

        Args:
            title: Report title
        """
        self.title = title
        self.sections: List[str] = []

    def add_header(self, text: str, level: int = 1) -> None:
        """
        Add header to report

        Args:
            text: Header text
            level: Header level (1-6)
        """
        self.sections.append(f"{'#' * level} {text}\n")

    def add_paragraph(self, text: str) -> None:
        """Add paragraph to report"""
        self.sections.append(f"{text}\n")

    def add_list(self, items: List[str], ordered: bool = False) -> None:
        """
        Add list to report

        Args:
            items: List items
            ordered: Use numbered list (default: False)
        """
        for i, item in enumerate(items, 1):
            prefix = f"{i}. " if ordered else "- "
            self.sections.append(f"{prefix}{item}\n")
        self.sections.append("\n")

    def add_table(self, headers: List[str], rows: List[List[str]]) -> None:
        """
        Add table to report

        Args:
            headers: Table headers
            rows: Table rows (list of lists)

        Example:
            gen.add_table(
                ["Name", "Value"],
                [["Key1", "Value1"], ["Key2", "Value2"]]
            )
        """
        # Header row
        self.sections.append(f"| {' | '.join(headers)} |\n")

        # Separator
        self.sections.append(f"| {' | '.join(['---'] * len(headers))} |\n")

        # Data rows
        for row in rows:
            self.sections.append(f"| {' | '.join(str(cell) for cell in row)} |\n")

        self.sections.append("\n")

    def add_code_block(self, code: str, language: str = "") -> None:
        """
        Add code block to report

        Args:
            code: Code content
            language: Language identifier for syntax highlighting
        """
        self.sections.append(f"```{language}\n{code}\n```\n\n")

    def add_horizontal_rule(self) -> None:
        """Add horizontal rule"""
        self.sections.append("---\n\n")

    def generate(self) -> str:
        """
        Generate complete Markdown document

        Returns:
            Formatted Markdown string
        """
        output = [f"# {self.title}\n\n"]
        output.append(f"*Generated: {datetime.utcnow().isoformat()}Z*\n\n")
        output.extend(self.sections)
        return "".join(output)

    def save(self, file_path: Union[str, Path]) -> None:
        """
        Save Markdown to file

        Args:
            file_path: Output file path
        """
        content = self.generate()
        SafeIO.write_lines(file_path, content.splitlines())
        logger.info(f"Saved Markdown report to {file_path}")


def validate_path_safe(file_path: Union[str, Path], base_dir: Optional[Path] = None) -> Path:
    """
    Validate file path is safe (prevent path traversal)

    Args:
        file_path: Path to validate
        base_dir: Base directory to restrict to (optional)

    Returns:
        Validated Path object

    Raises:
        ValueError: If path is unsafe

    Example:
        safe_path = validate_path_safe("../../etc/passwd", base_dir=Path("/tmp"))
        # Raises ValueError
    """
    file_path = Path(file_path).resolve()

    if base_dir:
        base_dir = base_dir.resolve()
        if not str(file_path).startswith(str(base_dir)):
            raise ValueError(
                f"Path {file_path} is outside base directory {base_dir}"
            )

    return file_path
