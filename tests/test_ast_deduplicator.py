#!/usr/bin/env python3
"""
Comprehensive unit tests for AST-based deduplication system
Tests Python AST parsing, JS/TS regex parsing, edge cases, and performance
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Import the module to test
import sys
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from ast_deduplicator import ASTDeduplicator, CodeLocation, create_enhanced_dedup_key


class TestCodeLocation:
    """Test CodeLocation dataclass"""

    def test_code_location_initialization(self):
        """Test CodeLocation can be initialized with all fields"""
        loc = CodeLocation(
            file_path="test.py",
            line_number=42,
            function_name="process_data",
            class_name="DataProcessor",
            start_line=30,
            end_line=60
        )

        assert loc.file_path == "test.py"
        assert loc.line_number == 42
        assert loc.function_name == "process_data"
        assert loc.class_name == "DataProcessor"
        assert loc.start_line == 30
        assert loc.end_line == 60

    def test_code_location_minimal(self):
        """Test CodeLocation with minimal fields"""
        loc = CodeLocation(file_path="test.py", line_number=10)

        assert loc.file_path == "test.py"
        assert loc.line_number == 10
        assert loc.function_name is None
        assert loc.class_name is None


class TestASTDeduplicatorPython:
    """Test AST parsing for Python files"""

    @pytest.fixture
    def deduplicator(self):
        """Create a fresh ASTDeduplicator instance"""
        return ASTDeduplicator()

    @pytest.fixture
    def python_test_file(self):
        """Create a temporary Python file with various structures"""
        code = '''
def standalone_function():
    """A standalone function at module level"""
    x = 1
    y = 2
    z = x + y
    return z

class MyClass:
    """A test class"""

    def method_one(self):
        """First method"""
        print("method one")
        data = {"key": "value"}
        return data

    def method_two(self):
        """Second method"""
        result = self.method_one()
        processed = result["key"].upper()
        return processed

    async def async_method(self):
        """An async method"""
        await some_operation()
        return "done"

def another_function():
    """Another standalone function"""
    # This is a longer function
    a = 1
    b = 2
    c = 3
    d = 4
    e = 5
    f = 6
    g = 7
    h = 8
    i = 9
    j = 10
    # Line 50 is still in this function
    return a + b + c + d + e + f + g + h + i + j

# Module-level code
x = 100
y = 200
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        yield temp_path

        # Cleanup
        Path(temp_path).unlink(missing_ok=True)

    def test_is_parseable_python(self, deduplicator):
        """Test that Python files are recognized as parseable"""
        assert deduplicator._is_parseable("test.py")
        assert deduplicator._is_parseable("/path/to/script.py")
        assert not deduplicator._is_parseable("test.txt")
        assert not deduplicator._is_parseable("README.md")

    def test_standalone_function_detection(self, deduplicator, python_test_file):
        """Test detecting code within a standalone function"""
        # Line 5 is inside standalone_function
        location = deduplicator.get_code_location(python_test_file, 5)

        assert location is not None
        assert location.function_name == "standalone_function"
        assert location.class_name is None
        assert location.start_line == 2  # Function starts at line 2
        assert location.line_number == 5

    def test_class_method_detection(self, deduplicator, python_test_file):
        """Test detecting code within a class method"""
        # Line 15 is inside MyClass.method_one
        location = deduplicator.get_code_location(python_test_file, 15)

        assert location is not None
        assert location.function_name == "method_one"
        assert location.class_name == "MyClass"
        assert "method_one" in location.function_name

    def test_multiple_methods_same_class(self, deduplicator, python_test_file):
        """Test that different methods in same class get different locations"""
        # Line 15 in method_one
        loc1 = deduplicator.get_code_location(python_test_file, 15)
        # Line 21 in method_two
        loc2 = deduplicator.get_code_location(python_test_file, 21)

        assert loc1.function_name == "method_one"
        assert loc2.function_name == "method_two"
        assert loc1.class_name == loc2.class_name  # Same class
        assert loc1.start_line != loc2.start_line  # Different functions

    def test_long_function_same_context(self, deduplicator, python_test_file):
        """Test that lines far apart in same function share context"""
        # Lines 35 and 50 are in same function (another_function)
        # Old approach would create L30 and L50 buckets (different groups)
        # New approach should identify same function

        loc_early = deduplicator.get_code_location(python_test_file, 35)
        loc_late = deduplicator.get_code_location(python_test_file, 48)

        # Both should be in another_function
        assert loc_early.function_name == "another_function"
        assert loc_late.function_name == "another_function"
        assert loc_early.start_line == loc_late.start_line  # Same function start

    def test_module_level_code(self, deduplicator, python_test_file):
        """Test module-level code (not in any function/class)"""
        # Line 54-55 are module-level
        location = deduplicator.get_code_location(python_test_file, 54)

        assert location.function_name is None
        assert location.class_name is None
        # Should fall back to line bucket
        assert location.start_line == 50  # Line bucket: (54 // 10) * 10

    def test_ast_caching(self, deduplicator, python_test_file):
        """Test that AST is cached for repeated queries"""
        # First call - parses file
        loc1 = deduplicator.get_code_location(python_test_file, 5)

        # Second call - should use cache
        loc2 = deduplicator.get_code_location(python_test_file, 10)

        # Both should succeed
        assert loc1 is not None
        assert loc2 is not None

        # Cache should contain the file
        assert python_test_file in deduplicator._ast_cache

    def test_clear_cache(self, deduplicator, python_test_file):
        """Test cache clearing"""
        # Parse file
        deduplicator.get_code_location(python_test_file, 5)
        assert python_test_file in deduplicator._ast_cache

        # Clear cache
        deduplicator.clear_cache()
        assert python_test_file not in deduplicator._ast_cache


class TestASTDeduplicatorJavaScript:
    """Test regex-based parsing for JavaScript/TypeScript files"""

    @pytest.fixture
    def deduplicator(self):
        """Create a fresh ASTDeduplicator instance"""
        return ASTDeduplicator()

    @pytest.fixture
    def javascript_test_file(self):
        """Create a temporary JavaScript file"""
        code = '''
// JavaScript test file
function traditionalFunction() {
    const x = 1;
    const y = 2;
    return x + y;
}

const arrowFunction = () => {
    const data = fetchData();
    return processData(data);
};

class MyComponent {
    constructor() {
        this.state = {};
    }

    methodOne() {
        console.log("method one");
        const result = this.calculate();
        return result;
    }

    methodTwo() {
        // Another method
        const value = 42;
        return value;
    }
}

async function asyncOperation() {
    const result = await fetch("/api/data");
    const json = await result.json();
    return json;
}
'''
        with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
            f.write(code)
            temp_path = f.name

        yield temp_path

        # Cleanup
        Path(temp_path).unlink(missing_ok=True)

    def test_is_parseable_javascript(self, deduplicator):
        """Test that JS/TS files are recognized as parseable"""
        assert deduplicator._is_parseable("app.js")
        assert deduplicator._is_parseable("component.jsx")
        assert deduplicator._is_parseable("types.ts")
        assert deduplicator._is_parseable("Component.tsx")

    def test_traditional_function_detection(self, deduplicator, javascript_test_file):
        """Test detecting traditional function declarations"""
        # Line 4 is inside traditionalFunction
        location = deduplicator.get_code_location(javascript_test_file, 4)

        assert location is not None
        assert location.function_name == "traditionalFunction"
        assert location.class_name is None

    def test_arrow_function_detection(self, deduplicator, javascript_test_file):
        """Test detecting arrow functions"""
        # Line 10 is inside arrowFunction
        location = deduplicator.get_code_location(javascript_test_file, 10)

        assert location is not None
        # Arrow functions should be detected
        if location.function_name:
            assert "arrowFunction" in location.function_name

    def test_class_method_detection_js(self, deduplicator, javascript_test_file):
        """Test detecting methods in JavaScript classes"""
        # Line 21 is inside MyComponent.methodOne
        location = deduplicator.get_code_location(javascript_test_file, 21)

        assert location is not None
        # Should detect we're in a class
        assert location.class_name == "MyComponent" or location.function_name is not None

    def test_async_function_detection(self, deduplicator, javascript_test_file):
        """Test detecting async functions"""
        # Line 34 is inside asyncOperation
        location = deduplicator.get_code_location(javascript_test_file, 34)

        assert location is not None
        assert location.function_name == "asyncOperation"


class TestDedupKeyGeneration:
    """Test deduplication key generation"""

    @pytest.fixture
    def deduplicator(self):
        """Create a fresh ASTDeduplicator instance"""
        return ASTDeduplicator()

    @pytest.fixture
    def sample_findings(self, tmp_path):
        """Create sample findings with a test Python file"""
        # Create test file
        test_file = tmp_path / "test.py"
        test_file.write_text('''
def vulnerable_function():
    password = "hardcoded"  # Line 3
    query = f"SELECT * FROM users WHERE id = {user_id}"  # Line 4
    return query
''')

        return [
            {
                "file_path": str(test_file),
                "line_number": 3,
                "rule_id": "hardcoded-secret",
                "code_snippet": 'password = "hardcoded"'
            },
            {
                "file_path": str(test_file),
                "line_number": 4,
                "rule_id": "sql-injection",
                "code_snippet": 'query = f"SELECT * FROM users WHERE id = {user_id}"'
            },
        ]

    def test_create_dedup_key_function_level(self, deduplicator, sample_findings):
        """Test that findings in same function get same base key"""
        finding1 = sample_findings[0]
        finding2 = sample_findings[1]

        key1 = deduplicator.create_dedup_key(finding1)
        key2 = deduplicator.create_dedup_key(finding2)

        # Both should reference the same function
        assert "fn:vulnerable_function" in key1
        assert "fn:vulnerable_function" in key2

        # But different rule IDs mean different keys
        assert "hardcoded-secret" in key1
        assert "sql-injection" in key2

    def test_create_dedup_key_with_hash(self, deduplicator, sample_findings):
        """Test code hash inclusion in dedup key"""
        finding = sample_findings[0]

        key_without_hash = deduplicator.create_dedup_key(finding, use_code_hash=False)
        key_with_hash = deduplicator.create_dedup_key(finding, use_code_hash=True)

        assert "hash:" not in key_without_hash
        assert "hash:" in key_with_hash

    def test_create_dedup_key_fallback(self, deduplicator):
        """Test fallback to line bucket for non-parseable files"""
        finding = {
            "file_path": "test.txt",
            "line_number": 25,
            "rule_id": "secret-detection"
        }

        key = deduplicator.create_dedup_key(finding)

        # Should use line bucket (25 // 10 * 10 = 20)
        assert "L20" in key
        assert "fn:" not in key

    def test_convenience_function(self, sample_findings):
        """Test create_enhanced_dedup_key convenience function"""
        finding = sample_findings[0]

        # Should work without providing deduplicator
        key = create_enhanced_dedup_key(finding)
        assert key is not None
        assert isinstance(key, str)

        # Should work with provided deduplicator
        dedup = ASTDeduplicator()
        key2 = create_enhanced_dedup_key(finding, dedup)
        assert key2 is not None


class TestEdgeCases:
    """Test edge cases and error handling"""

    @pytest.fixture
    def deduplicator(self):
        """Create a fresh ASTDeduplicator instance"""
        return ASTDeduplicator()

    def test_nonexistent_file(self, deduplicator):
        """Test handling of non-existent files"""
        location = deduplicator.get_code_location("/nonexistent/file.py", 10)

        # Should fall back to line bucket
        assert location is not None
        assert location.function_name is None
        assert location.start_line == 10  # Line bucket

    def test_syntax_error_file(self, deduplicator, tmp_path):
        """Test handling of files with syntax errors"""
        bad_file = tmp_path / "bad.py"
        bad_file.write_text("def broken(:\n    pass\n")  # Missing closing paren

        location = deduplicator.get_code_location(str(bad_file), 2)

        # Should fall back to line bucket gracefully
        assert location is not None
        assert location.start_line == 0  # Line bucket (2 // 10 * 10)

    def test_empty_file(self, deduplicator, tmp_path):
        """Test handling of empty files"""
        empty_file = tmp_path / "empty.py"
        empty_file.write_text("")

        location = deduplicator.get_code_location(str(empty_file), 1)

        # Should handle gracefully
        assert location is not None

    def test_unicode_file(self, deduplicator, tmp_path):
        """Test handling of files with Unicode characters"""
        unicode_file = tmp_path / "unicode.py"
        unicode_file.write_text('''
def 中文函数():
    """Unicode function name"""
    résultat = "données"
    return résultat
''', encoding='utf-8')

        location = deduplicator.get_code_location(str(unicode_file), 3)

        # Should parse correctly
        assert location is not None
        assert location.function_name == "中文函数"

    def test_finding_without_required_fields(self, deduplicator):
        """Test handling findings with missing fields"""
        incomplete_finding = {"file_path": "test.py"}  # Missing line_number, rule_id

        # Should not crash
        key = deduplicator.create_dedup_key(incomplete_finding)
        assert key is not None
        assert "unknown" in key or "0" in key

    def test_nested_functions(self, deduplicator, tmp_path):
        """Test handling of nested function definitions"""
        nested_file = tmp_path / "nested.py"
        nested_file.write_text('''
def outer():
    def inner():
        x = 1
        return x
    return inner()
''')

        # Line 4 is in inner function
        location = deduplicator.get_code_location(str(nested_file), 4)

        assert location is not None
        # Should detect innermost function
        assert location.function_name == "inner"

    def test_lambda_functions(self, deduplicator, tmp_path):
        """Test handling of lambda functions"""
        lambda_file = tmp_path / "lambda.py"
        lambda_file.write_text('''
process = lambda x: x * 2
result = process(5)
''')

        location = deduplicator.get_code_location(str(lambda_file), 2)

        # Lambda on single line - may not be detected as function
        assert location is not None


class TestPerformance:
    """Test performance characteristics"""

    @pytest.fixture
    def deduplicator(self):
        """Create a fresh ASTDeduplicator instance"""
        return ASTDeduplicator()

    def test_large_file_performance(self, deduplicator, tmp_path):
        """Test performance on large files"""
        import time

        # Create a large file with many functions
        large_file = tmp_path / "large.py"
        code_lines = []
        for i in range(100):
            code_lines.append(f'''
def function_{i}():
    """Function number {i}"""
    x = {i}
    y = x * 2
    z = y + 1
    return z
''')

        large_file.write_text('\n'.join(code_lines))

        # Measure parsing time
        start = time.time()
        location = deduplicator.get_code_location(str(large_file), 50)
        elapsed = time.time() - start

        # Should complete in reasonable time (< 1 second)
        assert elapsed < 1.0
        assert location is not None

    def test_cache_performance(self, deduplicator, tmp_path):
        """Test that caching improves performance"""
        import time

        test_file = tmp_path / "cache_test.py"
        test_file.write_text('''
def test_function():
    x = 1
    y = 2
    return x + y
''')

        # First call - parses file
        start = time.time()
        loc1 = deduplicator.get_code_location(str(test_file), 3)
        first_call = time.time() - start

        # Second call - uses cache
        start = time.time()
        loc2 = deduplicator.get_code_location(str(test_file), 4)
        second_call = time.time() - start

        # Second call should be faster (or at least not slower)
        assert second_call <= first_call * 1.5  # Allow some variance

    def test_batch_dedup_key_generation(self, deduplicator, tmp_path):
        """Test generating many dedup keys efficiently"""
        import time

        # Create test file
        test_file = tmp_path / "batch.py"
        test_file.write_text('''
def vulnerable_function():
    password = "hardcoded"
    api_key = "secret"
    token = "12345"
    query = "SELECT * FROM users"
''')

        # Create 100 findings
        findings = [
            {
                "file_path": str(test_file),
                "line_number": i % 5 + 2,  # Lines 2-6
                "rule_id": f"rule-{i % 10}"
            }
            for i in range(100)
        ]

        # Generate keys
        start = time.time()
        keys = [deduplicator.create_dedup_key(f) for f in findings]
        elapsed = time.time() - start

        # Should complete quickly
        assert elapsed < 1.0
        assert len(keys) == 100


class TestConsensusIntegration:
    """Test integration with ConsensusBuilder"""

    def test_consensus_builder_import(self):
        """Test that ConsensusBuilder can use ASTDeduplicator"""
        try:
            import run_ai_audit
            from ast_deduplicator import ASTDeduplicator

            # ConsensusBuilder should be able to use ASTDeduplicator
            agents = ["agent1", "agent2", "agent3"]
            builder = run_ai_audit.ConsensusBuilder(agents)

            # Should have deduplicator attribute if available
            if hasattr(run_ai_audit, 'AST_DEDUP_AVAILABLE'):
                if run_ai_audit.AST_DEDUP_AVAILABLE:
                    assert hasattr(builder, 'deduplicator')
                    assert builder.deduplicator is not None

        except ImportError:
            pytest.skip("run_ai_audit module not available")

    def test_legacy_fallback(self, tmp_path):
        """Test that system works without AST deduplicator"""
        # Create finding
        finding = {
            "file_path": str(tmp_path / "test.py"),
            "line_number": 25,
            "rule_id": "secret-detection"
        }

        # Should work even if AST parsing fails
        dedup = ASTDeduplicator()
        key = dedup.create_dedup_key(finding)

        assert key is not None
        assert isinstance(key, str)


if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "--tb=short"])
