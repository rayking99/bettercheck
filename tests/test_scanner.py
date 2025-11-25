# tests/test_scanner.py
import pytest
from pathlib import Path
from bettercheck.scanner import SecurityScanner, SecurityFinding, scan_directory


class TestSecurityScanner:
    @pytest.fixture
    def scanner(self):
        return SecurityScanner()
    
    def test_scanner_initialization(self, scanner):
        assert scanner.patterns is not None
        assert len(scanner.patterns) > 0
    
    def test_check_patterns_ssl_disabled(self, scanner):
        lines = ['requests.get(url, verify=False)']
        findings = scanner._check_patterns(lines)
        
        assert len(findings) >= 1
        ssl_finding = next((f for f in findings if "SSL" in f.risk), None)
        assert ssl_finding is not None
        assert ssl_finding.severity == "CRITICAL"
    
    def test_check_patterns_command_injection(self, scanner):
        lines = ['os.system("rm -rf /")']
        findings = scanner._check_patterns(lines)
        
        assert len(findings) >= 1
        cmd_finding = next((f for f in findings if "Command" in f.risk), None)
        assert cmd_finding is not None
    
    def test_check_patterns_eval_exec(self, scanner):
        lines = ['eval(user_input)', 'exec(code)']
        findings = scanner._check_patterns(lines)
        
        exec_findings = [f for f in findings if "Code Execution" in f.risk]
        assert len(exec_findings) >= 1
    
    def test_check_patterns_hardcoded_credentials(self, scanner):
        lines = ['password = "secret123"', 'api_key = "abc123xyz"']
        findings = scanner._check_patterns(lines)
        
        cred_findings = [f for f in findings if "Hardcoded Credentials" in f.risk]
        assert len(cred_findings) >= 1
    
    def test_check_patterns_weak_hash(self, scanner):
        lines = ['hashlib.md5(data)', 'hashlib.sha1(password)']
        findings = scanner._check_patterns(lines)
        
        hash_findings = [f for f in findings if "Weak Cryptographic Hash" in f.risk]
        assert len(hash_findings) >= 1
    
    def test_check_patterns_yaml_unsafe(self, scanner):
        lines = ['yaml.load(data)']
        findings = scanner._check_patterns(lines)
        
        yaml_findings = [f for f in findings if "YAML" in f.risk]
        assert len(yaml_findings) >= 1
    
    def test_check_ast_patterns(self, scanner):
        content = '''
import pickle
data = pickle.loads(user_data)
'''
        lines = content.split('\n')
        findings = scanner._check_ast_patterns(content, lines)
        
        # Should detect pickle.loads as insecure deserialization
        pickle_findings = [f for f in findings if "Deserialization" in f.risk]
        assert len(pickle_findings) >= 1
    
    def test_check_semantic_patterns(self, scanner):
        content = '''
import os
import subprocess
import pickle
import requests

os.system("ls")
'''
        findings = scanner._check_semantic_patterns(content)
        
        # Should detect dangerous import combinations
        assert len(findings) >= 1


class TestSecurityFinding:
    def test_finding_creation(self):
        finding = SecurityFinding(
            risk="Test Risk",
            severity="HIGH",
            line_number=10,
            context="test code",
            recommendation="Fix it"
        )
        
        assert finding.risk == "Test Risk"
        assert finding.severity == "HIGH"
        assert finding.line_number == 10
    
    def test_finding_str(self):
        finding = SecurityFinding(
            risk="SQL Injection",
            severity="CRITICAL",
            line_number=42,
            context="query = 'SELECT * FROM users WHERE id=' + user_id",
            recommendation="Use parameterized queries"
        )
        
        result = str(finding)
        assert "Line 42" in result
        assert "SQL Injection" in result
        assert "CRITICAL" in result


class TestScanDirectory:
    def test_scan_empty_directory(self, tmp_path):
        results = scan_directory(tmp_path)
        assert results == {}
    
    def test_scan_directory_with_python_file(self, tmp_path):
        # Create a Python file with a vulnerability
        py_file = tmp_path / "test.py"
        py_file.write_text('password = "secret123"\n')
        
        results = scan_directory(tmp_path)
        
        assert len(results) == 1
        assert str(py_file) in results
        assert len(results[str(py_file)]) >= 1
    
    def test_scan_directory_ignores_non_python(self, tmp_path):
        # Create a non-Python file
        txt_file = tmp_path / "test.txt"
        txt_file.write_text('password = "secret123"\n')
        
        results = scan_directory(tmp_path)
        assert results == {}
