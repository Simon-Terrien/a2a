#!/usr/bin/env python3
"""
Simplified Code Review Demo
A minimal version to demonstrate the multi-agent code review concept
"""

import os
import json
import re
import ast
from typing import Dict, List

# Mock the A2A and MCP functionality for demonstration
class MockAgent:
    """Mock agent for demonstration purposes"""
    
    def __init__(self, name, expertise):
        self.name = name
        self.expertise = expertise
    
    def analyze(self, code: str, focus: str) -> Dict:
        """Analyze code based on agent's expertise"""
        if self.expertise == "security":
            return self._security_analysis(code)
        elif self.expertise == "performance":
            return self._performance_analysis(code)
        elif self.expertise == "style":
            return self._style_analysis(code)
        else:
            return {"issues": [], "summary": "No analysis available"}
    
    def _security_analysis(self, code: str) -> Dict:
        """Basic security analysis"""
        issues = []
        
        # Check for common security issues
        if 'eval(' in code:
            issues.append({
                "severity": "HIGH",
                "type": "security",
                "issue": "Use of eval() function detected",
                "recommendation": "Replace eval() with safer alternatives like ast.literal_eval()",
                "line": self._find_line(code, 'eval(')
            })
        
        if 'exec(' in code:
            issues.append({
                "severity": "HIGH", 
                "type": "security",
                "issue": "Use of exec() function detected",
                "recommendation": "Avoid exec() or implement strict input validation",
                "line": self._find_line(code, 'exec(')
            })
        
        # Check for hardcoded passwords
        if re.search(r'password\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
            issues.append({
                "severity": "CRITICAL",
                "type": "security", 
                "issue": "Hardcoded password detected",
                "recommendation": "Use environment variables or secure credential storage",
                "line": self._find_line_regex(code, r'password\s*=\s*["\']')
            })
        
        # Check for SQL injection risks
        if re.search(r'SELECT.*\+.*["\']', code, re.IGNORECASE):
            issues.append({
                "severity": "CRITICAL",
                "type": "security",
                "issue": "Potential SQL injection vulnerability",
                "recommendation": "Use parameterized queries or prepared statements",
                "line": self._find_line_regex(code, r'SELECT.*\+')
            })
        
        return {
            "agent": self.name,
            "issues": issues,
            "summary": f"Found {len(issues)} security issues"
        }
    
    def _performance_analysis(self, code: str) -> Dict:
        """Basic performance analysis"""
        issues = []
        
        try:
            tree = ast.parse(code)
            
            # Check for nested loops
            for node in ast.walk(tree):
                if isinstance(node, ast.For):
                    for child in ast.walk(node):
                        if isinstance(child, ast.For) and child != node:
                            issues.append({
                                "severity": "MEDIUM",
                                "type": "performance",
                                "issue": "Nested loops detected - potential O(n²) complexity",
                                "recommendation": "Consider optimizing with hash maps or single-pass algorithms",
                                "line": node.lineno
                            })
                            break
        except SyntaxError:
            issues.append({
                "severity": "ERROR",
                "type": "performance",
                "issue": "Syntax error prevents performance analysis",
                "recommendation": "Fix syntax errors first",
                "line": "Unknown"
            })
        
        # Check for string concatenation in loops
        if re.search(r'for.*:.*\+\s*=.*str', code, re.DOTALL):
            issues.append({
                "severity": "MEDIUM",
                "type": "performance",
                "issue": "String concatenation in loop detected",
                "recommendation": "Use list.append() and ''.join() for better performance",
                "line": "Multiple locations"
            })
        
        return {
            "agent": self.name,
            "issues": issues,
            "summary": f"Found {len(issues)} performance issues"
        }
    
    def _style_analysis(self, code: str) -> Dict:
        """Basic style analysis"""
        issues = []
        lines = code.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Line length check
            if len(line) > 88:
                issues.append({
                    "severity": "LOW",
                    "type": "style",
                    "issue": f"Line too long ({len(line)} characters)",
                    "recommendation": "Break long lines for better readability",
                    "line": i
                })
            
            # Trailing whitespace
            if line.rstrip() != line:
                issues.append({
                    "severity": "LOW",
                    "type": "style",
                    "issue": "Trailing whitespace detected",
                    "recommendation": "Remove trailing whitespace",
                    "line": i
                })
        
        # Function naming convention
        if re.search(r'def [A-Z]', code):
            issues.append({
                "severity": "MEDIUM",
                "type": "style",
                "issue": "Function names should be lowercase with underscores",
                "recommendation": "Use snake_case for function names (PEP 8)",
                "line": self._find_line_regex(code, r'def [A-Z]')
            })
        
        # Missing docstrings
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    if not ast.get_docstring(node):
                        issues.append({
                            "severity": "MEDIUM",
                            "type": "style",
                            "issue": f"{node.__class__.__name__} '{node.name}' missing docstring",
                            "recommendation": "Add docstring to document purpose and usage",
                            "line": node.lineno
                        })
        except SyntaxError:
            pass
        
        return {
            "agent": self.name,
            "issues": issues,
            "summary": f"Found {len(issues)} style issues"
        }
    
    def _find_line(self, code: str, pattern: str) -> int:
        """Find line number containing pattern"""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return "Unknown"
    
    def _find_line_regex(self, code: str, pattern: str) -> int:
        """Find line number matching regex pattern"""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                return i
        return "Unknown"

class CodeReviewOrchestrator:
    """Orchestrates the multi-agent code review process"""
    
    def __init__(self):
        self.agents = {
            'security': MockAgent("Security Expert", "security"),
            'performance': MockAgent("Performance Expert", "performance"), 
            'style': MockAgent("Style Expert", "style")
        }
    
    def review_code(self, code: str) -> Dict:
        """Perform comprehensive code review using all agents"""
        print("🔍 Starting multi-agent code review...\n")
        
        results = {}
        all_issues = []
        
        for agent_type, agent in self.agents.items():
            print(f"📋 Running {agent.name} analysis...")
            result = agent.analyze(code, agent_type)
            results[agent_type] = result
            all_issues.extend(result['issues'])
            print(f"   {result['summary']}")
        
        # Generate comprehensive report
        report = self._generate_report(results, all_issues)
        return report
    
    def _generate_report(self, results: Dict, all_issues: List) -> Dict:
        """Generate comprehensive review report"""
        severity_counts = {
            'CRITICAL': len([i for i in all_issues if i['severity'] == 'CRITICAL']),
            'HIGH': len([i for i in all_issues if i['severity'] == 'HIGH']),
            'MEDIUM': len([i for i in all_issues if i['severity'] == 'MEDIUM']),
            'LOW': len([i for i in all_issues if i['severity'] == 'LOW']),
            'ERROR': len([i for i in all_issues if i['severity'] == 'ERROR'])
        }
        
        return {
            'summary': {
                'total_issues': len(all_issues),
                'security_issues': len(results['security']['issues']),
                'performance_issues': len(results['performance']['issues']),
                'style_issues': len(results['style']['issues']),
                'severity_breakdown': severity_counts
            },
            'detailed_results': results,
            'all_issues': sorted(all_issues, key=lambda x: {
                'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'ERROR': 4
            }.get(x['severity'], 5))
        }
    
    def print_report(self, report: Dict):
        """Print formatted code review report"""
        print("\n" + "="*60)
        print("🔍 COMPREHENSIVE CODE REVIEW REPORT")
        print("="*60)
        
        summary = report['summary']
        print(f"\n📊 SUMMARY:")
        print(f"   Total Issues Found: {summary['total_issues']}")
        print(f"   Security Issues: {summary['security_issues']}")
        print(f"   Performance Issues: {summary['performance_issues']}")
        print(f"   Style Issues: {summary['style_issues']}")
        
        print(f"\n🚨 SEVERITY BREAKDOWN:")
        for severity, count in summary['severity_breakdown'].items():
            if count > 0:
                emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'ERROR': '⚠️'}
                print(f"   {emoji.get(severity, '❓')} {severity}: {count}")
        
        if report['all_issues']:
            print(f"\n📋 DETAILED ISSUES:")
            for i, issue in enumerate(report['all_issues'], 1):
                severity_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'ERROR': '⚠️'}
                print(f"\n   {i}. {severity_emoji.get(issue['severity'], '❓')} {issue['severity']} - {issue['type'].upper()}")
                print(f"      Issue: {issue['issue']}")
                print(f"      Line: {issue['line']}")
                print(f"      Fix: {issue['recommendation']}")
        else:
            print(f"\n✅ No issues found! Code looks good.")

def main():
    """Main demo function"""
    print("🚀 Multi-Agent Code Review System Demo")
    print("="*50)
    
    # Test code with various issues
    test_code = '''
def calculatePassword(username, password="admin123"):
    """This function has multiple issues for demonstration"""
    # Security issue: hardcoded password
    if password == "admin123":
        return True
    
    # Security issue: SQL injection vulnerability  
    sql = "SELECT * FROM users WHERE username = '" + username + "'"
    
    # Security issue: using eval
    result = eval("execute_query('" + sql + "')")
    
    # Performance issue: nested loops (O(n²))
    for i in range(len(result)):
        for j in range(len(result[i])):
            if result[i][j] == password:
                return True
    
    return False

# Style issues: class naming, missing docstring
class myClass:
    def MyMethod(self):  # Style issue: method naming
        pass
'''
    
    print("📝 Analyzing the following code:")
    print("-" * 30)
    print(test_code)
    print("-" * 30)
    
    # Create orchestrator and run review
    orchestrator = CodeReviewOrchestrator()
    report = orchestrator.review_code(test_code)
    
    # Print detailed report
    orchestrator.print_report(report)
    
    print(f"\n💡 RECOMMENDATIONS:")
    print("   1. Replace hardcoded credentials with environment variables")
    print("   2. Use parameterized queries to prevent SQL injection")
    print("   3. Avoid eval() - use safer alternatives like ast.literal_eval()")
    print("   4. Optimize nested loops with better algorithms (sets, dicts)")
    print("   5. Follow PEP 8 naming conventions")
    print("   6. Add proper documentation with docstrings")
    
    print(f"\n🎯 NEXT STEPS:")
    print("   • Fix critical and high severity issues first")
    print("   • Run security scan tools like Bandit")
    print("   • Use code formatters like Black for style consistency")
    print("   • Consider code review automation in CI/CD pipeline")
    
    print(f"\n✅ Demo completed! This shows how multiple specialized agents")
    print("   can collaborate to provide comprehensive code analysis.")

if __name__ == "__main__":
    main()