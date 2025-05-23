#!/usr/bin/env python3
"""
Enhanced Fallback Agents for Code Review System
Provides AI-powered analysis when A2A/MCP libraries are not available
"""

import os
import ast
import re
import json
import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from abc import ABC, abstractmethod

try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

class BaseFallbackAgent(ABC):
    """Base class for fallback agents"""
    
    def __init__(self, config, agent_type: str):
        self.config = config
        self.agent_type = agent_type
        self.logger = logging.getLogger(f'agent.fallback.{agent_type}')
        
        # Initialize OpenAI client if available
        if OPENAI_AVAILABLE and config.openai_api_key:
            self.client = OpenAI(api_key=config.openai_api_key)
        else:
            self.client = None
            self.logger.warning("OpenAI client not available, using rule-based analysis only")
    
    @abstractmethod
    def get_system_prompt(self) -> str:
        """Get system prompt for this agent type"""
        pass
    
    @abstractmethod
    def perform_static_analysis(self, code: str) -> Dict[str, Any]:
        """Perform static analysis without AI"""
        pass
    
    def analyze(self, code: str) -> Dict[str, Any]:
        """Perform comprehensive analysis"""
        start_time = time.time()
        
        try:
            # Always perform static analysis
            static_results = self.perform_static_analysis(code)
            
            # Enhance with AI analysis if available
            if self.client:
                ai_results = self._perform_ai_analysis(code)
                combined_results = self._combine_results(static_results, ai_results)
            else:
                combined_results = static_results
            
            execution_time = time.time() - start_time
            combined_results['execution_time'] = execution_time
            combined_results['agent_type'] = self.agent_type
            combined_results['analysis_method'] = 'ai_enhanced' if self.client else 'static_only'
            
            self.logger.info(f"Analysis completed in {execution_time:.3f}s")
            return combined_results
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}", exc_info=True)
            return {
                'issues': [],
                'summary': {'error': str(e)},
                'execution_time': time.time() - start_time,
                'success': False
            }
    
    def _perform_ai_analysis(self, code: str) -> Dict[str, Any]:
        """Perform AI-enhanced analysis"""
        try:
            response = self.client.chat.completions.create(
                model=self.config.agent.model,
                messages=[
                    {"role": "system", "content": self.get_system_prompt()},
                    {"role": "user", "content": f"Analyze this code:\n\n```python\n{code}\n```"}
                ],
                max_tokens=self.config.agent.max_tokens,
                temperature=self.config.agent.temperature
            )
            
            ai_analysis = response.choices[0].message.content
            
            # Parse AI response into structured format
            return self._parse_ai_response(ai_analysis)
            
        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            return {'issues': [], 'summary': {'ai_error': str(e)}}
    
    def _parse_ai_response(self, ai_response: str) -> Dict[str, Any]:
        """Parse AI response into structured format"""
        # This is a simplified parser - in production, you'd want more sophisticated parsing
        issues = []
        
        # Look for common patterns in AI responses
        lines = ai_response.split('\n')
        current_issue = {}
        
        for line in lines:
            line = line.strip()
            
            # Look for severity indicators
            if any(keyword in line.lower() for keyword in ['critical', 'high', 'medium', 'low']):
                if current_issue:
                    issues.append(current_issue)
                    current_issue = {}
                
                # Extract severity
                for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                    if severity.lower() in line.lower():
                        current_issue['severity'] = severity
                        break
                
                current_issue['issue'] = line
            
            # Look for recommendations
            elif 'recommendation' in line.lower() or 'fix' in line.lower():
                if current_issue:
                    current_issue['recommendation'] = line
            
            # Look for line numbers
            elif 'line' in line.lower() and any(char.isdigit() for char in line):
                if current_issue:
                    # Extract line number
                    import re
                    line_match = re.search(r'line\s*(\d+)', line.lower())
                    if line_match:
                        current_issue['line'] = int(line_match.group(1))
        
        # Add the last issue if it exists
        if current_issue:
            issues.append(current_issue)
        
        return {
            'issues': issues,
            'summary': {
                'ai_analysis': ai_response,
                'issues_found': len(issues)
            }
        }
    
    def _combine_results(self, static_results: Dict, ai_results: Dict) -> Dict[str, Any]:
        """Combine static and AI analysis results"""
        combined_issues = static_results.get('issues', []) + ai_results.get('issues', [])
        
        # Remove duplicates based on issue content
        seen_issues = set()
        unique_issues = []
        
        for issue in combined_issues:
            issue_key = (issue.get('issue', ''), issue.get('line', 'unknown'))
            if issue_key not in seen_issues:
                seen_issues.add(issue_key)
                unique_issues.append(issue)
        
        combined_summary = {
            **static_results.get('summary', {}),
            **ai_results.get('summary', {}),
            'total_issues': len(unique_issues),
            'static_issues': len(static_results.get('issues', [])),
            'ai_issues': len(ai_results.get('issues', []))
        }
        
        return {
            'issues': unique_issues,
            'summary': combined_summary,
            'success': True
        }

class FallbackSecurityAgent(BaseFallbackAgent):
    """Security analysis fallback agent"""
    
    def __init__(self, config):
        super().__init__(config, 'security')
    
    def get_system_prompt(self) -> str:
        return """You are an expert cybersecurity analyst specializing in code security review.
        
        Analyze the provided code for security vulnerabilities including:
        - SQL injection vulnerabilities
        - Cross-site scripting (XSS) risks
        - Authentication and authorization flaws
        - Input validation issues
        - Cryptographic weaknesses
        - Hardcoded credentials
        - Command injection vulnerabilities
        - Path traversal issues
        - Insecure deserialization
        - Security misconfigurations
        
        For each issue found, provide:
        1. Severity level (CRITICAL, HIGH, MEDIUM, LOW)
        2. Clear description of the vulnerability
        3. Specific line number if applicable
        4. Detailed remediation recommendation
        5. Potential impact assessment
        
        Focus on practical, actionable security recommendations."""
    
    def perform_static_analysis(self, code: str) -> Dict[str, Any]:
        """Perform static security analysis"""
        issues = []
        
        # Check for eval/exec usage
        if 'eval(' in code:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Use of eval() function detected - potential code injection risk',
                'recommendation': 'Replace eval() with safer alternatives like ast.literal_eval() or JSON parsing',
                'line': self._find_line_number(code, 'eval('),
                'category': 'code_injection'
            })
        
        if 'exec(' in code:
            issues.append({
                'severity': 'HIGH',
                'issue': 'Use of exec() function detected - potential code injection risk',
                'recommendation': 'Avoid exec() or implement strict input validation and sandboxing',
                'line': self._find_line_number(code, 'exec('),
                'category': 'code_injection'
            })
        
        # Check for hardcoded passwords
        password_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'passwd\s*=\s*["\'][^"\']+["\']',
            r'pwd\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']'
        ]
        
        for pattern in password_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            for match in matches:
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': 'Hardcoded credentials detected',
                    'recommendation': 'Use environment variables or secure credential management systems',
                    'line': self._find_line_number_for_position(code, match.start()),
                    'category': 'credential_exposure'
                })
        
        # Check for SQL injection patterns
        sql_injection_patterns = [
            r'SELECT.*\+.*["\']',
            r'INSERT.*\+.*["\']',
            r'UPDATE.*\+.*["\']',
            r'DELETE.*\+.*["\']',
            r'DROP.*\+.*["\']'
        ]
        
        for pattern in sql_injection_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE | re.DOTALL))
            for match in matches:
                issues.append({
                    'severity': 'CRITICAL',
                    'issue': 'Potential SQL injection vulnerability detected',
                    'recommendation': 'Use parameterized queries or prepared statements',
                    'line': self._find_line_number_for_position(code, match.start()),
                    'category': 'sql_injection'
                })
        
        # Check for command injection
        command_patterns = [
            r'os\.system\(',
            r'subprocess\.call\(.*shell=True',
            r'subprocess\.run\(.*shell=True',
            r'os\.popen\('
        ]
        
        for pattern in command_patterns:
            matches = list(re.finditer(pattern, code, re.IGNORECASE))
            for match in matches:
                issues.append({
                    'severity': 'HIGH',
                    'issue': 'Potential command injection vulnerability',
                    'recommendation': 'Validate and sanitize all user inputs, avoid shell=True',
                    'line': self._find_line_number_for_position(code, match.start()),
                    'category': 'command_injection'
                })
        
        # Check for weak random number generation
        weak_random_patterns = [
            r'random\.random\(',
            r'random\.randint\(',
            r'random\.choice\('
        ]
        
        for pattern in weak_random_patterns:
            if re.search(pattern, code):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'Use of predictable random number generator',
                    'recommendation': 'Use secrets module for cryptographically secure random numbers',
                    'line': self._find_line_number(code, pattern.replace('\\', '')),
                    'category': 'weak_crypto'
                })
        
        # Check for insecure hash functions
        weak_hash_patterns = [
            r'hashlib\.md5\(',
            r'hashlib\.sha1\('
        ]
        
        for pattern in weak_hash_patterns:
            if re.search(pattern, code):
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'Use of weak cryptographic hash function',
                    'recommendation': 'Use SHA-256 or stronger hash functions',
                    'line': self._find_line_number(code, pattern.replace('\\', '')),
                    'category': 'weak_crypto'
                })
        
        return {
            'issues': issues,
            'summary': {
                'total_vulnerabilities': len(issues),
                'critical_issues': len([i for i in issues if i['severity'] == 'CRITICAL']),
                'high_issues': len([i for i in issues if i['severity'] == 'HIGH']),
                'medium_issues': len([i for i in issues if i['severity'] == 'MEDIUM']),
                'categories': list(set(i['category'] for i in issues))
            }
        }
    
    def _find_line_number(self, code: str, pattern: str) -> int:
        """Find line number containing pattern"""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if pattern in line:
                return i
        return 0
    
    def _find_line_number_for_position(self, code: str, position: int) -> int:
        """Find line number for character position"""
        lines_before = code[:position].count('\n')
        return lines_before + 1

class FallbackPerformanceAgent(BaseFallbackAgent):
    """Performance analysis fallback agent"""
    
    def __init__(self, config):
        super().__init__(config, 'performance')
    
    def get_system_prompt(self) -> str:
        return """You are a senior performance engineer specializing in code optimization.
        
        Analyze the provided code for performance issues including:
        - Algorithmic complexity problems (O(n²), O(n³), etc.)
        - Memory inefficiencies and potential leaks
        - Inefficient data structure usage
        - Unnecessary loops and iterations
        - Database query optimization opportunities
        - Caching opportunities
        - Concurrency and threading issues
        - I/O bottlenecks
        - String manipulation inefficiencies
        - Recursive function optimization
        
        For each issue found, provide:
        1. Severity level (HIGH, MEDIUM, LOW)
        2. Performance impact description
        3. Specific line number if applicable
        4. Optimization recommendation with code examples
        5. Expected performance improvement
        
        Focus on practical optimizations that provide measurable performance gains."""
    
    def perform_static_analysis(self, code: str) -> Dict[str, Any]:
        """Perform static performance analysis"""
        issues = []
        
        try:
            tree = ast.parse(code)
            
            # Check for nested loops (O(n²) complexity)
            nested_loops = self._find_nested_loops(tree)
            for loop_info in nested_loops:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': f'Nested loops detected - potential O(n²) or higher complexity',
                    'recommendation': 'Consider using hash maps, sets, or optimized algorithms to reduce complexity',
                    'line': loop_info['line'],
                    'category': 'algorithmic_complexity'
                })
            
            # Check for inefficient string concatenation
            string_concat_in_loops = self._find_string_concat_in_loops(tree, code)
            for concat_info in string_concat_in_loops:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'String concatenation in loop detected',
                    'recommendation': 'Use list.append() and "".join() for better performance',
                    'line': concat_info['line'],
                    'category': 'string_optimization'
                })
            
            # Check for inefficient list operations
            inefficient_list_ops = self._find_inefficient_list_operations(tree)
            for op_info in inefficient_list_ops:
                issues.append({
                    'severity': 'LOW',
                    'issue': 'Potentially inefficient list operation',
                    'recommendation': op_info['recommendation'],
                    'line': op_info['line'],
                    'category': 'data_structure'
                })
        
        except SyntaxError as e:
            issues.append({
                'severity': 'ERROR',
                'issue': f'Syntax error prevents performance analysis: {str(e)}',
                'recommendation': 'Fix syntax errors before performance analysis',
                'line': getattr(e, 'lineno', 0),
                'category': 'syntax_error'
            })
        
        # Check for database query patterns
        db_issues = self._analyze_database_patterns(code)
        issues.extend(db_issues)
        
        # Check for file I/O patterns
        io_issues = self._analyze_io_patterns(code)
        issues.extend(io_issues)
        
        return {
            'issues': issues,
            'summary': {
                'total_performance_issues': len(issues),
                'complexity_issues': len([i for i in issues if i['category'] == 'algorithmic_complexity']),
                'optimization_opportunities': len([i for i in issues if i['severity'] != 'ERROR']),
                'categories': list(set(i['category'] for i in issues))
            }
        }
    
    def _find_nested_loops(self, tree) -> List[Dict]:
        """Find nested loops in AST"""
        nested_loops = []
        
    def _find_nested_loops(self, tree) -> List[Dict]:
        """Find nested loops in AST"""
        nested_loops = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                # Check if this loop contains another loop
                for child in ast.walk(node):
                    if isinstance(child, (ast.For, ast.While)) and child != node:
                        nested_loops.append({
                            'line': node.lineno,
                            'type': 'nested_loop',
                            'outer_type': type(node).__name__,
                            'inner_type': type(child).__name__
                        })
                        break
        
        return nested_loops
    
    def _find_string_concat_in_loops(self, tree, code: str) -> List[Dict]:
        """Find string concatenation inside loops"""
        concat_in_loops = []
        
        for node in ast.walk(tree):
            if isinstance(node, (ast.For, ast.While)):
                # Look for string concatenation patterns within this loop
                for child in ast.walk(node):
                    if isinstance(child, ast.AugAssign) and isinstance(child.op, ast.Add):
                        # Check if it's likely string concatenation
                        concat_in_loops.append({
                            'line': child.lineno,
                            'type': 'string_concat_in_loop'
                        })
                    elif isinstance(child, ast.BinOp) and isinstance(child.op, ast.Add):
                        # Check for string + string patterns
                        concat_in_loops.append({
                            'line': child.lineno,
                            'type': 'string_concat_in_loop'
                        })
        
        return concat_in_loops
    
    def _find_inefficient_list_operations(self, tree) -> List[Dict]:
        """Find inefficient list operations"""
        inefficient_ops = []
        
        for node in ast.walk(tree):
            # Check for list.insert(0, item) which is O(n)
            if (isinstance(node, ast.Call) and 
                isinstance(node.func, ast.Attribute) and 
                node.func.attr == 'insert' and 
                len(node.args) >= 2):
                
                if (isinstance(node.args[0], ast.Constant) and 
                    node.args[0].value == 0):
                    inefficient_ops.append({
                        'line': node.lineno,
                        'type': 'inefficient_list_insert',
                        'recommendation': 'Consider using collections.deque for frequent insertions at the beginning'
                    })
            
            # Check for list comprehensions that could be generator expressions
            if isinstance(node, ast.ListComp):
                # This is a simplification - in practice, you'd need more context
                parent_nodes = []
                for parent in ast.walk(tree):
                    for child in ast.iter_child_nodes(parent):
                        if child == node:
                            parent_nodes.append(parent)
                
                # If used only for iteration, suggest generator
                if any(isinstance(p, (ast.For, ast.Call)) for p in parent_nodes):
                    inefficient_ops.append({
                        'line': node.lineno,
                        'type': 'list_comp_to_generator',
                        'recommendation': 'Consider using generator expression if list is only iterated once'
                    })
        
        return inefficient_ops
    
    def _analyze_database_patterns(self, code: str) -> List[Dict]:
        """Analyze database usage patterns"""
        issues = []
        
        # Check for N+1 query patterns
        if re.search(r'for.*in.*:\s*.*\.query\(', code, re.DOTALL):
            issues.append({
                'severity': 'HIGH',
                'issue': 'Potential N+1 query problem detected',
                'recommendation': 'Use bulk queries, joins, or prefetch_related to reduce database round trips',
                'line': self._find_line_with_pattern(code, r'for.*in.*:'),
                'category': 'database_optimization'
            })
        
        # Check for missing indexes
        if 'WHERE' in code.upper() and 'INDEX' not in code.upper():
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'SQL query without explicit index consideration',
                'recommendation': 'Ensure appropriate database indexes exist for WHERE clauses',
                'line': self._find_line_with_pattern(code, r'WHERE', re.IGNORECASE),
                'category': 'database_optimization'
            })
        
        # Check for SELECT * usage
        if re.search(r'SELECT\s+\*', code, re.IGNORECASE):
            issues.append({
                'severity': 'LOW',
                'issue': 'SELECT * query detected',
                'recommendation': 'Select only required columns to reduce data transfer',
                'line': self._find_line_with_pattern(code, r'SELECT\s+\*', re.IGNORECASE),
                'category': 'database_optimization'
            })
        
        return issues
    
    def _analyze_io_patterns(self, code: str) -> List[Dict]:
        """Analyze I/O usage patterns"""
        issues = []
        
        # Check for file operations in loops
        if re.search(r'for.*in.*:.*open\(', code, re.DOTALL):
            issues.append({
                'severity': 'HIGH',
                'issue': 'File operations inside loop detected',
                'recommendation': 'Move file operations outside loops or use batch processing',
                'line': self._find_line_with_pattern(code, r'open\('),
                'category': 'io_optimization'
            })
        
        # Check for missing context managers
        if 'open(' in code and 'with ' not in code:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'File opened without context manager',
                'recommendation': 'Use "with open()" to ensure proper file closure',
                'line': self._find_line_with_pattern(code, r'open\('),
                'category': 'resource_management'
            })
        
        return issues
    
    def _find_line_with_pattern(self, code: str, pattern: str, flags=0) -> int:
        """Find line number with regex pattern"""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, flags):
                return i
        return 0

class FallbackStyleAgent(BaseFallbackAgent):
    """Style and code quality analysis fallback agent"""
    
    def __init__(self, config):
        super().__init__(config, 'style')
    
    def get_system_prompt(self) -> str:
        return """You are a senior software architect specializing in code quality and maintainability.
        
        Analyze the provided code for style and quality issues including:
        - PEP 8 compliance and coding standards
        - Code complexity and maintainability
        - Documentation quality and completeness
        - Naming conventions and clarity
        - Function and class design principles
        - SOLID principles adherence
        - Code duplication and reusability
        - Error handling patterns
        - Type hints and annotations
        - Code organization and structure
        
        For each issue found, provide:
        1. Severity level (MEDIUM, LOW)
        2. Style or quality issue description
        3. Specific line number if applicable
        4. Improvement recommendation with examples
        5. Long-term maintainability impact
        
        Focus on improving code readability, maintainability, and team collaboration."""
    
    def perform_static_analysis(self, code: str) -> Dict[str, Any]:
        """Perform static style and quality analysis"""
        issues = []
        lines = code.split('\n')
        
        # Check line length (PEP 8)
        for i, line in enumerate(lines, 1):
            if len(line) > 88:  # Slightly more lenient than PEP 8's 79
                issues.append({
                    'severity': 'LOW',
                    'issue': f'Line too long ({len(line)} characters)',
                    'recommendation': 'Break long lines for better readability (PEP 8)',
                    'line': i,
                    'category': 'formatting'
                })
            
            # Check for trailing whitespace
            if line.rstrip() != line:
                issues.append({
                    'severity': 'LOW',
                    'issue': 'Trailing whitespace detected',
                    'recommendation': 'Remove trailing whitespace',
                    'line': i,
                    'category': 'formatting'
                })
        
        # Check naming conventions
        naming_issues = self._check_naming_conventions(code)
        issues.extend(naming_issues)
        
        # Check for missing docstrings
        docstring_issues = self._check_docstrings(code)
        issues.extend(docstring_issues)
        
        # Check complexity
        complexity_issues = self._check_complexity(code)
        issues.extend(complexity_issues)
        
        # Check for code smells
        code_smell_issues = self._check_code_smells(code)
        issues.extend(code_smell_issues)
        
        return {
            'issues': issues,
            'summary': {
                'total_style_issues': len(issues),
                'formatting_issues': len([i for i in issues if i['category'] == 'formatting']),
                'naming_issues': len([i for i in issues if i['category'] == 'naming']),
                'documentation_issues': len([i for i in issues if i['category'] == 'documentation']),
                'complexity_issues': len([i for i in issues if i['category'] == 'complexity']),
                'maintainability_score': self._calculate_maintainability_score(issues)
            }
        }
    
    def _check_naming_conventions(self, code: str) -> List[Dict]:
        """Check naming convention violations"""
        issues = []
        
        # Check function naming (should be snake_case)
        function_pattern = r'def ([A-Z][a-zA-Z]*)\('
        for match in re.finditer(function_pattern, code):
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'Function name "{match.group(1)}" should use snake_case',
                'recommendation': 'Use snake_case for function names (PEP 8)',
                'line': self._find_line_number_for_text(code, match.group(0)),
                'category': 'naming'
            })
        
        # Check class naming (should be PascalCase)
        class_pattern = r'class ([a-z][a-zA-Z]*)'
        for match in re.finditer(class_pattern, code):
            issues.append({
                'severity': 'MEDIUM',
                'issue': f'Class name "{match.group(1)}" should use PascalCase',
                'recommendation': 'Use PascalCase for class names (PEP 8)',
                'line': self._find_line_number_for_text(code, match.group(0)),
                'category': 'naming'
            })
        
        # Check constant naming (should be UPPER_CASE)
        constant_pattern = r'^([a-z][a-zA-Z_]*)\s*=\s*["\']'
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.match(constant_pattern, line.strip()):
                match = re.match(constant_pattern, line.strip())
                if match and not match.group(1).isupper():
                    issues.append({
                        'severity': 'LOW',
                        'issue': f'Constant "{match.group(1)}" should use UPPER_CASE',
                        'recommendation': 'Use UPPER_CASE for constants (PEP 8)',
                        'line': i,
                        'category': 'naming'
                    })
        
        return issues
    
    def _check_docstrings(self, code: str) -> List[Dict]:
        """Check for missing or inadequate docstrings"""
        issues = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    docstring = ast.get_docstring(node)
                    
                    if not docstring:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue': f'{node.__class__.__name__} "{node.name}" missing docstring',
                            'recommendation': 'Add docstring to document purpose, parameters, and return values',
                            'line': node.lineno,
                            'category': 'documentation'
                        })
                    elif len(docstring.strip()) < 10:
                        issues.append({
                            'severity': 'LOW',
                            'issue': f'{node.__class__.__name__} "{node.name}" has very brief docstring',
                            'recommendation': 'Expand docstring to include more detailed documentation',
                            'line': node.lineno,
                            'category': 'documentation'
                        })
        
        except SyntaxError:
            pass  # Already handled in other agents
        
        return issues
    
    def _check_complexity(self, code: str) -> List[Dict]:
        """Check for high complexity functions"""
        issues = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    complexity = self._calculate_cyclomatic_complexity(node)
                    
                    if complexity > 10:
                        issues.append({
                            'severity': 'MEDIUM',
                            'issue': f'Function "{node.name}" has high cyclomatic complexity ({complexity})',
                            'recommendation': 'Consider breaking down into smaller functions',
                            'line': node.lineno,
                            'category': 'complexity'
                        })
                    elif complexity > 7:
                        issues.append({
                            'severity': 'LOW',
                            'issue': f'Function "{node.name}" has moderate complexity ({complexity})',
                            'recommendation': 'Consider refactoring to reduce complexity',
                            'line': node.lineno,
                            'category': 'complexity'
                        })
        
        except SyntaxError:
            pass
        
        return issues
    
    def _check_code_smells(self, code: str) -> List[Dict]:
        """Check for common code smells"""
        issues = []
        
        # Long parameter lists
        long_param_pattern = r'def\s+\w+\s*\([^)]{60,}\)'
        for match in re.finditer(long_param_pattern, code):
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Function has too many parameters',
                'recommendation': 'Consider using parameter objects or configuration classes',
                'line': self._find_line_number_for_text(code, match.group(0)),
                'category': 'design'
            })
        
        # Magic numbers
        magic_number_pattern = r'(?<![a-zA-Z_])[0-9]{3,}(?![a-zA-Z_])'
        for match in re.finditer(magic_number_pattern, code):
            # Skip common exceptions like years, HTTP status codes, etc.
            number = int(match.group(0))
            if number not in [200, 201, 400, 401, 403, 404, 500, 1000, 2000]:
                issues.append({
                    'severity': 'LOW',
                    'issue': f'Magic number "{number}" detected',
                    'recommendation': 'Replace magic numbers with named constants',
                    'line': self._find_line_number_for_text(code, match.group(0)),
                    'category': 'maintainability'
                })
        
        # Duplicate code detection (simplified)
        lines = [line.strip() for line in code.split('\n') if line.strip()]
        line_counts = {}
        for i, line in enumerate(lines):
            if len(line) > 20:  # Only check substantial lines
                if line in line_counts:
                    line_counts[line].append(i + 1)
                else:
                    line_counts[line] = [i + 1]
        
        for line, occurrences in line_counts.items():
            if len(occurrences) > 2:
                issues.append({
                    'severity': 'MEDIUM',
                    'issue': f'Duplicate code detected ({len(occurrences)} times)',
                    'recommendation': 'Extract duplicate code into a reusable function',
                    'line': occurrences[0],
                    'category': 'duplication'
                })
        
        return issues
    
    def _calculate_cyclomatic_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity of a function"""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            # Add complexity for decision points
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.With):
                complexity += 1
            elif isinstance(child, ast.Assert):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity
    
    def _calculate_maintainability_score(self, issues: List[Dict]) -> int:
        """Calculate maintainability score based on issues"""
        base_score = 100
        
        # Deduct points based on issue severity
        for issue in issues:
            if issue['severity'] == 'HIGH':
                base_score -= 10
            elif issue['severity'] == 'MEDIUM':
                base_score -= 5
            elif issue['severity'] == 'LOW':
                base_score -= 2
        
        return max(0, base_score)
    
    def _find_line_number_for_text(self, code: str, text: str) -> int:
        """Find line number containing specific text"""
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if text in line:
                return i
        return 0

# Factory function for creating fallback agents
def create_fallback_agents(config) -> Dict[str, BaseFallbackAgent]:
    """Create all fallback agents"""
    return {
        'security': FallbackSecurityAgent(config),
        'performance': FallbackPerformanceAgent(config),
        'style': FallbackStyleAgent(config)
    }

# Example usage and testing
if __name__ == "__main__":
    # Test the fallback agents
    class MockConfig:
        def __init__(self):
            self.openai_api_key = os.getenv('OPENAI_API_KEY')
            
            class AgentConfig:
                model = "gpt-4o-mini"
                temperature = 0.1
                max_tokens = 1500
            
            self.agent = AgentConfig()
    
    config = MockConfig()
    
    test_code = '''
def calculatePassword(username, password="admin123"):
    if password == "admin123":
        return True
    sql = "SELECT * FROM users WHERE username = '" + username + "'"
    result = eval("execute_query('" + sql + "')")
    for i in range(len(result)):
        for j in range(len(result[i])):
            if result[i][j] == password:
                return True
    return False

class myClass:
    def MyMethod(self):
        pass
'''
    
    # Test each agent
    agents = create_fallback_agents(config)
    
    for agent_name, agent in agents.items():
        print(f"\n🧪 Testing {agent_name} agent...")
        result = agent.analyze(test_code)
        print(f"Found {len(result.get('issues', []))} issues")
        
        for issue in result.get('issues', [])[:3]:  # Show first 3 issues
            print(f"  • {issue.get('severity', 'UNKNOWN')}: {issue.get('issue', 'Unknown issue')}")
    
    print("\n✅ Fallback agents test completed")