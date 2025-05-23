#!/usr/bin/env python3
"""
Multi-Agent Code Review System
Using A2A + MCP + LangChain for automated code analysis

This system creates specialized agents for:
- Security Analysis
- Performance Analysis  
- Style & Best Practices Analysis
- Meta Review Coordination
"""

import os
import sys
import socket
import time
import threading
import argparse
import json
import ast
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

# Core frameworks
from python_a2a import OpenAIA2AServer, run_server, A2AServer, AgentCard, AgentSkill
from python_a2a.langchain import to_langchain_agent, to_langchain_tool
from python_a2a.mcp import FastMCP
from langchain_openai import ChatOpenAI
from langchain.agents import initialize_agent, Tool, AgentType

# Analysis libraries
import bandit
from pylint import lint
from pylint.reporters import JSONReporter
import ast
import subprocess
import tempfile

def check_api_key():
    """Check if OpenAI API key is available"""
    if not os.environ.get("OPENAI_API_KEY"):
        print("❌ Error: OPENAI_API_KEY environment variable not set")
        print("Please set your OpenAI API key: export OPENAI_API_KEY='your-key-here'")
        return False
    return True

def find_available_port(start_port=5000, max_tries=20):
    """Find an available port starting from start_port"""
    for port in range(start_port, start_port + max_tries):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('localhost', port))
            sock.close()
            return port
        except OSError:
            continue
    return start_port + 1000

def run_server_in_thread(server_func, server, **kwargs):
    """Run a server in a background thread"""
    thread = threading.Thread(target=server_func, args=(server,), kwargs=kwargs, daemon=True)
    thread.start()
    time.sleep(2)
    return thread

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Multi-Agent Code Review System")
    parser.add_argument("--security-port", type=int, default=None, help="Security agent port")
    parser.add_argument("--performance-port", type=int, default=None, help="Performance agent port")
    parser.add_argument("--style-port", type=int, default=None, help="Style agent port")
    parser.add_argument("--mcp-port", type=int, default=None, help="MCP tools port")
    parser.add_argument("--model", type=str, default="gpt-4o", help="OpenAI model to use")
    parser.add_argument("--temperature", type=float, default=0.1, help="Temperature for generation")
    return parser.parse_args()

class SecurityAnalysisAgent(A2AServer):
    """Specialized agent for security analysis"""
    
    def __init__(self, openai_server, agent_card):
        super().__init__(agent_card=agent_card)
        self.openai_server = openai_server
    
    def handle_message(self, message):
        """Handle security analysis requests"""
        return self.openai_server.handle_message(message)

class PerformanceAnalysisAgent(A2AServer):
    """Specialized agent for performance analysis"""
    
    def __init__(self, openai_server, agent_card):
        super().__init__(agent_card=agent_card)
        self.openai_server = openai_server
    
    def handle_message(self, message):
        """Handle performance analysis requests"""
        return self.openai_server.handle_message(message)

class StyleAnalysisAgent(A2AServer):
    """Specialized agent for style and best practices analysis"""
    
    def __init__(self, openai_server, agent_card):
        super().__init__(agent_card=agent_card)
        self.openai_server = openai_server
    
    def handle_message(self, message):
        """Handle style analysis requests"""
        return self.openai_server.handle_message(message)

def create_security_agent(model, temperature, port):
    """Create security analysis agent"""
    agent_card = AgentCard(
        name="Security Analysis Expert",
        description="Specialized in identifying security vulnerabilities, injection attacks, authentication issues, and secure coding practices",
        url=f"http://localhost:{port}",
        version="1.0.0",
        skills=[
            AgentSkill(
                name="Vulnerability Detection",
                description="Identify SQL injection, XSS, CSRF, and other security vulnerabilities",
                examples=["Check for SQL injection risks", "Analyze authentication mechanisms"]
            ),
            AgentSkill(
                name="Secure Coding Practices",
                description="Review code for security best practices and compliance",
                examples=["Review input validation", "Check encryption implementation"]
            ),
            AgentSkill(
                name="Access Control Analysis",
                description="Analyze authorization and access control mechanisms",
                examples=["Review user permissions", "Check API security"]
            )
        ]
    )
    
    openai_server = OpenAIA2AServer(
        api_key=os.environ["OPENAI_API_KEY"],
        model=model,
        temperature=temperature,
        system_prompt="""You are a cybersecurity expert specializing in code security analysis. 
        Focus on identifying security vulnerabilities, insecure coding practices, and potential attack vectors.
        Provide specific, actionable security recommendations with severity levels (Critical, High, Medium, Low).
        Always explain the potential impact of security issues and how to fix them."""
    )
    
    return SecurityAnalysisAgent(openai_server, agent_card)

def create_performance_agent(model, temperature, port):
    """Create performance analysis agent"""
    agent_card = AgentCard(
        name="Performance Analysis Expert",
        description="Specialized in identifying performance bottlenecks, memory issues, and optimization opportunities",
        url=f"http://localhost:{port}",
        version="1.0.0",
        skills=[
            AgentSkill(
                name="Algorithm Complexity Analysis",
                description="Analyze time and space complexity of algorithms",
                examples=["Identify O(n²) loops", "Analyze recursive function efficiency"]
            ),
            AgentSkill(
                name="Memory Usage Optimization",
                description="Identify memory leaks and inefficient memory usage",
                examples=["Check for memory leaks", "Analyze object lifecycle"]
            ),
            AgentSkill(
                name="Database Query Optimization",
                description="Optimize database queries and connection handling",
                examples=["Review SQL query performance", "Check connection pooling"]
            )
        ]
    )
    
    openai_server = OpenAIA2AServer(
        api_key=os.environ["OPENAI_API_KEY"],
        model=model,
        temperature=temperature,
        system_prompt="""You are a performance optimization expert specializing in code performance analysis.
        Focus on identifying performance bottlenecks, inefficient algorithms, memory issues, and optimization opportunities.
        Provide specific performance improvement recommendations with estimated impact.
        Always suggest concrete optimization strategies and best practices."""
    )
    
    return PerformanceAnalysisAgent(openai_server, agent_card)

def create_style_agent(model, temperature, port):
    """Create style analysis agent"""
    agent_card = AgentCard(
        name="Code Style & Best Practices Expert",
        description="Specialized in code style, maintainability, and software engineering best practices",
        url=f"http://localhost:{port}",
        version="1.0.0",
        skills=[
            AgentSkill(
                name="Code Style Analysis",
                description="Review code formatting, naming conventions, and style consistency",
                examples=["Check naming conventions", "Review code formatting"]
            ),
            AgentSkill(
                name="Maintainability Review",
                description="Analyze code structure, documentation, and maintainability",
                examples=["Review function complexity", "Check documentation quality"]
            ),
            AgentSkill(
                name="Best Practices Compliance",
                description="Ensure adherence to language-specific best practices and patterns",
                examples=["Review design patterns usage", "Check error handling"]
            )
        ]
    )
    
    openai_server = OpenAIA2AServer(
        api_key=os.environ["OPENAI_API_KEY"],
        model=model,
        temperature=temperature,
        system_prompt="""You are a software engineering expert specializing in code quality, style, and best practices.
        Focus on code readability, maintainability, proper documentation, and adherence to coding standards.
        Provide specific recommendations for improving code structure, naming, and overall quality.
        Always suggest refactoring opportunities and architectural improvements."""
    )
    
    return StyleAnalysisAgent(openai_server, agent_card)

def main():
    """Main function"""
    if not check_api_key():
        return 1
    
    args = parse_arguments()
    
    # Find available ports
    security_port = args.security_port or find_available_port(5000, 20)
    performance_port = args.performance_port or find_available_port(5100, 20)
    style_port = args.style_port or find_available_port(5200, 20)
    mcp_port = args.mcp_port or find_available_port(7000, 20)
    
    print(f"🔍 Security Agent port: {security_port}")
    print(f"🔍 Performance Agent port: {performance_port}")
    print(f"🔍 Style Agent port: {style_port}")
    print(f"🔍 MCP Tools port: {mcp_port}")
    
    # Step 1: Create specialized A2A agents
    print("\n📝 Step 1: Creating Specialized A2A Agents")
    
    security_agent = create_security_agent(args.model, args.temperature, security_port)
    performance_agent = create_performance_agent(args.model, args.temperature, performance_port)
    style_agent = create_style_agent(args.model, args.temperature, style_port)
    
    # Start A2A servers
    def run_a2a_server(server, host="0.0.0.0", port=None):
        run_server(server, host=host, port=port)
    
    print("\nStarting A2A servers...")
    security_thread = run_server_in_thread(run_a2a_server, security_agent, port=security_port)
    performance_thread = run_server_in_thread(run_a2a_server, performance_agent, port=performance_port)
    style_thread = run_server_in_thread(run_a2a_server, style_agent, port=style_port)
    
    # Step 2: Create MCP Server with Code Analysis Tools
    print("\n📝 Step 2: Creating MCP Server with Code Analysis Tools")
    
    mcp_server = FastMCP(
        name="Code Analysis Tools",
        description="Tools for automated code analysis and static code checking"
    )
    
    @mcp_server.tool(
        name="static_security_scan",
        description="Run static security analysis using Bandit and custom security checks"
    )
    def static_security_scan(code_content=None, **kwargs):
        """Run static security analysis on code"""
        try:
            if 'input' in kwargs:
                code_content = kwargs['input']
            
            if not code_content:
                return {"text": "Error: No code content provided"}
            
            # Create temporary file for analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write(str(code_content))
                temp_file = f.name
            
            try:
                # Run Bandit security scan
                result = subprocess.run([
                    'bandit', '-f', 'json', temp_file
                ], capture_output=True, text=True)
                
                if result.stdout:
                    bandit_results = json.loads(result.stdout)
                else:
                    bandit_results = {"results": []}
                
                # Custom security checks
                security_issues = []
                
                # Check for common security anti-patterns
                if 'eval(' in code_content:
                    security_issues.append({
                        "severity": "HIGH",
                        "issue": "Use of eval() function detected",
                        "line": "Multiple locations",
                        "recommendation": "Replace eval() with safer alternatives like ast.literal_eval()"
                    })
                
                if 'exec(' in code_content:
                    security_issues.append({
                        "severity": "HIGH", 
                        "issue": "Use of exec() function detected",
                        "line": "Multiple locations",
                        "recommendation": "Avoid exec() or implement strict input validation"
                    })
                
                if re.search(r'password\s*=\s*["\'][^"\']+["\']', code_content, re.IGNORECASE):
                    security_issues.append({
                        "severity": "CRITICAL",
                        "issue": "Hardcoded password detected",
                        "line": "Multiple locations",
                        "recommendation": "Use environment variables or secure credential storage"
                    })
                
                return {"text": json.dumps({
                    "bandit_results": bandit_results,
                    "custom_security_checks": security_issues,
                    "summary": f"Found {len(bandit_results.get('results', []))} Bandit issues and {len(security_issues)} custom security issues"
                })}
                
            finally:
                os.unlink(temp_file)
                
        except Exception as e:
            return {"text": f"Error in security scan: {str(e)}"}
    
    @mcp_server.tool(
        name="performance_analysis",
        description="Analyze code for performance issues and optimization opportunities"
    )
    def performance_analysis(code_content=None, **kwargs):
        """Analyze code performance"""
        try:
            if 'input' in kwargs:
                code_content = kwargs['input']
            
            if not code_content:
                return {"text": "Error: No code content provided"}
            
            performance_issues = []
            
            # Analyze AST for performance anti-patterns
            try:
                tree = ast.parse(str(code_content))
                
                for node in ast.walk(tree):
                    # Check for nested loops
                    if isinstance(node, ast.For):
                        for child in ast.walk(node):
                            if isinstance(child, ast.For) and child != node:
                                performance_issues.append({
                                    "severity": "MEDIUM",
                                    "issue": "Nested loops detected - potential O(n²) complexity",
                                    "line": f"Line {node.lineno}",
                                    "recommendation": "Consider optimizing with hash maps or single-pass algorithms"
                                })
                    
                    # Check for list comprehensions in loops
                    if isinstance(node, ast.For):
                        for child in ast.walk(node):
                            if isinstance(child, ast.ListComp):
                                performance_issues.append({
                                    "severity": "LOW",
                                    "issue": "List comprehension inside loop",
                                    "line": f"Line {getattr(child, 'lineno', 'Unknown')}",
                                    "recommendation": "Consider moving list comprehension outside loop if possible"
                                })
            
            except SyntaxError as e:
                performance_issues.append({
                    "severity": "ERROR",
                    "issue": f"Syntax error prevents performance analysis: {str(e)}",
                    "line": f"Line {getattr(e, 'lineno', 'Unknown')}",
                    "recommendation": "Fix syntax errors before performance analysis"
                })
            
            # Check for string concatenation in loops
            if re.search(r'for.*:.*\+\s*=.*str', code_content, re.DOTALL):
                performance_issues.append({
                    "severity": "MEDIUM",
                    "issue": "String concatenation in loop detected",
                    "line": "Multiple locations",
                    "recommendation": "Use list.append() and ''.join() for better performance"
                })
            
            return {"text": json.dumps({
                "performance_issues": performance_issues,
                "summary": f"Found {len(performance_issues)} performance-related issues"
            })}
            
        except Exception as e:
            return {"text": f"Error in performance analysis: {str(e)}"}
    
    @mcp_server.tool(
        name="style_analysis", 
        description="Analyze code style, formatting, and best practices compliance"
    )
    def style_analysis(code_content=None, **kwargs):
        """Analyze code style and best practices"""
        try:
            if 'input' in kwargs:
                code_content = kwargs['input']
            
            if not code_content:
                return {"text": "Error: No code content provided"}
            
            style_issues = []
            
            # Basic style checks
            lines = str(code_content).split('\n')
            
            for i, line in enumerate(lines, 1):
                # Line length check
                if len(line) > 88:  # PEP 8 recommends 79, but 88 is common
                    style_issues.append({
                        "severity": "LOW",
                        "issue": f"Line too long ({len(line)} characters)",
                        "line": f"Line {i}",
                        "recommendation": "Break long lines for better readability"
                    })
                
                # Trailing whitespace
                if line.rstrip() != line:
                    style_issues.append({
                        "severity": "LOW",
                        "issue": "Trailing whitespace detected",
                        "line": f"Line {i}",
                        "recommendation": "Remove trailing whitespace"
                    })
            
            # Function naming convention
            if re.search(r'def [A-Z]', code_content):
                style_issues.append({
                    "severity": "MEDIUM",
                    "issue": "Function names should be lowercase with underscores",
                    "line": "Multiple locations",
                    "recommendation": "Use snake_case for function names (PEP 8)"
                })
            
            # Missing docstrings
            try:
                tree = ast.parse(str(code_content))
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                        if not ast.get_docstring(node):
                            style_issues.append({
                                "severity": "MEDIUM",
                                "issue": f"{node.__class__.__name__} '{node.name}' missing docstring",
                                "line": f"Line {node.lineno}",
                                "recommendation": "Add docstring to document purpose and usage"
                            })
            except SyntaxError:
                pass
            
            return {"text": json.dumps({
                "style_issues": style_issues,
                "summary": f"Found {len(style_issues)} style-related issues"
            })}
            
        except Exception as e:
            return {"text": f"Error in style analysis: {str(e)}"}
    
    # Start MCP server
    print(f"\nStarting MCP server on http://localhost:{mcp_port}...")
    
    def run_mcp_server(server, host="0.0.0.0", port=mcp_port):
        server.run(host=host, port=port)
    
    mcp_thread = run_server_in_thread(run_mcp_server, mcp_server)
    time.sleep(5)
    
    # Step 3: Convert agents and tools to LangChain
    print("\n📝 Step 3: Converting Agents and Tools to LangChain")
    
    try:
        security_langchain = to_langchain_agent(f"http://localhost:{security_port}")
        performance_langchain = to_langchain_agent(f"http://localhost:{performance_port}")
        style_langchain = to_langchain_agent(f"http://localhost:{style_port}")
        
        security_scan_tool = to_langchain_tool(f"http://localhost:{mcp_port}", "static_security_scan")
        performance_tool = to_langchain_tool(f"http://localhost:{mcp_port}", "performance_analysis") 
        style_tool = to_langchain_tool(f"http://localhost:{mcp_port}", "style_analysis")
        
        print("✅ Successfully converted all agents and tools to LangChain")
        
    except Exception as e:
        print(f"❌ Error converting to LangChain: {e}")
        return 1
    
    # Step 4: Create Meta Code Review Agent
    print("\n📝 Step 4: Creating Meta Code Review Agent")
    
    llm = ChatOpenAI(model=args.model, temperature=args.temperature)
    
    def ask_security_expert(query):
        """Ask security analysis expert"""
        try:
            result = security_langchain.invoke(query)
            return result.get('output', 'No response')
        except Exception as e:
            return f"Error querying security expert: {str(e)}"
    
    def ask_performance_expert(query):
        """Ask performance analysis expert"""
        try:
            result = performance_langchain.invoke(query)
            return result.get('output', 'No response')
        except Exception as e:
            return f"Error querying performance expert: {str(e)}"
    
    def ask_style_expert(query):
        """Ask style analysis expert"""
        try:
            result = style_langchain.invoke(query)
            return result.get('output', 'No response')
        except Exception as e:
            return f"Error querying style expert: {str(e)}"
    
    def run_security_scan(code):
        """Run automated security scan"""
        try:
            return security_scan_tool.invoke(str(code))
        except Exception as e:
            return f"Error in security scan: {str(e)}"
    
    def run_performance_analysis(code):
        """Run automated performance analysis"""
        try:
            return performance_tool.invoke(str(code))
        except Exception as e:
            return f"Error in performance analysis: {str(e)}"
    
    def run_style_analysis(code):
        """Run automated style analysis"""
        try:
            return style_tool.invoke(str(code))
        except Exception as e:
            return f"Error in style analysis: {str(e)}"
    
    tools = [
        Tool(
            name="SecurityExpert",
            func=ask_security_expert,
            description="Ask security expert about vulnerabilities, secure coding practices, and security concerns"
        ),
        Tool(
            name="PerformanceExpert", 
            func=ask_performance_expert,
            description="Ask performance expert about optimization, bottlenecks, and efficiency improvements"
        ),
        Tool(
            name="StyleExpert",
            func=ask_style_expert,
            description="Ask style expert about code quality, maintainability, and best practices"
        ),
        Tool(
            name="SecurityScan",
            func=run_security_scan,
            description="Run automated security scan on code. Input should be the code to analyze."
        ),
        Tool(
            name="PerformanceAnalysis",
            func=run_performance_analysis,
            description="Run automated performance analysis on code. Input should be the code to analyze."
        ),
        Tool(
            name="StyleAnalysis",
            func=run_style_analysis,
            description="Run automated style analysis on code. Input should be the code to analyze."
        )
    ]
    
    meta_agent = initialize_agent(
        tools,
        llm,
        agent=AgentType.OPENAI_FUNCTIONS,
        verbose=True,
        handle_parsing_errors=True
    )
    
    # Step 5: Test the Code Review System
    print("\n📝 Step 5: Testing Code Review System")
    
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
    
    print(f"\nAnalyzing test code...")
    print("=" * 50)
    
    review_query = f"""
    Please perform a comprehensive code review of this Python code:
    
    ```python
{test_code}
    ```
    
    Analyze for:
    1. Security vulnerabilities and issues
    2. Performance problems and optimization opportunities  
    3. Style issues and best practices violations
    
    Provide a detailed report with specific recommendations and severity levels.
    """
    
    try:
        result = meta_agent.invoke(review_query)
        print("\n🔍 COMPREHENSIVE CODE REVIEW REPORT:")
        print("=" * 50)
        print(result.get('output', 'No response'))
        
    except Exception as e:
        print(f"❌ Error during code review: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n✅ Code Review System is running!")
    print("The system is ready to analyze your code.")
    print("Press Ctrl+C to stop the servers and exit")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down...")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
        sys.exit(0)