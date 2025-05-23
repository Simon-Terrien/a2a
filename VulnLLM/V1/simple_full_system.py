# File: simple_full_system.py
#!/usr/bin/env python3
"""
Simplified Full Multi-Agent Code Review System
More robust version with better error handling
"""

import os
import re
import sys
import json
import threading
import time
from typing import Dict, List

# Check if libraries are available
try:
    from openai import OpenAI
    print("✅ OpenAI library loaded")
except ImportError:
    print("❌ OpenAI library not found")
    sys.exit(1)

class SimpleA2AAgent:
    """Simplified A2A-style agent"""
    def __init__(self, name: str, system_prompt: str):
        self.name = name
        self.system_prompt = system_prompt
        self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
    
    def analyze(self, code: str, query: str) -> str:
        """Analyze code with AI agent"""
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": f"Analyze this code:\n\n{code}\n\nFocus on: {query}"}
                ],
                max_tokens=1500,
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error in {self.name}: {str(e)}"

class SimpleMCPTool:
    """Simplified MCP-style tool"""
    def __init__(self, name: str, description: str, func):
        self.name = name
        self.description = description
        self.func = func
    
    def invoke(self, input_data: str) -> str:
        """Invoke the tool"""
        try:
            return self.func(input_data)
        except Exception as e:
            return f"Error in {self.name}: {str(e)}"

def security_scan_tool(code: str) -> str:
    """Security scanning tool"""
    issues = []
    
    # Basic security checks
    if 'eval(' in code:
        issues.append("🔴 HIGH: eval() function detected - security risk")
    
    if 'exec(' in code:
        issues.append("🔴 HIGH: exec() function detected - security risk")
    
    # Check for hardcoded passwords
    import re
    if re.search(r'password\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
        issues.append("🔴 CRITICAL: Hardcoded password detected")
    
    # Check for SQL injection
    if re.search(r'SELECT.*\+.*["\']', code, re.IGNORECASE):
        issues.append("🔴 CRITICAL: Potential SQL injection vulnerability")
    
    return f"Security Scan Results:\n" + "\n".join(issues) if issues else "✅ No security issues found"

def performance_scan_tool(code: str) -> str:
    """Performance scanning tool"""
    issues = []
    
    # Check for nested loops
    if 'for ' in code and code.count('for ') >= 2:
        lines = code.split('\n')
        for i, line in enumerate(lines):
            if 'for ' in line:
                # Check subsequent lines for another for loop
                for j in range(i+1, min(i+10, len(lines))):
                    if 'for ' in lines[j] and lines[j].strip().startswith('for'):
                        issues.append("🟡 MEDIUM: Nested loops detected - O(n²) complexity risk")
                        break
    
    # Check for string concatenation in loops
    if re.search(r'for.*:.*\+\s*=.*str', code, re.DOTALL):
        issues.append("🟡 MEDIUM: String concatenation in loop - performance issue")
    
    return f"Performance Scan Results:\n" + "\n".join(issues) if issues else "✅ No performance issues found"

def style_scan_tool(code: str) -> str:
    """Style scanning tool"""
    issues = []
    lines = code.split('\n')
    
    # Check line length
    for i, line in enumerate(lines, 1):
        if len(line) > 88:
            issues.append(f"🟢 LOW: Line {i} too long ({len(line)} chars)")
    
    # Check function naming
    if re.search(r'def [A-Z]', code):
        issues.append("🟡 MEDIUM: Function names should be snake_case")
    
    # Check for missing docstrings
    if re.search(r'def \w+\([^)]*\):\s*\n\s*[^"\']{3}', code):
        issues.append("🟡 MEDIUM: Functions missing docstrings")
    
    return f"Style Scan Results:\n" + "\n".join(issues) if issues else "✅ No style issues found"

class EnhancedCodeReviewSystem:
    """Enhanced multi-agent code review system"""
    
    def __init__(self):
        print("🚀 Initializing Enhanced Code Review System...")
        
        # Create AI agents
        self.security_agent = SimpleA2AAgent(
            "Security Expert",
            "You are a cybersecurity expert. Analyze code for security vulnerabilities, provide specific recommendations, and rate severity levels."
        )
        
        self.performance_agent = SimpleA2AAgent(
            "Performance Expert", 
            "You are a performance optimization expert. Analyze code for bottlenecks, inefficiencies, and optimization opportunities."
        )
        
        self.style_agent = SimpleA2AAgent(
            "Code Quality Expert",
            "You are a code quality expert. Analyze code for style, maintainability, and best practices compliance."
        )
        
        # Create MCP tools
        self.security_tool = SimpleMCPTool("SecurityScan", "Automated security scanning", security_scan_tool)
        self.performance_tool = SimpleMCPTool("PerformanceScan", "Automated performance analysis", performance_scan_tool)
        self.style_tool = SimpleMCPTool("StyleScan", "Automated style checking", style_scan_tool)
        
        print("✅ All agents and tools initialized")
    
    def comprehensive_review(self, code: str) -> Dict:
        """Perform comprehensive code review"""
        print("\n🔍 Starting comprehensive code review...")
        
        results = {}
        
        # Run AI agent analysis
        print("📋 Running AI Agent Analysis...")
        
        security_analysis = self.security_agent.analyze(code, "security vulnerabilities and secure coding practices")
        performance_analysis = self.performance_agent.analyze(code, "performance bottlenecks and optimization opportunities")
        style_analysis = self.style_agent.analyze(code, "code style, maintainability, and best practices")
        
        # Run automated tool scans
        print("🔧 Running Automated Tool Scans...")
        
        security_scan = self.security_tool.invoke(code)
        performance_scan = self.performance_tool.invoke(code)
        style_scan = self.style_tool.invoke(code)
        
        return {
            "ai_analysis": {
                "security": security_analysis,
                "performance": performance_analysis,
                "style": style_analysis
            },
            "automated_scans": {
                "security": security_scan,
                "performance": performance_scan,
                "style": style_scan
            }
        }
    
    def print_comprehensive_report(self, results: Dict):
        """Print detailed comprehensive report"""
        print("\n" + "="*70)
        print("🔍 COMPREHENSIVE AI + AUTOMATED CODE REVIEW REPORT")
        print("="*70)
        
        print("\n🤖 AI AGENT ANALYSIS:")
        print("-" * 50)
        
        print("\n🔒 SECURITY EXPERT ANALYSIS:")
        print(results["ai_analysis"]["security"])
        
        print("\n⚡ PERFORMANCE EXPERT ANALYSIS:")
        print(results["ai_analysis"]["performance"])
        
        print("\n📝 CODE QUALITY EXPERT ANALYSIS:")
        print(results["ai_analysis"]["style"])
        
        print("\n🔧 AUTOMATED TOOL SCANS:")
        print("-" * 50)
        
        print("\n🛡️", results["automated_scans"]["security"])
        print("\n🚀", results["automated_scans"]["performance"])
        print("\n✨", results["automated_scans"]["style"])

def main():
    """Main function"""
    print("🚀 Enhanced Multi-Agent Code Review System")
    print("="*50)
    
    # Check API key
    if not os.environ.get("OPENAI_API_KEY"):
        print("❌ Error: OPENAI_API_KEY not set")
        return 1
    
    # Test code with issues
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
    
    print("📝 Analyzing test code...")
    print("-" * 30)
    
    try:
        # Create system and run analysis
        system = EnhancedCodeReviewSystem()
        results = system.comprehensive_review(test_code)
        system.print_comprehensive_report(results)
        
        print(f"\n✅ Analysis completed successfully!")
        print("\n💡 This demonstrates the power of combining:")
        print("   • AI agents for intelligent analysis")
        print("   • Automated tools for consistent scanning")
        print("   • Multi-agent collaboration for comprehensive review")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
