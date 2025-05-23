#!/usr/bin/env python3
"""
Web Interface for Multi-Agent Code Review System
Flask-based web UI for easy code analysis
"""

from flask import Flask, render_template_string, request, jsonify
import os
import sys
import json
import threading
import time
from typing import Dict

# Import our enhanced system
try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

app = Flask(__name__)

# HTML Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 Multi-Agent Code Review System</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            color: white;
            margin-bottom: 30px;
        }
        
        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2rem;
            opacity: 0.9;
        }
        
        .main-card {
            background: white;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .card-header {
            background: linear-gradient(90deg, #4CAF50, #45a049);
            color: white;
            padding: 20px;
            text-align: center;
        }
        
        .card-body {
            padding: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }
        
        textarea {
            width: 100%;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            resize: vertical;
            transition: border-color 0.3s;
        }
        
        textarea:focus {
            outline: none;
            border-color: #4CAF50;
        }
        
        .btn {
            background: linear-gradient(90deg, #4CAF50, #45a049);
            color: white;
            border: none;
            padding: 15px 30px;
            font-size: 16px;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
            width: 100%;
            margin-top: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(76,175,80,0.3);
        }
        
        .btn:disabled {
            background: #ccc;
            cursor: not-allowed;
            transform: none;
        }
        
        .loading {
            display: none;
            text-align: center;
            margin: 20px 0;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #4CAF50;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 10px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            margin-top: 30px;
            display: none;
        }
        
        .result-section {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            border-left: 4px solid #4CAF50;
        }
        
        .result-section h3 {
            color: #2c3e50;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .result-content {
            background: white;
            padding: 15px;
            border-radius: 6px;
            white-space: pre-wrap;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.6;
            border: 1px solid #ddd;
        }
        
        .error {
            background: #ffebee;
            border-left-color: #f44336;
            color: #c62828;
        }
        
        .success {
            background: #e8f5e8;
            border-left-color: #4CAF50;
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .feature-card {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            color: white;
        }
        
        .feature-card h3 {
            margin-bottom: 10px;
            font-size: 1.2rem;
        }
        
        .sample-code {
            background: #2d3748;
            color: #e2e8f0;
            padding: 15px;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            margin: 10px 0;
            overflow-x: auto;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Multi-Agent Code Review System</h1>
            <p>AI-Powered Security, Performance & Style Analysis</p>
            
            <div class="feature-grid">
                <div class="feature-card">
                    <h3>🔒 Security Analysis</h3>
                    <p>Detects vulnerabilities, injection attacks, and security issues</p>
                </div>
                <div class="feature-card">
                    <h3>⚡ Performance Review</h3>
                    <p>Identifies bottlenecks and optimization opportunities</p>
                </div>
                <div class="feature-card">
                    <h3>📝 Style & Quality</h3>
                    <p>Ensures code quality and best practices compliance</p>
                </div>
            </div>
        </div>
        
        <div class="main-card">
            <div class="card-header">
                <h2>🤖 Submit Your Code for AI Review</h2>
                <p>Get comprehensive analysis from specialized AI agents</p>
            </div>
            
            <div class="card-body">
                <form id="reviewForm">
                    <div class="form-group">
                        <label for="codeInput">📄 Paste Your Code Here:</label>
                        <textarea 
                            id="codeInput" 
                            name="code" 
                            rows="15" 
                            placeholder="# Paste your code here for analysis
# Example:
def login(username, password):
    sql = \"SELECT * FROM users WHERE username = '\" + username + \"'\"
    return execute_query(sql)"
                            required
                        ></textarea>
                    </div>
                    
                    <button type="submit" class="btn" id="submitBtn">
                        🚀 Analyze Code
                    </button>
                </form>
                
                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>🤖 AI agents are analyzing your code...</p>
                    <p><small>This may take 30-60 seconds</small></p>
                </div>
                
                <div class="results" id="results">
                    <div class="result-section success">
                        <h3>🔒 Security Analysis</h3>
                        <div class="result-content" id="securityResult"></div>
                    </div>
                    
                    <div class="result-section success">
                        <h3>⚡ Performance Analysis</h3>
                        <div class="result-content" id="performanceResult"></div>
                    </div>
                    
                    <div class="result-section success">
                        <h3>📝 Style & Quality Analysis</h3>
                        <div class="result-content" id="styleResult"></div>
                    </div>
                    
                    <div class="result-section">
                        <h3>🔧 Automated Scan Results</h3>
                        <div class="result-content" id="automatedResult"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('reviewForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const code = document.getElementById('codeInput').value;
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const results = document.getElementById('results');
            
            // Show loading state
            submitBtn.disabled = true;
            submitBtn.textContent = '🔄 Analyzing...';
            loading.style.display = 'block';
            results.style.display = 'none';
            
            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ code: code })
                });
                
                const data = await response.json();
                
                if (data.error) {
                    throw new Error(data.error);
                }
                
                // Display results
                document.getElementById('securityResult').textContent = data.ai_analysis.security;
                document.getElementById('performanceResult').textContent = data.ai_analysis.performance;
                document.getElementById('styleResult').textContent = data.ai_analysis.style;
                
                const automatedResults = [
                    '🛡️ ' + data.automated_scans.security,
                    '🚀 ' + data.automated_scans.performance,
                    '✨ ' + data.automated_scans.style
                ].join('\\n\\n');
                
                document.getElementById('automatedResult').textContent = automatedResults;
                
                results.style.display = 'block';
                
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                // Reset button state
                submitBtn.disabled = false;
                submitBtn.textContent = '🚀 Analyze Code';
                loading.style.display = 'none';
            }
        });
        
        // Sample code button
        function loadSampleCode() {
            const sampleCode = `def calculatePassword(username, password="admin123"):
    # Security issue: hardcoded password
    if password == "admin123":
        return True
    
    # Security issue: SQL injection vulnerability
    sql = "SELECT * FROM users WHERE username = '" + username + "'"
    
    # Security issue: using eval
    result = eval("execute_query('" + sql + "')")
    
    # Performance issue: nested loops
    for i in range(len(result)):
        for j in range(len(result[i])):
            if result[i][j] == password:
                return True
    
    return False

class myClass:  # Style issue: naming
    def MyMethod(self):  # Style issue: naming
        pass`;
            
            document.getElementById('codeInput').value = sampleCode;
        }
    </script>
</body>
</html>
"""

# Simple AI agents (same as enhanced system)
class SimpleA2AAgent:
    def __init__(self, name: str, system_prompt: str):
        self.name = name
        self.system_prompt = system_prompt
        if OPENAI_AVAILABLE and os.environ.get("OPENAI_API_KEY"):
            self.client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))
        else:
            self.client = None
    
    def analyze(self, code: str, query: str) -> str:
        if not self.client:
            return f"OpenAI not available for {self.name} analysis"
        
        try:
            response = self.client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": f"Analyze this code:\n\n{code}\n\nFocus on: {query}"}
                ],
                max_tokens=1000,
                temperature=0.1
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error in {self.name}: {str(e)}"

# Automated scanning functions
def security_scan_tool(code: str) -> str:
    issues = []
    
    if 'eval(' in code:
        issues.append("🔴 HIGH: eval() function detected - security risk")
    
    if 'exec(' in code:
        issues.append("🔴 HIGH: exec() function detected - security risk")
    
    import re
    if re.search(r'password\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
        issues.append("🔴 CRITICAL: Hardcoded password detected")
    
    if re.search(r'SELECT.*\+.*["\']', code, re.IGNORECASE):
        issues.append("🔴 CRITICAL: Potential SQL injection vulnerability")
    
    return "Security Scan Results:\n" + "\n".join(issues) if issues else "✅ No security issues found"

def performance_scan_tool(code: str) -> str:
    issues = []
    
    if 'for ' in code and code.count('for ') >= 2:
        issues.append("🟡 MEDIUM: Nested loops detected - O(n²) complexity risk")
    
    import re
    if re.search(r'for.*:.*\+\s*=.*str', code, re.DOTALL):
        issues.append("🟡 MEDIUM: String concatenation in loop - performance issue")
    
    return "Performance Scan Results:\n" + "\n".join(issues) if issues else "✅ No performance issues found"

def style_scan_tool(code: str) -> str:
    issues = []
    lines = code.split('\n')
    
    for i, line in enumerate(lines, 1):
        if len(line) > 88:
            issues.append(f"🟢 LOW: Line {i} too long ({len(line)} chars)")
    
    import re
    if re.search(r'def [A-Z]', code):
        issues.append("🟡 MEDIUM: Function names should be snake_case")
    
    if re.search(r'class [a-z]', code):
        issues.append("🟡 MEDIUM: Class names should be PascalCase")
    
    return "Style Scan Results:\n" + "\n".join(issues) if issues else "✅ No style issues found"

# Web interface setup
class WebCodeReviewSystem:
    def __init__(self):
        self.security_agent = SimpleA2AAgent(
            "Security Expert",
            "You are a cybersecurity expert. Analyze code for security vulnerabilities, provide specific recommendations with severity levels (Critical, High, Medium, Low). Be concise but thorough."
        )
        
        self.performance_agent = SimpleA2AAgent(
            "Performance Expert", 
            "You are a performance optimization expert. Analyze code for bottlenecks, inefficiencies, and optimization opportunities. Provide specific suggestions with impact levels."
        )
        
        self.style_agent = SimpleA2AAgent(
            "Code Quality Expert",
            "You are a code quality expert. Analyze code for style, maintainability, documentation, and best practices compliance. Focus on readability and maintainability."
        )
    
    def comprehensive_review(self, code: str) -> Dict:
        """Perform comprehensive code review"""
        
        # Run AI agent analysis
        security_analysis = self.security_agent.analyze(code, "security vulnerabilities and secure coding practices")
        performance_analysis = self.performance_agent.analyze(code, "performance bottlenecks and optimization opportunities")
        style_analysis = self.style_agent.analyze(code, "code style, maintainability, and best practices")
        
        # Run automated tool scans
        security_scan = security_scan_tool(code)
        performance_scan = performance_scan_tool(code)
        style_scan = style_scan_tool(code)
        
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

# Initialize the system
review_system = WebCodeReviewSystem()

@app.route('/')
def index():
    """Main page"""
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze_code():
    """Analyze code endpoint"""
    try:
        data = request.get_json()
        code = data.get('code', '')
        
        if not code.strip():
            return jsonify({'error': 'No code provided'}), 400
        
        # Perform analysis
        results = review_system.comprehensive_review(code)
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'openai_available': OPENAI_AVAILABLE,
        'api_key_configured': bool(os.environ.get("OPENAI_API_KEY"))
    })

if __name__ == '__main__':
    print("🚀 Starting Web Interface for Code Review System")
    print("="*50)
    
    # Check requirements
    if not OPENAI_AVAILABLE:
        print("⚠️  Warning: OpenAI library not available")
    
    if not os.environ.get("OPENAI_API_KEY"):
        print("⚠️  Warning: OPENAI_API_KEY not set")
    
    print("\n🌐 Starting web server...")
    print("📱 Open your browser and go to: http://localhost:5000")
    print("🔧 Health check available at: http://localhost:5000/health")
    print("\n📋 Features available:")
    print("   • 🔒 AI-powered security analysis")
    print("   • ⚡ Performance optimization suggestions")
    print("   • 📝 Code style and quality review")
    print("   • 🔧 Automated vulnerability scanning")
    print("\n💡 Press Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
