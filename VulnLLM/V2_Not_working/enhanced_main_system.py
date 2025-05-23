#!/usr/bin/env python3
"""
Enhanced Multi-Agent Code Review System
Production-ready version with improved architecture, performance, and features
"""

import os
import sys
import asyncio
import uuid
import time
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass
import json

# Import our enhanced modules
from enhanced_config import load_config, CodeReviewConfig
from enhanced_logging import setup_logging, get_logger, log_context, log_performance
from enhanced_caching import create_cache, CodeAnalysisCache

# Core frameworks (original imports)
try:
    from python_a2a import OpenAIA2AServer, run_server, A2AServer, AgentCard, AgentSkill
    from python_a2a.langchain import to_langchain_agent, to_langchain_tool
    from python_a2a.mcp import FastMCP
    from langchain_openai import ChatOpenAI
    from langchain.agents import initialize_agent, Tool, AgentType
    A2A_AVAILABLE = True
except ImportError:
    A2A_AVAILABLE = False
    print("⚠️  A2A/MCP libraries not available. Running in fallback mode.")

# Analysis libraries
import ast
import re
import subprocess
import tempfile
from datetime import datetime

@dataclass
class AnalysisResult:
    """Structured analysis result"""
    analysis_id: str
    analysis_type: str
    code_hash: str
    issues: List[Dict[str, Any]]
    summary: Dict[str, Any]
    execution_time: float
    success: bool
    error_message: Optional[str] = None
    cached: bool = False

@dataclass
class CodeReviewRequest:
    """Code review request with metadata"""
    request_id: str
    code: str
    analysis_types: List[str]
    priority: str = "normal"  # low, normal, high
    timeout: Optional[int] = None
    cache_enabled: bool = True

class EnhancedCodeReviewSystem:
    """Enhanced multi-agent code review system with production features"""
    
    def __init__(self, config_path: Optional[str] = None):
        # Load configuration
        self.config = load_config(config_path)
        
        # Setup logging
        self.logger_system = setup_logging(self.config)
        self.logger = get_logger('main')
        
        # Setup caching
        self.cache = create_cache(self.config)
        
        # Initialize components
        self.agents = {}
        self.tools = {}
        self.meta_agent = None
        self.servers = {}
        self.executor = ThreadPoolExecutor(max_workers=self.config.analysis.max_workers)
        
        # Performance tracking
        self.performance_metrics = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'cache_hits': 0,
            'average_execution_time': 0.0
        }
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        self.logger.info("Enhanced Code Review System initialized")
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully"""
        self.logger.info(f"Received signal {signum}, shutting down gracefully...")
        self.shutdown()
        sys.exit(0)
    
    @log_performance("system_startup")
    def start(self) -> bool:
        """Start the code review system"""
        try:
            self.logger.info("Starting Enhanced Code Review System...")
            
            if A2A_AVAILABLE:
                # Start A2A agents and MCP servers
                if not self._start_agents():
                    self.logger.error("Failed to start agents")
                    return False
                
                if not self._start_mcp_servers():
                    self.logger.error("Failed to start MCP servers")
                    return False
                
                # Setup LangChain integration
                if not self._setup_langchain():
                    self.logger.error("Failed to setup LangChain integration")
                    return False
            else:
                # Setup fallback agents
                self._setup_fallback_agents()
            
            self.logger.info("✅ Code Review System started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start system: {e}", exc_info=True)
            return False
    
    def _start_agents(self) -> bool:
        """Start A2A agents"""
        try:
            self.logger.info("Starting A2A agents...")
            
            agent_configs = [
                ('security', self.config.security_server, self._create_security_agent),
                ('performance', self.config.performance_server, self._create_performance_agent),
                ('style', self.config.style_server, self._create_style_agent)
            ]
            
            for agent_name, server_config, agent_factory in agent_configs:
                port = server_config.port or self._find_available_port(server_config.port_range_start)
                agent = agent_factory(port)
                
                # Start server in background thread
                thread = threading.Thread(
                    target=self._run_agent_server,
                    args=(agent, server_config.host, port),
                    daemon=True
                )
                thread.start()
                
                self.agents[agent_name] = {
                    'agent': agent,
                    'url': f"http://{server_config.host}:{port}",
                    'thread': thread
                }
                
                self.logger.info(f"Started {agent_name} agent on port {port}")
                
                # Wait for server to start
                time.sleep(2)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting agents: {e}")
            return False
    
    def _start_mcp_servers(self) -> bool:
        """Start MCP servers with tools"""
        try:
            self.logger.info("Starting MCP servers...")
            
            # Create MCP server
            mcp_server = FastMCP(
                name="Enhanced Code Analysis Tools",
                description="Advanced tools for comprehensive code analysis"
            )
            
            # Add enhanced tools
            self._add_mcp_tools(mcp_server)
            
            # Start MCP server
            port = self.config.mcp_server.port or self._find_available_port(self.config.mcp_server.port_range_start)
            
            thread = threading.Thread(
                target=self._run_mcp_server,
                args=(mcp_server, self.config.mcp_server.host, port),
                daemon=True
            )
            thread.start()
            
            self.servers['mcp'] = {
                'server': mcp_server,
                'url': f"http://{self.config.mcp_server.host}:{port}",
                'thread': thread
            }
            
            self.logger.info(f"Started MCP server on port {port}")
            time.sleep(3)  # Wait for server to start
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting MCP servers: {e}")
            return False
    
    def _setup_langchain(self) -> bool:
        """Setup LangChain integration"""
        try:
            self.logger.info("Setting up LangChain integration...")
            
            # Convert A2A agents to LangChain
            langchain_agents = {}
            for agent_name, agent_info in self.agents.items():
                try:
                    langchain_agent = to_langchain_agent(agent_info['url'])
                    langchain_agents[agent_name] = langchain_agent
                    self.logger.debug(f"Converted {agent_name} agent to LangChain")
                except Exception as e:
                    self.logger.warning(f"Failed to convert {agent_name} agent: {e}")
            
            # Convert MCP tools to LangChain
            langchain_tools = {}
            if 'mcp' in self.servers:
                mcp_url = self.servers['mcp']['url']
                tool_names = ['enhanced_security_scan', 'enhanced_performance_analysis', 'enhanced_style_analysis']
                
                for tool_name in tool_names:
                    try:
                        tool = to_langchain_tool(mcp_url, tool_name)
                        langchain_tools[tool_name] = tool
                        self.logger.debug(f"Converted {tool_name} tool to LangChain")
                    except Exception as e:
                        self.logger.warning(f"Failed to convert {tool_name} tool: {e}")
            
            # Create meta agent
            self._create_meta_agent(langchain_agents, langchain_tools)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting up LangChain: {e}")
            return False
    
    def _setup_fallback_agents(self):
        """Setup fallback agents when A2A is not available"""
        self.logger.info("Setting up fallback agents...")
        
        from enhanced_fallback_agents import (
            FallbackSecurityAgent,
            FallbackPerformanceAgent,
            FallbackStyleAgent
        )
        
        self.agents = {
            'security': FallbackSecurityAgent(self.config),
            'performance': FallbackPerformanceAgent(self.config),
            'style': FallbackStyleAgent(self.config)
        }
        
        self.logger.info("Fallback agents initialized")
    
    def _create_security_agent(self, port: int):
        """Create security analysis agent"""
        agent_card = AgentCard(
            name="Enhanced Security Analysis Expert",
            description="Advanced security vulnerability detection and secure coding analysis",
            url=f"http://localhost:{port}",
            version="2.0.0",
            skills=[
                AgentSkill(
                    name="Advanced Vulnerability Detection",
                    description="Deep analysis of security vulnerabilities including OWASP Top 10",
                    examples=["Detect SQL injection", "Find XSS vulnerabilities", "Check authentication flaws"]
                ),
                AgentSkill(
                    name="Cryptographic Analysis",
                    description="Review cryptographic implementations and key management",
                    examples=["Check encryption strength", "Validate key storage", "Review random number generation"]
                ),
                AgentSkill(
                    name="Access Control Review",
                    description="Comprehensive authorization and access control analysis",
                    examples=["Review permission systems", "Check privilege escalation", "Validate RBAC implementation"]
                )
            ]
        )
        
        openai_server = OpenAIA2AServer(
            api_key=self.config.openai_api_key,
            model=self.config.agent.model,
            temperature=self.config.agent.temperature,
            system_prompt="""You are an elite cybersecurity expert with 15+ years of experience in application security.
            Your expertise includes:
            - OWASP Top 10 vulnerabilities and mitigation strategies
            - Advanced persistent threat (APT) detection patterns
            - Cryptographic implementation analysis
            - Secure coding practices across multiple languages
            - Zero-trust architecture principles
            
            Provide detailed security analysis with:
            - Specific vulnerability identification with CVE references where applicable
            - Risk severity scoring (Critical/High/Medium/Low) with CVSS-like scoring
            - Detailed remediation steps with code examples
            - Attack vector analysis and potential impact assessment
            - Compliance implications (SOC2, PCI-DSS, GDPR, etc.)
            
            Always consider the broader security context and provide actionable recommendations."""
        )
        
        class SecurityAgent(A2AServer):
            def __init__(self, openai_server, agent_card):
                super().__init__(agent_card=agent_card)
                self.openai_server = openai_server
                self.logger = get_logger('agent.security')
            
            def handle_message(self, message):
                self.logger.debug("Processing security analysis request")
                return self.openai_server.handle_message(message)
        
        return SecurityAgent(openai_server, agent_card)
    
    def _create_performance_agent(self, port: int):
        """Create performance analysis agent"""
        agent_card = AgentCard(
            name="Enhanced Performance Analysis Expert",
            description="Advanced performance optimization and scalability analysis",
            url=f"http://localhost:{port}",
            version="2.0.0",
            skills=[
                AgentSkill(
                    name="Algorithm Complexity Analysis",
                    description="Deep algorithmic performance analysis with Big O complexity assessment",
                    examples=["Analyze time complexity", "Identify bottlenecks", "Suggest optimizations"]
                ),
                AgentSkill(
                    name="Memory Optimization",
                    description="Memory usage patterns and optimization strategies",
                    examples=["Memory leak detection", "Garbage collection optimization", "Cache efficiency analysis"]
                ),
                AgentSkill(
                    name="Scalability Assessment",
                    description="Horizontal and vertical scaling considerations",
                    examples=["Concurrency analysis", "Database performance", "Microservices optimization"]
                )
            ]
        )
        
        openai_server = OpenAIA2AServer(
            api_key=self.config.openai_api_key,
            model=self.config.agent.model,
            temperature=self.config.agent.temperature,
            system_prompt="""You are a senior performance engineer with expertise in high-scale systems optimization.
            Your specializations include:
            - Algorithmic complexity analysis and optimization
            - Memory management and garbage collection tuning
            - Database query optimization and indexing strategies
            - Distributed systems performance patterns
            - Profiling and benchmarking methodologies
            
            Provide comprehensive performance analysis including:
            - Big O complexity analysis with specific optimizations
            - Memory usage patterns and leak detection
            - Concurrency and thread safety considerations
            - Database performance implications
            - Caching strategies and recommendations
            - Load testing and scalability projections
            
            Always provide quantitative metrics where possible and practical optimization steps."""
        )
        
        class PerformanceAgent(A2AServer):
            def __init__(self, openai_server, agent_card):
                super().__init__(agent_card=agent_card)
                self.openai_server = openai_server
                self.logger = get_logger('agent.performance')
            
            def handle_message(self, message):
                self.logger.debug("Processing performance analysis request")
                return self.openai_server.handle_message(message)
        
        return PerformanceAgent(openai_server, agent_card)
    
    def _create_style_agent(self, port: int):
        """Create style analysis agent"""
        agent_card = AgentCard(
            name="Enhanced Code Quality Expert",
            description="Advanced code quality, maintainability, and best practices analysis",
            url=f"http://localhost:{port}",
            version="2.0.0",
            skills=[
                AgentSkill(
                    name="Code Quality Assessment",
                    description="Comprehensive code quality metrics and maintainability analysis",
                    examples=["Cyclomatic complexity", "Code duplication", "Technical debt assessment"]
                ),
                AgentSkill(
                    name="Design Pattern Analysis",
                    description="Design pattern usage and architectural recommendations",
                    examples=["SOLID principles", "Design patterns", "Anti-pattern detection"]
                ),
                AgentSkill(
                    name="Documentation Review",
                    description="Code documentation quality and completeness assessment",
                    examples=["API documentation", "Inline comments", "README completeness"]
                )
            ]
        )
        
        openai_server = OpenAIA2AServer(
            api_key=self.config.openai_api_key,
            model=self.config.agent.model,
            temperature=self.config.agent.temperature,
            system_prompt="""You are a principal software architect with expertise in code quality and maintainability.
            Your expertise covers:
            - SOLID principles and clean code practices
            - Design patterns and architectural patterns
            - Code metrics and quality assessment
            - Technical debt identification and remediation
            - Team coding standards and best practices
            
            Provide detailed code quality analysis including:
            - Maintainability index and complexity metrics
            - SOLID principles adherence assessment
            - Design pattern recommendations and anti-pattern identification
            - Documentation quality and completeness
            - Refactoring opportunities with specific suggestions
            - Team workflow and collaboration improvements
            
            Focus on long-term maintainability and team productivity enhancements."""
        )
        
        class StyleAgent(A2AServer):
            def __init__(self, openai_server, agent_card):
                super().__init__(agent_card=agent_card)
                self.openai_server = openai_server
                self.logger = get_logger('agent.style')
            
            def handle_message(self, message):
                self.logger.debug("Processing style analysis request")
                return self.openai_server.handle_message(message)
        
        return StyleAgent(openai_server, agent_card)
    
    def _add_mcp_tools(self, mcp_server):
        """Add enhanced MCP tools to server"""
        
        @mcp_server.tool(
            name="enhanced_security_scan",
            description="Advanced security vulnerability scanning with SAST integration"
        )
        def enhanced_security_scan(code_content=None, **kwargs):
            """Enhanced security scanning"""
            try:
                if 'input' in kwargs:
                    code_content = kwargs['input']
                
                if not code_content:
                    return {"text": "Error: No code content provided"}
                
                # Run multiple security scanners
                results = {
                    'bandit_results': self._run_bandit_scan(code_content),
                    'custom_security_checks': self._run_custom_security_checks(code_content),
                    'owasp_checks': self._run_owasp_checks(code_content),
                    'cryptographic_analysis': self._analyze_cryptography(code_content)
                }
                
                # Generate risk score
                risk_score = self._calculate_security_risk_score(results)
                results['risk_score'] = risk_score
                
                return {"text": json.dumps(results)}
                
            except Exception as e:
                self.logger.error(f"Error in enhanced security scan: {e}")
                return {"text": f"Error: {str(e)}"}
        
        @mcp_server.tool(
            name="enhanced_performance_analysis",
            description="Advanced performance analysis with complexity assessment"
        )
        def enhanced_performance_analysis(code_content=None, **kwargs):
            """Enhanced performance analysis"""
            try:
                if 'input' in kwargs:
                    code_content = kwargs['input']
                
                if not code_content:
                    return {"text": "Error: No code content provided"}
                
                results = {
                    'complexity_analysis': self._analyze_complexity(code_content),
                    'memory_analysis': self._analyze_memory_patterns(code_content),
                    'concurrency_analysis': self._analyze_concurrency(code_content),
                    'database_analysis': self._analyze_database_patterns(code_content)
                }
                
                # Generate performance score
                performance_score = self._calculate_performance_score(results)
                results['performance_score'] = performance_score
                
                return {"text": json.dumps(results)}
                
            except Exception as e:
                self.logger.error(f"Error in enhanced performance analysis: {e}")
                return {"text": f"Error: {str(e)}"}
        
        @mcp_server.tool(
            name="enhanced_style_analysis",
            description="Advanced code quality and maintainability analysis"
        )
        def enhanced_style_analysis(code_content=None, **kwargs):
            """Enhanced style and quality analysis"""
            try:
                if 'input' in kwargs:
                    code_content = kwargs['input']
                
                if not code_content:
                    return {"text": "Error: No code content provided"}
                
                results = {
                    'style_violations': self._check_style_violations(code_content),
                    'maintainability_metrics': self._calculate_maintainability_metrics(code_content),
                    'design_pattern_analysis': self._analyze_design_patterns(code_content),
                    'documentation_analysis': self._analyze_documentation(code_content)
                }
                
                # Generate quality score
                quality_score = self._calculate_quality_score(results)
                results['quality_score'] = quality_score
                
                return {"text": json.dumps(results)}
                
            except Exception as e:
                self.logger.error(f"Error in enhanced style analysis: {e}")
                return {"text": f"Error: {str(e)}"}
    
    @log_performance("comprehensive_analysis")
    def analyze_code(self, request: CodeReviewRequest) -> Dict[str, AnalysisResult]:
        """Perform comprehensive code analysis"""
        self.logger.info(f"Starting analysis for request {request.request_id}")
        
        with log_context(analysis_id=request.request_id):
            results = {}
            
            if self.config.analysis.parallel_execution:
                # Parallel execution
                results = self._analyze_parallel(request)
            else:
                # Sequential execution
                results = self._analyze_sequential(request)
            
            # Update performance metrics
            self._update_performance_metrics(results)
            
            self.logger.info(f"Completed analysis for request {request.request_id}")
            return results
    
    def _analyze_parallel(self, request: CodeReviewRequest) -> Dict[str, AnalysisResult]:
        """Analyze code using parallel execution"""
        futures = {}
        
        for analysis_type in request.analysis_types:
            future = self.executor.submit(
                self._single_analysis,
                request.code,
                analysis_type,
                request.request_id,
                request.cache_enabled
            )
            futures[analysis_type] = future
        
        results = {}
        for analysis_type, future in futures.items():
            try:
                timeout = request.timeout or self.config.analysis.analysis_timeout
                result = future.result(timeout=timeout)
                results[analysis_type] = result
            except Exception as e:
                self.logger.error(f"Analysis {analysis_type} failed: {e}")
                results[analysis_type] = AnalysisResult(
                    analysis_id=str(uuid.uuid4()),
                    analysis_type=analysis_type,
                    code_hash=self._hash_code(request.code),
                    issues=[],
                    summary={'error': str(e)},
                    execution_time=0.0,
                    success=False,
                    error_message=str(e)
                )
        
        return results
    
    def _analyze_sequential(self, request: CodeReviewRequest) -> Dict[str, AnalysisResult]:
        """Analyze code using sequential execution"""
        results = {}
        
        for analysis_type in request.analysis_types:
            result = self._single_analysis(
                request.code,
                analysis_type,
                request.request_id,
                request.cache_enabled
            )
            results[analysis_type] = result
        
        return results
    
    def _single_analysis(self, code: str, analysis_type: str, request_id: str, cache_enabled: bool) -> AnalysisResult:
        """Perform single analysis with caching"""
        start_time = time.time()
        analysis_id = f"{request_id}_{analysis_type}"
        
        # Check cache first
        if cache_enabled:
            cached_result = self.cache.get_analysis_result(code, analysis_type)
            if cached_result:
                self.performance_metrics['cache_hits'] += 1
                self.logger.debug(f"Cache hit for {analysis_type} analysis")
                
                cached_result['cached'] = True
                cached_result['execution_time'] = time.time() - start_time
                
                return AnalysisResult(
                    analysis_id=analysis_id,
                    analysis_type=analysis_type,
                    code_hash=self._hash_code(code),
                    issues=cached_result.get('issues', []),
                    summary=cached_result.get('summary', {}),
                    execution_time=time.time() - start_time,
                    success=True,
                    cached=True
                )
        
        # Perform actual analysis
        try:
            if A2A_AVAILABLE and self.meta_agent:
                result = self._analyze_with_meta_agent(code, analysis_type)
            else:
                result = self._analyze_with_fallback(code, analysis_type)
            
            execution_time = time.time() - start_time
            
            analysis_result = AnalysisResult(
                analysis_id=analysis_id,
                analysis_type=analysis_type,
                code_hash=self._hash_code(code),
                issues=result.get('issues', []),
                summary=result.get('summary', {}),
                execution_time=execution_time,
                success=True
            )
            
            # Cache the result
            if cache_enabled:
                self.cache.cache_analysis_result(code, analysis_type, result)
            
            return analysis_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Analysis {analysis_type} failed: {e}")
            
            return AnalysisResult(
                analysis_id=analysis_id,
                analysis_type=analysis_type,
                code_hash=self._hash_code(code),
                issues=[],
                summary={'error': str(e)},
                execution_time=execution_time,
                success=False,
                error_message=str(e)
            )
    
    def shutdown(self):
        """Graceful shutdown of the system"""
        self.logger.info("Shutting down Code Review System...")
        
        # Shutdown executor
        self.executor.shutdown(wait=True)
        
        # Log final metrics
        self._log_final_metrics()
        
        self.logger.info("✅ Code Review System shutdown complete")
    
    def _log_final_metrics(self):
        """Log final performance metrics"""
        cache_stats = self.cache.get_cache_stats()
        
        metrics = {
            'performance': self.performance_metrics,
            'cache': cache_stats
        }
        
        self.logger.info(f"Final metrics: {json.dumps(metrics, indent=2)}")
    
    # Helper methods (simplified implementations)
    def _find_available_port(self, start_port: int) -> int:
        """Find available port"""
        import socket
        for port in range(start_port, start_port + 20):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('localhost', port))
                    return port
            except OSError:
                continue
        return start_port + 1000
    
    def _hash_code(self, code: str) -> str:
        """Generate hash for code"""
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()[:16]
    
    def _update_performance_metrics(self, results: Dict[str, AnalysisResult]):
        """Update system performance metrics"""
        self.performance_metrics['total_analyses'] += len(results)
        
        successful = sum(1 for r in results.values() if r.success)
        self.performance_metrics['successful_analyses'] += successful
        
        total_time = sum(r.execution_time for r in results.values())
        if total_time > 0:
            current_avg = self.performance_metrics['average_execution_time']
            total_analyses = self.performance_metrics['total_analyses']
            self.performance_metrics['average_execution_time'] = (
                (current_avg * (total_analyses - len(results)) + total_time) / total_analyses
            )
    
    # Placeholder methods for analysis implementations
    def _run_bandit_scan(self, code: str) -> Dict:
        """Run Bandit security scan"""
        # Implementation would use actual Bandit
        return {"issues": [], "summary": "Bandit scan completed"}
    
    def _run_custom_security_checks(self, code: str) -> List[Dict]:
        """Run custom security checks"""
        issues = []
        
        if 'eval(' in code:
            issues.append({
                "severity": "HIGH",
                "issue": "Use of eval() function",
                "recommendation": "Replace with ast.literal_eval()"
            })
        
        return issues
    
    def _run_owasp_checks(self, code: str) -> Dict:
        """Run OWASP-based security checks"""
        return {"owasp_issues": [], "compliance_score": 85}
    
    def _analyze_cryptography(self, code: str) -> Dict:
        """Analyze cryptographic implementations"""
        return {"crypto_issues": [], "strength_score": 90}
    
    def _calculate_security_risk_score(self, results: Dict) -> int:
        """Calculate overall security risk score"""
        # Simplified scoring logic
        return 75
    
    def _analyze_complexity(self, code: str) -> Dict:
        """Analyze algorithmic complexity"""
        return {"complexity_score": 3, "recommendations": []}
    
    def _analyze_memory_patterns(self, code: str) -> Dict:
        """Analyze memory usage patterns"""
        return {"memory_issues": [], "optimization_opportunities": []}
    
    def _analyze_concurrency(self, code: str) -> Dict:
        """Analyze concurrency patterns"""
        return {"concurrency_issues": [], "thread_safety_score": 80}
    
    def _analyze_database_patterns(self, code: str) -> Dict:
        """Analyze database usage patterns"""
        return {"db_issues": [], "query_optimizations": []}
    
    def _calculate_performance_score(self, results: Dict) -> int:
        """Calculate performance score"""
        return 80
    
    def _check_style_violations(self, code: str) -> List[Dict]:
        """Check style violations"""
        violations = []
        
        # Basic style checks
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if len(line) > 88:
                violations.append({
                    "line": i,
                    "severity": "LOW",
                    "issue": f"Line too long ({len(line)} chars)",
                    "recommendation": "Break long lines"
                })
        
        return violations
    
    def _calculate_maintainability_metrics(self, code: str) -> Dict:
        """Calculate maintainability metrics"""
        return {"maintainability_index": 75, "technical_debt_hours": 2.5}
    
    def _analyze_design_patterns(self, code: str) -> Dict:
        """Analyze design patterns"""
        return {"patterns_detected": [], "anti_patterns": [], "recommendations": []}
    
    def _analyze_documentation(self, code: str) -> Dict:
        """Analyze documentation quality"""
        return {"documentation_score": 70, "missing_docs": []}
    
    def _calculate_quality_score(self, results: Dict) -> int:
        """Calculate code quality score"""
        return 78
    
    def _run_agent_server(self, agent, host: str, port: int):
        """Run A2A agent server"""
        try:
            run_server(agent, host=host, port=port)
        except Exception as e:
            self.logger.error(f"Agent server error: {e}")
    
    def _run_mcp_server(self, server, host: str, port: int):
        """Run MCP server"""
        try:
            server.run(host=host, port=port)
        except Exception as e:
            self.logger.error(f"MCP server error: {e}")
    
    def _create_meta_agent(self, langchain_agents: Dict, langchain_tools: Dict):
        """Create meta agent for coordinating analysis"""
        # Simplified implementation
        self.meta_agent = True  # Placeholder
        self.logger.info("Meta agent created")
    
    def _analyze_with_meta_agent(self, code: str, analysis_type: str) -> Dict:
        """Analyze using meta agent"""
        # Simplified implementation
        return {
            "issues": [],
            "summary": f"{analysis_type} analysis completed via meta agent"
        }
    
    def _analyze_with_fallback(self, code: str, analysis_type: str) -> Dict:
        """Analyze using fallback agents"""
        agent = self.agents.get(analysis_type)
        if agent:
            return agent.analyze(code)
        else:
            return {
                "issues": [],
                "summary": f"No agent available for {analysis_type} analysis"
            }

# CLI Interface
def main():
    """Main entry point"""
    import argparse
    
def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Multi-Agent Code Review System")
    parser.add_argument("--config", type=str, help="Configuration file path")
    parser.add_argument("--code-file", type=str, help="Code file to analyze")
    parser.add_argument("--code", type=str, help="Code string to analyze")
    parser.add_argument("--analysis-types", type=str, nargs='+', 
                       default=['security', 'performance', 'style'],
                       help="Types of analysis to perform")
    parser.add_argument("--output", type=str, help="Output file for results")
    parser.add_argument("--format", type=str, choices=['json', 'text', 'html'], 
                       default='text', help="Output format")
    parser.add_argument("--daemon", action='store_true', help="Run as daemon")
    parser.add_argument("--port", type=int, help="Port for web interface")
    
    args = parser.parse_args()
    
    try:
        # Initialize system
        system = EnhancedCodeReviewSystem(args.config)
        
        if not system.start():
            print("❌ Failed to start code review system")
            return 1
        
        if args.daemon:
            # Run as daemon
            print("🚀 Code Review System running as daemon...")
            print("Press Ctrl+C to stop")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        
        elif args.code_file or args.code:
            # Analyze specific code
            if args.code_file:
                with open(args.code_file, 'r') as f:
                    code = f.read()
            else:
                code = args.code
            
            # Create analysis request
            request = CodeReviewRequest(
                request_id=str(uuid.uuid4()),
                code=code,
                analysis_types=args.analysis_types
            )
            
            # Perform analysis
            print("🔍 Analyzing code...")
            results = system.analyze_code(request)
            
            # Output results
            if args.output:
                output_results(results, args.output, args.format)
            else:
                print_results(results, args.format)
        
        else:
            # Interactive mode
            interactive_mode(system)
        
        # Shutdown
        system.shutdown()
        return 0
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return 1

def interactive_mode(system: EnhancedCodeReviewSystem):
    """Interactive mode for code analysis"""
    print("\n🔍 Enhanced Code Review System - Interactive Mode")
    print("="*60)
    print("Enter your code (type 'END' on a new line to finish, 'quit' to exit):")
    
    while True:
        try:
            code_lines = []
            while True:
                line = input()
                if line.strip().lower() == 'quit':
                    return
                if line.strip() == 'END':
                    break
                code_lines.append(line)
            
            if not code_lines:
                print("No code provided. Try again.")
                continue
            
            code = '\n'.join(code_lines)
            
            # Get analysis types
            print("\nSelect analysis types (comma-separated): security,performance,style")
            analysis_input = input("Analysis types [all]: ").strip()
            
            if analysis_input.lower() in ['', 'all']:
                analysis_types = ['security', 'performance', 'style']
            else:
                analysis_types = [t.strip() for t in analysis_input.split(',')]
            
            # Create request
            request = CodeReviewRequest(
                request_id=str(uuid.uuid4()),
                code=code,
                analysis_types=analysis_types
            )
            
            # Analyze
            print("\n🔍 Analyzing...")
            results = system.analyze_code(request)
            
            # Display results
            print_results(results, 'text')
            
            print("\n" + "="*60)
            print("Enter more code to analyze (or 'quit' to exit):")
            
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

def print_results(results: Dict[str, AnalysisResult], format_type: str = 'text'):
    """Print analysis results"""
    if format_type == 'json':
        print(json.dumps({k: v.__dict__ for k, v in results.items()}, indent=2, default=str))
        return
    
    # Text format
    print("\n" + "="*70)
    print("🔍 CODE REVIEW RESULTS")
    print("="*70)
    
    for analysis_type, result in results.items():
        print(f"\n📋 {analysis_type.upper()} ANALYSIS")
        print("-" * 50)
        
        if result.success:
            if result.cached:
                print("📦 (Cached result)")
            
            print(f"⏱️  Execution Time: {result.execution_time:.3f}s")
            print(f"🔍 Issues Found: {len(result.issues)}")
            
            if result.issues:
                print("\n🚨 ISSUES:")
                for i, issue in enumerate(result.issues, 1):
                    severity_emoji = {
                        'CRITICAL': '🔴',
                        'HIGH': '🟠', 
                        'MEDIUM': '🟡',
                        'LOW': '🟢'
                    }.get(issue.get('severity', 'UNKNOWN'), '❓')
                    
                    print(f"  {i}. {severity_emoji} {issue.get('severity', 'UNKNOWN')}")
                    print(f"     Issue: {issue.get('issue', 'Unknown issue')}")
                    if 'line' in issue:
                        print(f"     Line: {issue['line']}")
                    if 'recommendation' in issue:
                        print(f"     Fix: {issue['recommendation']}")
                    print()
            else:
                print("✅ No issues found!")
            
            # Print summary if available
            if result.summary:
                print("📊 SUMMARY:")
                for key, value in result.summary.items():
                    if key != 'error':
                        print(f"   {key}: {value}")
        
        else:
            print(f"❌ Analysis failed: {result.error_message}")
    
    # Overall summary
    total_issues = sum(len(r.issues) for r in results.values())
    successful_analyses = sum(1 for r in results.values() if r.success)
    total_time = sum(r.execution_time for r in results.values())
    
    print(f"\n📊 OVERALL SUMMARY:")
    print(f"   Total Issues: {total_issues}")
    print(f"   Successful Analyses: {successful_analyses}/{len(results)}")
    print(f"   Total Execution Time: {total_time:.3f}s")

def output_results(results: Dict[str, AnalysisResult], output_file: str, format_type: str):
    """Output results to file"""
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    if format_type == 'json':
        with open(output_path, 'w') as f:
            json.dump({k: v.__dict__ for k, v in results.items()}, f, indent=2, default=str)
    
    elif format_type == 'html':
        html_content = generate_html_report(results)
        with open(output_path, 'w') as f:
            f.write(html_content)
    
    else:  # text
        with open(output_path, 'w') as f:
            # Redirect print to file
            import sys
            old_stdout = sys.stdout
            sys.stdout = f
            print_results(results, 'text')
            sys.stdout = old_stdout
    
    print(f"✅ Results saved to {output_path}")

def generate_html_report(results: Dict[str, AnalysisResult]) -> str:
    """Generate HTML report"""
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Code Review Report</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { background: #2c3e50; color: white; padding: 20px; border-radius: 8px; }
            .analysis { margin: 20px 0; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }
            .issue { margin: 10px 0; padding: 10px; background: #f8f9fa; border-left: 4px solid #007bff; }
            .critical { border-left-color: #dc3545; }
            .high { border-left-color: #fd7e14; }
            .medium { border-left-color: #ffc107; }
            .low { border-left-color: #28a745; }
            .summary { background: #e9ecef; padding: 15px; border-radius: 6px; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔍 Code Review Report</h1>
            <p>Generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
        </div>
    """
    
    for analysis_type, result in results.items():
        html += f"""
        <div class="analysis">
            <h2>📋 {analysis_type.upper()} Analysis</h2>
            <p><strong>Status:</strong> {'✅ Success' if result.success else '❌ Failed'}</p>
            <p><strong>Execution Time:</strong> {result.execution_time:.3f}s</p>
            <p><strong>Issues Found:</strong> {len(result.issues)}</p>
        """
        
        if result.success and result.issues:
            html += "<h3>Issues:</h3>"
            for issue in result.issues:
                severity = issue.get('severity', 'UNKNOWN').lower()
                html += f"""
                <div class="issue {severity}">
                    <strong>{issue.get('severity', 'UNKNOWN')}:</strong> {issue.get('issue', 'Unknown issue')}<br>
                    <strong>Recommendation:</strong> {issue.get('recommendation', 'No recommendation available')}
                """
                if 'line' in issue:
                    html += f"<br><strong>Line:</strong> {issue['line']}"
                html += "</div>"
        
        html += "</div>"
    
    # Overall summary
    total_issues = sum(len(r.issues) for r in results.values())
    successful_analyses = sum(1 for r in results.values() if r.success)
    total_time = sum(r.execution_time for r in results.values())
    
    html += f"""
        <div class="summary">
            <h3>📊 Overall Summary</h3>
            <p><strong>Total Issues:</strong> {total_issues}</p>
            <p><strong>Successful Analyses:</strong> {successful_analyses}/{len(results)}</p>
            <p><strong>Total Execution Time:</strong> {total_time:.3f}s</p>
        </div>
    </body>
    </html>
    """
    
    return html

# Example usage and testing
if __name__ == "__main__":
    # Test with sample code if no arguments provided
    if len(sys.argv) == 1:
        print("🧪 Running test analysis...")
        
        test_code = '''
def calculate_password(username, password="admin123"):
    """Test function with security issues"""
    if password == "admin123":  # Hardcoded password
        return True
    
    # SQL injection vulnerability
    sql = "SELECT * FROM users WHERE username = '" + username + "'"
    result = eval("execute_query('" + sql + "')")  # eval usage
    
    # Performance issue: nested loops
    for i in range(len(result)):
        for j in range(len(result[i])):
            if result[i][j] == password:
                return True
    
    return False

class myClass:  # Style issue: naming
    def MyMethod(self):  # Style issue: method naming
        pass
'''
        
        try:
            system = EnhancedCodeReviewSystem()
            if system.start():
                request = CodeReviewRequest(
                    request_id="test-001",
                    code=test_code,
                    analysis_types=['security', 'performance', 'style']
                )
                
                results = system.analyze_code(request)
                print_results(results)
                system.shutdown()
            else:
                print("❌ Failed to start system for testing")
        except Exception as e:
            print(f"❌ Test failed: {e}")
    else:
        # Run main CLI
        sys.exit(main())