"""
OASIS MCP Tools Integration
Integrates external security tools via Model Context Protocol
"""
import json
import os
import subprocess
import threading
import time
import requests
from pathlib import Path
from typing import Dict, List, Any, Optional
import tempfile

# MCP imports (with fallback for missing dependencies)
try:
    from fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    # Fallback class for when MCP is not available
    class FastMCP:
        def __init__(self, name, description=""):
            self.name = name
        def tool(self, name, description=""):
            def decorator(func):
                return func
            return decorator
        def run(self, host="localhost", port=7000):
            pass

from .config import MCP_CONFIG
from .utils import logger, sanitize_name

class MCPToolManager:
    """
    Manages MCP (Model Context Protocol) tools for external security integrations
    """
    
    def __init__(self, config_file: str = "config.json", enabled: bool = True):
        """Initialize MCP tool manager"""
        self.enabled = enabled and MCP_AVAILABLE
        self.config_file = Path(config_file)
        self.tools = {}
        self.servers = {}
        self.active_tools = []
        
        if not self.enabled:
            logger.warning("MCP tools disabled - FastMCP not available")
            return
        
        # Load MCP configuration
        self.mcp_config = self._load_mcp_config()
        
        # Initialize MCP servers
        self._init_mcp_servers()
    
    def _load_mcp_config(self) -> Dict:
        """Load MCP configuration from config.json"""
        try:
            if self.config_file.exists():
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    return config.get('mcpServers', {})
            else:
                logger.warning(f"MCP config file not found: {self.config_file}")
                return {}
        except Exception as e:
            logger.error(f"Error loading MCP config: {str(e)}")
            return {}
    
    def _init_mcp_servers(self):
        """Initialize MCP servers for each tool"""
        if not self.enabled:
            return
            
        logger.info("🔧 Initializing MCP tool servers...")
        
        # Initialize NVD (CVE Database) tool
        if 'nvd' in self.mcp_config:
            self._init_nvd_server()
        
        # Initialize Semgrep tool  
        if 'semgrep' in self.mcp_config:
            self._init_semgrep_server()
        
        # Initialize Git analyzer tool
        if 'git-analyzer' in self.mcp_config:
            self._init_git_analyzer_server()
        
        # Initialize dependency scanner
        if 'dependency-scanner' in self.mcp_config:
            self._init_dependency_scanner_server()
    
    def _init_nvd_server(self):
        """Initialize NVD (National Vulnerability Database) MCP server"""
        try:
            nvd_server = FastMCP(
                name="NVD Vulnerability Database",
                description="Query NIST National Vulnerability Database for CVE information"
            )
            
            @nvd_server.tool(
                name="lookup_cve",
                description="Lookup CVE information for vulnerability findings"
            )
            def lookup_cve(vulnerability_info: str) -> Dict[str, Any]:
                """
                Query NVD database for CVE information related to findings
                """
                try:
                    # Extract relevant information from vulnerability finding
                    keywords = self._extract_cve_keywords(vulnerability_info)
                    
                    # Query NVD API
                    api_key = os.getenv('NVD_API_KEY')
                    headers = {}
                    if api_key:
                        headers['apiKey'] = api_key
                    
                    results = []
                    for keyword in keywords[:3]:  # Limit to top 3 keywords
                        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                        params = {
                            'keywordSearch': keyword,
                            'resultsPerPage': 5
                        }
                        
                        response = requests.get(url, params=params, headers=headers, timeout=10)
                        
                        if response.status_code == 200:
                            data = response.json()
                            cves = data.get('vulnerabilities', [])
                            
                            for cve_item in cves:
                                cve = cve_item.get('cve', {})
                                cve_id = cve.get('id', '')
                                description = ''
                                
                                # Extract description
                                descriptions = cve.get('descriptions', [])
                                for desc in descriptions:
                                    if desc.get('lang') == 'en':
                                        description = desc.get('value', '')
                                        break
                                
                                # Extract CVSS score
                                cvss_score = 'Unknown'
                                metrics = cve.get('metrics', {})
                                if 'cvssMetricV31' in metrics:
                                    cvss_data = metrics['cvssMetricV31'][0]['cvssData']
                                    cvss_score = cvss_data.get('baseScore', 'Unknown')
                                
                                results.append({
                                    'cve_id': cve_id,
                                    'description': description[:200] + '...' if len(description) > 200 else description,
                                    'cvss_score': cvss_score,
                                    'keyword_match': keyword
                                })
                    
                    return {
                        'matches': results[:10],  # Top 10 matches
                        'total_found': len(results),
                        'keywords_searched': keywords
                    }
                    
                except Exception as e:
                    logger.debug(f"Error querying NVD: {str(e)}")
                    return {
                        'error': str(e),
                        'matches': []
                    }
            
            self.tools['nvd'] = nvd_server
            self.active_tools.append('nvd')
            logger.debug("✅ NVD MCP server initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize NVD server: {str(e)}")
    
    def _init_semgrep_server(self):
        """Initialize Semgrep static analysis MCP server"""
        try:
            semgrep_server = FastMCP(
                name="Semgrep Static Analysis",
                description="Static analysis validation using Semgrep rules"
            )
            
            @semgrep_server.tool(
                name="validate_with_semgrep",
                description="Validate findings using Semgrep static analysis"
            )
            def validate_with_semgrep(file_path: str, vulnerability_type: str = "") -> Dict[str, Any]:
                """
                Run Semgrep analysis on a file to validate findings
                """
                try:
                    if not Path(file_path).exists():
                        return {'error': f'File not found: {file_path}', 'findings': []}
                    
                    # Build Semgrep command
                    cmd = ['semgrep', '--json', '--quiet']
                    
                    # Add vulnerability-specific rules if available
                    if vulnerability_type:
                        rule_map = {
                            'sqli': 'sql-injection',
                            'xss': 'xss',
                            'auth': 'authentication',
                            'crypto': 'cryptography',
                            'config': 'security-misconfiguration'
                        }
                        rule = rule_map.get(vulnerability_type.lower())
                        if rule:
                            cmd.extend(['--config', f'p/{rule}'])
                    else:
                        # Use general security rules
                        cmd.extend(['--config', 'p/security-audit'])
                    
                    cmd.append(file_path)
                    
                    # Run Semgrep
                    result = subprocess.run(
                        cmd, 
                        capture_output=True, 
                        text=True, 
                        timeout=60
                    )
                    
                    if result.returncode == 0:
                        try:
                            semgrep_output = json.loads(result.stdout)
                            findings = semgrep_output.get('results', [])
                            
                            processed_findings = []
                            for finding in findings:
                                processed_findings.append({
                                    'rule_id': finding.get('check_id', ''),
                                    'message': finding.get('extra', {}).get('message', ''),
                                    'severity': finding.get('extra', {}).get('severity', 'INFO'),
                                    'line': finding.get('start', {}).get('line', 0),
                                    'confidence': finding.get('extra', {}).get('metadata', {}).get('confidence', 'MEDIUM')
                                })
                            
                            return {
                                'findings': processed_findings,
                                'total_issues': len(processed_findings),
                                'tool': 'semgrep'
                            }
                            
                        except json.JSONDecodeError:
                            return {'error': 'Invalid JSON from Semgrep', 'findings': []}
                    else:
                        return {
                            'error': f'Semgrep failed: {result.stderr}',
                            'findings': []
                        }
                        
                except subprocess.TimeoutExpired:
                    return {'error': 'Semgrep analysis timed out', 'findings': []}
                except Exception as e:
                    return {'error': f'Semgrep error: {str(e)}', 'findings': []}
            
            self.tools['semgrep'] = semgrep_server
            self.active_tools.append('semgrep')
            logger.debug("✅ Semgrep MCP server initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Semgrep server: {str(e)}")
    
    def _init_git_analyzer_server(self):
        """Initialize Git history analyzer MCP server"""
        try:
            git_server = FastMCP(
                name="Git History Analyzer", 
                description="Analyze git history for security-related changes"
            )
            
            @git_server.tool(
                name="analyze_git_history",
                description="Analyze git history for when vulnerabilities were introduced"
            )
            def analyze_git_history(file_path: str, lines_of_interest: List[int] = None) -> Dict[str, Any]:
                """
                Analyze git history to understand when vulnerable code was introduced
                """
                try:
                    if not Path(file_path).exists():
                        return {'error': f'File not found: {file_path}'}
                    
                    # Get git blame information
                    blame_cmd = ['git', 'blame', '--porcelain', file_path]
                    blame_result = subprocess.run(
                        blame_cmd, 
                        capture_output=True, 
                        text=True, 
                        timeout=30,
                        cwd=Path(file_path).parent
                    )
                    
                    if blame_result.returncode != 0:
                        return {'error': 'Git blame failed - not a git repository or file not tracked'}
                    
                    # Parse git blame output
                    blame_info = self._parse_git_blame(blame_result.stdout)
                    
                    # Get recent commits affecting this file
                    log_cmd = ['git', 'log', '--oneline', '-10', file_path]
                    log_result = subprocess.run(
                        log_cmd,
                        capture_output=True,
                        text=True, 
                        timeout=30,
                        cwd=Path(file_path).parent
                    )
                    
                    recent_commits = []
                    if log_result.returncode == 0:
                        for line in log_result.stdout.strip().split('\n'):
                            if line:
                                parts = line.split(' ', 1)
                                if len(parts) == 2:
                                    recent_commits.append({
                                        'hash': parts[0],
                                        'message': parts[1]
                                    })
                    
                    return {
                        'blame_info': blame_info,
                        'recent_commits': recent_commits,
                        'analysis_date': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'file_path': file_path
                    }
                    
                except subprocess.TimeoutExpired:
                    return {'error': 'Git analysis timed out'}
                except Exception as e:
                    return {'error': f'Git analysis error: {str(e)}'}
            
            self.tools['git_analyzer'] = git_server
            self.active_tools.append('git_analyzer')
            logger.debug("✅ Git analyzer MCP server initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize Git analyzer server: {str(e)}")
    
    def _init_dependency_scanner_server(self):
        """Initialize dependency scanner MCP server"""
        try:
            dep_server = FastMCP(
                name="Dependency Scanner",
                description="Scan project dependencies for known vulnerabilities"
            )
            
            @dep_server.tool(
                name="scan_dependencies", 
                description="Scan project dependencies for vulnerabilities"
            )
            def scan_dependencies(project_path: str) -> Dict[str, Any]:
                """
                Scan project dependencies for known vulnerabilities
                """
                try:
                    project_dir = Path(project_path).parent if Path(project_path).is_file() else Path(project_path)
                    
                    vulnerabilities = []
                    
                    # Scan Python requirements
                    requirements_files = list(project_dir.glob('*requirements*.txt'))
                    if requirements_files:
                        for req_file in requirements_files:
                            python_vulns = self._scan_python_dependencies(req_file)
                            vulnerabilities.extend(python_vulns)
                    
                    # Scan Node.js package.json
                    package_json = project_dir / 'package.json'
                    if package_json.exists():
                        node_vulns = self._scan_node_dependencies(package_json)
                        vulnerabilities.extend(node_vulns)
                    
                    # Scan Java pom.xml
                    pom_xml = project_dir / 'pom.xml'
                    if pom_xml.exists():
                        java_vulns = self._scan_java_dependencies(pom_xml)
                        vulnerabilities.extend(java_vulns)
                    
                    return {
                        'vulnerabilities': vulnerabilities,
                        'total_issues': len(vulnerabilities),
                        'scanned_files': [str(f) for f in [*requirements_files, package_json, pom_xml] if f.exists()],
                        'scan_date': time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                except Exception as e:
                    return {'error': f'Dependency scan error: {str(e)}', 'vulnerabilities': []}
            
            self.tools['dependency_scanner'] = dep_server
            self.active_tools.append('dependency_scanner')
            logger.debug("✅ Dependency scanner MCP server initialized")
            
        except Exception as e:
            logger.error(f"Failed to initialize dependency scanner server: {str(e)}")
    
    def start_servers(self) -> bool:
        """Start all MCP tool servers"""
        if not self.enabled:
            logger.info("MCP tools are disabled")
            return False
        
        success_count = 0
        
        for tool_name, server in self.tools.items():
            try:
                config = MCP_CONFIG['tools'].get(tool_name, {})
                port = MCP_CONFIG['base_port'] + config.get('port_offset', 0)
                
                # Start server in background thread
                def run_server(srv, p):
                    try:
                        srv.run(host="localhost", port=p)
                    except Exception as e:
                        logger.debug(f"MCP server {tool_name} error: {str(e)}")
                
                thread = threading.Thread(
                    target=run_server,
                    args=(server, port),
                    daemon=True
                )
                thread.start()
                
                # Give server time to start
                time.sleep(1)
                
                # Test if server is responding
                if self._test_server_connection(port):
                    self.servers[tool_name] = {
                        'server': server,
                        'port': port,
                        'thread': thread,
                        'status': 'running'
                    }
                    success_count += 1
                    logger.debug(f"✅ {tool_name} MCP server started on port {port}")
                else:
                    logger.warning(f"⚠️  {tool_name} MCP server failed to start")
                    
            except Exception as e:
                logger.error(f"Error starting {tool_name} MCP server: {str(e)}")
        
        if success_count > 0:
            logger.info(f"🔧 Started {success_count}/{len(self.tools)} MCP tool servers")
            return True
        else:
            logger.warning("No MCP tool servers started successfully")
            return False
    
    def _test_server_connection(self, port: int) -> bool:
        """Test if MCP server is responding on the given port"""
        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('localhost', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def lookup_cve(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Lookup CVE information for a finding"""
        if not self.enabled or 'nvd' not in self.servers:
            return {'matches': [], 'error': 'NVD tool not available'}
        
        try:
            # Extract vulnerability information from finding
            vuln_info = f"{finding.get('vulnerability', {}).get('name', '')} {finding.get('analysis', '')}"
            
            # Call NVD tool
            nvd_server = self.tools['nvd']
            result = nvd_server.lookup_cve(vuln_info)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error calling NVD tool: {str(e)}")
            return {'matches': [], 'error': str(e)}
    
    def validate_with_semgrep(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Validate finding with Semgrep"""
        if not self.enabled or 'semgrep' not in self.servers:
            return {'findings': [], 'error': 'Semgrep tool not available'}
        
        try:
            file_path = finding.get('file_path', '')
            vuln_type = finding.get('agent', '')
            
            # Call Semgrep tool
            semgrep_server = self.tools['semgrep']
            result = semgrep_server.validate_with_semgrep(file_path, vuln_type)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error calling Semgrep tool: {str(e)}")
            return {'findings': [], 'error': str(e)}
    
    def scan_dependencies(self, file_path: str) -> Dict[str, Any]:
        """Scan dependencies for vulnerabilities"""
        if not self.enabled or 'dependency_scanner' not in self.servers:
            return {'vulnerabilities': [], 'error': 'Dependency scanner not available'}
        
        try:
            # Call dependency scanner tool
            dep_server = self.tools['dependency_scanner']
            result = dep_server.scan_dependencies(file_path)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error calling dependency scanner: {str(e)}")
            return {'vulnerabilities': [], 'error': str(e)}
    
    def analyze_git_history(self, file_path: str) -> Dict[str, Any]:
        """Analyze git history for a file"""
        if not self.enabled or 'git_analyzer' not in self.servers:
            return {'error': 'Git analyzer not available'}
        
        try:
            # Call git analyzer tool
            git_server = self.tools['git_analyzer']
            result = git_server.analyze_git_history(file_path)
            
            return result
            
        except Exception as e:
            logger.debug(f"Error calling git analyzer: {str(e)}")
            return {'error': str(e)}
    
    def get_active_tools(self) -> List[str]:
        """Get list of active MCP tools"""
        return self.active_tools
    
    def cleanup(self):
        """Cleanup MCP servers and resources"""
        logger.info("🧹 Cleaning up MCP tools...")
        
        for tool_name, server_info in self.servers.items():
            try:
                server_info['status'] = 'stopped'
                # Threads are daemon threads, so they'll stop when main process exits
            except Exception as e:
                logger.debug(f"Error stopping {tool_name} server: {str(e)}")
    
    # Utility methods
    def _extract_cve_keywords(self, vulnerability_info: str) -> List[str]:
        """Extract keywords for CVE search from vulnerability information"""
        keywords = []
        
        # Common vulnerability keywords
        vuln_keywords = {
            'sql injection': ['sql injection', 'sqli', 'database'],
            'xss': ['cross-site scripting', 'xss', 'javascript injection'],
            'authentication': ['authentication bypass', 'auth', 'login'],
            'cryptography': ['weak encryption', 'crypto', 'ssl', 'tls'],
            'configuration': ['misconfiguration', 'default credentials', 'exposure']
        }
        
        info_lower = vulnerability_info.lower()
        
        for vuln_type, terms in vuln_keywords.items():
            for term in terms:
                if term in info_lower:
                    keywords.append(term)
                    break
        
        # Add generic keywords if none found
        if not keywords:
            keywords = ['vulnerability', 'security']
        
        return keywords[:5]  # Limit to 5 keywords
    
    def _parse_git_blame(self, blame_output: str) -> Dict[str, Any]:
        """Parse git blame output"""
        lines = blame_output.strip().split('\n')
        blame_info = {
            'authors': {},
            'commits': {},
            'line_count': 0
        }
        
        current_commit = None
        
        for line in lines:
            if line.startswith('author '):
                author = line[7:]
                if author not in blame_info['authors']:
                    blame_info['authors'][author] = 0
                blame_info['authors'][author] += 1
            elif line.startswith('summary '):
                summary = line[8:]
                if current_commit:
                    blame_info['commits'][current_commit] = summary
            elif len(line) == 40 and all(c in '0123456789abcdef' for c in line):
                current_commit = line
            elif line.startswith('\t'):
                blame_info['line_count'] += 1
        
        return blame_info
    
    def _scan_python_dependencies(self, requirements_file: Path) -> List[Dict[str, Any]]:
        """Scan Python requirements for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Use safety tool if available
            result = subprocess.run(
                ['safety', 'check', '-r', str(requirements_file), '--json'],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                try:
                    safety_output = json.loads(result.stdout)
                    for vuln in safety_output:
                        vulnerabilities.append({
                            'package': vuln.get('package', ''),
                            'version': vuln.get('installed_version', ''),
                            'vulnerability_id': vuln.get('vulnerability_id', ''),
                            'description': vuln.get('advisory', ''),
                            'severity': 'HIGH',  # Safety doesn't provide severity
                            'source': 'safety'
                        })
                except json.JSONDecodeError:
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # safety tool not available or timed out
            pass
        
        return vulnerabilities
    
    def _scan_node_dependencies(self, package_json: Path) -> List[Dict[str, Any]]:
        """Scan Node.js dependencies for vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Use npm audit if available
            result = subprocess.run(
                ['npm', 'audit', '--json'],
                capture_output=True,
                text=True,
                timeout=60,
                cwd=package_json.parent
            )
            
            if result.stdout:
                try:
                    audit_output = json.loads(result.stdout)
                    advisories = audit_output.get('advisories', {})
                    
                    for advisory_id, advisory in advisories.items():
                        vulnerabilities.append({
                            'package': advisory.get('module_name', ''),
                            'version': advisory.get('findings', [{}])[0].get('version', ''),
                            'vulnerability_id': advisory_id,
                            'description': advisory.get('title', ''),
                            'severity': advisory.get('severity', 'UNKNOWN').upper(),
                            'source': 'npm_audit'
                        })
                        
                except json.JSONDecodeError:
                    pass
                    
        except (subprocess.TimeoutExpired, FileNotFoundError):
            # npm not available or timed out
            pass
        
        return vulnerabilities
    
    def _scan_java_dependencies(self, pom_xml: Path) -> List[Dict[str, Any]]:
        """Scan Java dependencies for vulnerabilities (basic implementation)"""
        vulnerabilities = []
        
        # This is a simplified implementation
        # In a real scenario, you'd integrate with tools like OWASP Dependency Check
        
        try:
            # Read pom.xml and extract dependencies
            with open(pom_xml, 'r') as f:
                content = f.read()
            
            # Simple regex to find dependencies (very basic)
            import re
            dependency_pattern = r'<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>'
            dependencies = re.findall(dependency_pattern, content, re.DOTALL)
            
            # For demo purposes, flag some commonly vulnerable patterns
            vulnerable_patterns = [
                ('log4j', '2.1'),  # Log4Shell
                ('struts', '2.3'),  # Struts vulnerabilities
                ('spring', '4.3')   # Spring vulnerabilities
            ]
            
            for group_id, artifact_id, version in dependencies:
                for pattern, vuln_version in vulnerable_patterns:
                    if pattern in artifact_id.lower() and version.startswith(vuln_version):
                        vulnerabilities.append({
                            'package': f"{group_id}:{artifact_id}",
                            'version': version,
                            'vulnerability_id': f"DEMO-{pattern.upper()}",
                            'description': f"Potentially vulnerable {pattern} version",
                            'severity': 'HIGH',
                            'source': 'pom_analysis'
                        })
                        
        except Exception as e:
            logger.debug(f"Error scanning Java dependencies: {str(e)}")
        
        return vulnerabilities