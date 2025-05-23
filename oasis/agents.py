"""
OASIS A2A Agent System
Refactored from analyze.py to use specialized security agents
"""
import asyncio
from typing import List, Dict, Tuple, Any, Union, Optional
from pathlib import Path
from tqdm import tqdm
import threading
import time
import json
import argparse

# A2A imports (with fallback for missing dependencies)
try:
    from python_a2a import A2AServer, AgentCard, AgentSkill, run_server
    from python_a2a.langchain import to_langchain_agent, to_langchain_tool
    A2A_AVAILABLE = True
except ImportError:
    A2A_AVAILABLE = False
    # Fallback classes for legacy mode
    class A2AServer:
        def __init__(self, agent_card=None): pass
    class AgentCard:
        def __init__(self, **kwargs): pass
    class AgentSkill:
        def __init__(self, **kwargs): pass

# Import configuration and utilities
from .config import (
    VULNERABILITY_MAPPING, AGENT_CONFIG, AGENT_COLLABORATION_RULES, 
    MODEL_EMOJIS, VULNERABILITY_PROMPT_EXTENSION, CHUNK_ANALYZE_TIMEOUT,
    EMBEDDING_THRESHOLDS, MAX_CHUNK_SIZE, DEFAULT_ARGS
)
from .utils import logger, calculate_similarity, sanitize_name, chunk_content
from .ollama_manager import OllamaManager
from .embedding import EmbeddingManager
from .cache import CacheManager
from .mcp_tools import MCPToolManager

# Keep original analyze.py enums for compatibility
class AnalysisMode:
    SCAN = "scan"
    DEEP = "deep"
    AGENT = "agent"

class AnalysisType:
    STANDARD = "standard"
    ADAPTIVE = "adaptive"
    COLLABORATIVE = "collaborative"

class SecurityAgentBase(A2AServer):
    """
    Base class for all specialized security agents
    Inherits from A2AServer for A2A protocol support
    """
    
    def __init__(self, agent_type: str, ollama_manager: OllamaManager):
        """Initialize base security agent"""
        self.agent_type = agent_type
        self.ollama_manager = ollama_manager
        self.config = AGENT_CONFIG.get(agent_type, {})
        self.model = self.config.get('model', 'llama2:7b')
        self.port = self.config.get('port', 5000)
        
        # Create agent card for A2A protocol
        if A2A_AVAILABLE:
            agent_card = AgentCard(
                name=self.config.get('name', f'{agent_type.upper()} Expert'),
                description=self.config.get('description', f'Expert in {agent_type} vulnerabilities'),
                url=f"http://localhost:{self.port}",
                version="2.0.0",
                skills=[
                    AgentSkill(
                        name=skill,
                        description=f"Specialized in {skill.lower()}",
                        examples=[f"Analyze code for {skill.lower()}", f"Detect {skill.lower()} patterns"]
                    ) for skill in self.config.get('skills', [])
                ]
            )
            super().__init__(agent_card=agent_card)
        
        # Initialize client connection
        self.client = None
        self.server_thread = None
        self.running = False
        
    def start_server(self):
        """Start the A2A server for this agent"""
        if not A2A_AVAILABLE:
            logger.debug(f"A2A not available, skipping server start for {self.agent_type}")
            return True
            
        try:
            def run_agent_server():
                run_server(self, host="localhost", port=self.port)
            
            self.server_thread = threading.Thread(target=run_agent_server, daemon=True)
            self.server_thread.start()
            time.sleep(2)  # Give server time to start
            self.running = True
            
            logger.debug(f"✅ Started A2A server for {self.agent_type} on port {self.port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start A2A server for {self.agent_type}: {str(e)}")
            return False
    
    def stop_server(self):
        """Stop the A2A server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
    
    def ensure_model_available(self):
        """Ensure the agent's model is available"""
        return self.ollama_manager.ensure_model_available(self.model)
    
    def get_client(self):
        """Get Ollama client for this agent's model"""
        if not self.client:
            self.client = self.ollama_manager.get_client()
        return self.client
    
    def analyze_chunk(self, chunk: str, vulnerability: Dict, file_path: str = None) -> str:
        """
        Analyze a code chunk for the agent's specialized vulnerability type
        Reuses existing OASIS prompt engineering
        """
        try:
            # Build specialized prompt for this agent
            prompt = self._build_agent_prompt(chunk, vulnerability, file_path)
            
            # Use Ollama to analyze with this agent's specialized model
            client = self.get_client()
            response = client.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={"timeout": CHUNK_ANALYZE_TIMEOUT * 1000}
            )
            
            return response['message']['content']
            
        except Exception as e:
            logger.exception(f"Error in {self.agent_type} agent analysis: {str(e)}")
            return f"Error during {self.agent_type} analysis: {str(e)}"
    
    def _build_agent_prompt(self, chunk: str, vulnerability: Dict, file_path: str = None) -> str:
        """Build specialized prompt for this agent type"""
        vuln_name = vulnerability.get('name', '')
        vuln_desc = vulnerability.get('description', '')
        vuln_patterns = vulnerability.get('patterns', [])
        vuln_impact = vulnerability.get('impact', '')
        vuln_mitigation = vulnerability.get('mitigation', '')
        
        agent_specialization = f"""
You are a {self.config.get('name', f'{self.agent_type} Expert')} with deep expertise in {vuln_name} vulnerabilities.

AGENT SPECIALIZATION:
{self.config.get('description', '')}

SPECIALIZED SKILLS:
{', '.join(self.config.get('skills', []))}
"""
        
        # Reuse existing prompt building logic from original analyze.py
        return f"""{agent_specialization}

VULNERABILITY DETAILS:
- Name: {vuln_name}
- Description: {vuln_desc}
- Common patterns: {', '.join(vuln_patterns[:5]) if vuln_patterns else 'N/A'}
- Security impact: {vuln_impact}
- Mitigation: {vuln_mitigation}

CODE SEGMENT TO ANALYZE:
```
{chunk}
```

YOUR TASK:
As a specialized {vuln_name} expert, analyze this code segment for {vuln_name} vulnerabilities ONLY.

{self._get_agent_analysis_format()}

{VULNERABILITY_PROMPT_EXTENSION}
"""
    
    def _get_agent_analysis_format(self) -> str:
        """Get agent-specific analysis format instructions"""
        return """
ANALYSIS FORMAT:
1. **Vulnerability Assessment**: Is this code vulnerable to the specific vulnerability type you specialize in?
2. **Technical Analysis**: Detailed technical explanation of the vulnerability
3. **Risk Level**: Critical/High/Medium/Low based on your expertise
4. **Attack Vector**: How an attacker would exploit this specific vulnerability
5. **Remediation**: Specific, actionable remediation steps
6. **Agent Confidence**: Your confidence level (1-10) in this assessment

FORMAT YOUR RESPONSE AS:
## Vulnerability Assessment
[Your assessment]

## Technical Analysis  
[Detailed analysis]

## Risk Level
[Risk level with justification]

## Attack Vector
[Step-by-step attack scenario]

## Remediation
[Specific remediation steps]

## Agent Confidence
[Confidence score and reasoning]
"""

    def handle_message(self, message):
        """Handle A2A protocol messages"""
        try:
            # Extract analysis request from A2A message
            if isinstance(message, dict):
                chunk = message.get('code', '')
                vulnerability = message.get('vulnerability', {})
                file_path = message.get('file_path', '')
            else:
                # Fallback for simple string messages
                chunk = str(message)
                vulnerability = {'name': self.agent_type, 'description': ''}
                file_path = ''
            
            # Perform analysis
            result = self.analyze_chunk(chunk, vulnerability, file_path)
            
            return {
                'agent': self.agent_type,
                'analysis': result,
                'confidence': self._extract_confidence(result),
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.exception(f"Error handling A2A message in {self.agent_type}: {str(e)}")
            return {
                'agent': self.agent_type,
                'error': str(e),
                'timestamp': time.time()
            }
    
    def _extract_confidence(self, analysis_result: str) -> float:
        """Extract confidence score from analysis result"""
        try:
            # Look for confidence patterns in the analysis
            import re
            confidence_match = re.search(r'confidence.*?(\d+(?:\.\d+)?)', analysis_result.lower())
            if confidence_match:
                return float(confidence_match.group(1)) / 10.0  # Normalize to 0-1
            return 0.5  # Default medium confidence
        except:
            return 0.5

# Specialized Agent Implementations
class SQLInjectionAgent(SecurityAgentBase):
    """Specialized agent for SQL injection vulnerabilities"""
    def __init__(self, ollama_manager: OllamaManager):
        super().__init__('sqli', ollama_manager)

class XSSAgent(SecurityAgentBase):
    """Specialized agent for XSS vulnerabilities"""
    def __init__(self, ollama_manager: OllamaManager):
        super().__init__('xss', ollama_manager)

class AuthenticationAgent(SecurityAgentBase):
    """Specialized agent for authentication vulnerabilities"""
    def __init__(self, ollama_manager: OllamaManager):
        super().__init__('auth', ollama_manager)

class CryptographyAgent(SecurityAgentBase):
    """Specialized agent for cryptography vulnerabilities"""
    def __init__(self, ollama_manager: OllamaManager):
        super().__init__('crypto', ollama_manager)

class ConfigurationAgent(SecurityAgentBase):
    """Specialized agent for configuration vulnerabilities"""
    def __init__(self, ollama_manager: OllamaManager):
        super().__init__('config', ollama_manager)

class AgentOrchestrator:
    """
    Orchestrates multiple specialized security agents
    Replaces the original SecurityAnalyzer for multi-agent mode
    """
    
    def __init__(self, args, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager, 
                 mcp_tools: MCPToolManager = None):
        """Initialize the agent orchestrator"""
        self.args = args
        self.embedding_manager = embedding_manager
        self.ollama_manager = ollama_manager
        self.mcp_tools = mcp_tools
        
        # Initialize specialized agents
        self.agents = {}
        self._init_agents()
        
        # Collaboration settings
        self.collaboration_enabled = getattr(args, 'agent_collaboration', True)
        self.collaboration_rules = AGENT_COLLABORATION_RULES
        
        # Cache management
        self.cache_managers = {}
        self._init_caches()
        
        # Analysis state
        self.analysis_results = {}
        self.agent_findings = {}
        
    def _init_agents(self):
        """Initialize specialized security agents"""
        logger.info("🤝 Initializing specialized security agents...")
        
        # Determine which agents to create
        if hasattr(self.args, 'agents') and self.args.agents:
            agent_types = [a.strip() for a in self.args.agents.split(',')]
        else:
            agent_types = list(AGENT_CONFIG.keys())
        
        # Create agent instances
        agent_classes = {
            'sqli': SQLInjectionAgent,
            'xss': XSSAgent,
            'auth': AuthenticationAgent,
            'crypto': CryptographyAgent,
            'config': ConfigurationAgent
        }
        
        for agent_type in agent_types:
            if agent_type in agent_classes:
                try:
                    agent = agent_classes[agent_type](self.ollama_manager)
                    
                    # Ensure agent's model is available
                    if agent.ensure_model_available():
                        self.agents[agent_type] = agent
                        
                        # Start A2A server if available
                        if A2A_AVAILABLE:
                            agent.start_server()
                            
                        logger.info(f"✅ {agent.config.get('name', agent_type)} initialized")
                    else:
                        logger.warning(f"⚠️  {agent_type} agent model not available")
                        
                except Exception as e:
                    logger.error(f"Failed to initialize {agent_type} agent: {str(e)}")
        
        if not self.agents:
            logger.error("No agents were successfully initialized!")
            raise RuntimeError("Agent initialization failed")
            
        logger.info(f"🤝 Initialized {len(self.agents)} specialized agents")
    
    def _init_caches(self):
        """Initialize cache managers for each agent"""
        for agent_type in self.agents.keys():
            cache_manager = CacheManager(
                input_path=self.embedding_manager.input_path,
                llm_model=self.agents[agent_type].model,
                scan_model=self.agents[agent_type].model,  # Agents use same model for both
                cache_days=self.args.cache_days
            )
            self.cache_managers[agent_type] = cache_manager

    def process_multi_agent_analysis(self, vulnerabilities, args, report):
        """
        Process security analysis using multiple specialized agents
        """
        logger.info("🤝 Starting multi-agent collaborative analysis")
        
        all_results = {}
        
        # Phase 1: Route vulnerabilities to appropriate agents
        agent_tasks = self._route_vulnerabilities_to_agents(vulnerabilities)
        
        # Phase 2: Execute agent-specific analysis
        with tqdm(total=len(agent_tasks), desc="Agent analysis progress", 
                 position=0, leave=True, disable=args.silent) as agent_pbar:
            
            for agent_type, vuln_list in agent_tasks.items():
                agent_pbar.set_postfix_str(f"Agent: {agent_type}")
                
                # Process vulnerabilities with this agent
                agent_results = self._process_agent_vulnerabilities(
                    agent_type, vuln_list, args.silent
                )
                
                # Store results
                for vuln_name, results in agent_results.items():
                    all_results[vuln_name] = results
                    
                    # Generate individual vulnerability report
                    if results:
                        report.generate_vulnerability_report(
                            vulnerability=next(v for v in vuln_list if v['name'] == vuln_name),
                            results=results,
                            model_name=f"Agent: {self.agents[agent_type].config.get('name', agent_type)}"
                        )
                
                agent_pbar.update(1)
        
        # Phase 3: Agent collaboration and correlation
        if self.collaboration_enabled and len(self.agents) > 1:
            logger.info("🤝 Running agent collaboration and correlation")
            correlated_results = self._correlate_agent_findings(all_results)
            
            # Generate collaboration report
            if correlated_results:
                report.generate_agent_collaboration_report(correlated_results)
        
        # Phase 4: MCP tool enhancement
        if self.mcp_tools:
            logger.info("🔧 Enhancing findings with MCP tools")
            enhanced_results = self._enhance_with_mcp_tools(all_results)
            all_results.update(enhanced_results)
        
        return all_results
    
    def _route_vulnerabilities_to_agents(self, vulnerabilities) -> Dict[str, List[Dict]]:
        """Route vulnerabilities to appropriate specialized agents"""
        agent_tasks = {agent_type: [] for agent_type in self.agents.keys()}
        
        for vulnerability in vulnerabilities:
            # Get the primary agent for this vulnerability type
            primary_agent = vulnerability.get('agent')
            
            if primary_agent and primary_agent in self.agents:
                agent_tasks[primary_agent].append(vulnerability)
            else:
                # Fallback: try to map based on vulnerability name
                vuln_name = vulnerability.get('name', '').lower()
                if 'sql' in vuln_name or 'injection' in vuln_name:
                    agent_tasks.get('sqli', []).append(vulnerability)
                elif 'xss' in vuln_name or 'script' in vuln_name:
                    agent_tasks.get('xss', []).append(vulnerability)
                elif 'auth' in vuln_name or 'session' in vuln_name:
                    agent_tasks.get('auth', []).append(vulnerability)
                elif 'crypto' in vuln_name or 'encrypt' in vuln_name:
                    agent_tasks.get('crypto', []).append(vulnerability)
                else:
                    agent_tasks.get('config', []).append(vulnerability)
        
        # Remove empty agent tasks
        return {k: v for k, v in agent_tasks.items() if v}
    
    def _process_agent_vulnerabilities(self, agent_type: str, vulnerabilities: List[Dict], 
                                     silent: bool = False) -> Dict[str, List[Dict]]:
        """Process vulnerabilities with a specific agent"""
        agent = self.agents[agent_type]
        agent_results = {}
        
        for vulnerability in vulnerabilities:
            vuln_name = vulnerability['name']
            
            # Find potentially vulnerable files using existing embedding system
            embedding_results = self._find_vulnerable_files(vulnerability)
            
            if not embedding_results:
                logger.debug(f"No files found for {vuln_name} with {agent_type} agent")
                continue
            
            # Analyze files with the specialized agent
            detailed_results = []
            
            with tqdm(total=len(embedding_results), 
                     desc=f"{agent_type} analyzing {vuln_name}", 
                     position=1, leave=False, disable=silent) as file_pbar:
                
                for file_path, similarity_score in embedding_results:
                    file_result = self._analyze_file_with_agent(
                        agent, file_path, similarity_score, vulnerability
                    )
                    
                    if file_result:
                        detailed_results.append(file_result)
                    
                    file_pbar.update(1)
            
            if detailed_results:
                agent_results[vuln_name] = detailed_results
                logger.info(f"🎯 {agent_type} found {len(detailed_results)} potential {vuln_name} issues")
        
        return agent_results
    
    def _find_vulnerable_files(self, vulnerability: Dict) -> List[Tuple[str, float]]:
        """
        Find potentially vulnerable files using existing embedding system
        Reuses OASIS's core embedding-based detection
        """
        try:
            # Use existing embedding search from SecurityAnalyzer
            results = self._search_vulnerabilities_embedding(vulnerability, self.args.threshold)
            return [(path, score) for path, score in results if score >= self.args.threshold]
        except Exception as e:
            logger.exception(f"Error finding vulnerable files: {str(e)}")
            return []
    
    def _search_vulnerabilities_embedding(self, vulnerability: Union[str, Dict], threshold: float = 0.5) -> List[Tuple[str, float]]:
        """
        Search for potential vulnerabilities using embeddings (from original SecurityAnalyzer)
        """
        try:
            vuln_name = vulnerability['name']
            
            # Get embedding for vulnerability type using complete information
            vuln_vector = self.embedding_manager.get_vulnerability_embedding(vulnerability)
            if not vuln_vector:
                logger.error(f"Failed to get embedding for vulnerability type '{vuln_name}'")
                return []
                
            results = []
            code_base = self.embedding_manager.code_base
            
            # Process all files (reuse existing logic)
            for file_path, data in code_base.items():
                if self.embedding_manager.analyze_by_function:
                    # Process functions for this file
                    self._process_functions_embedding(file_path, data, vuln_vector, threshold, results)
                else:
                    # Process file as a whole
                    self._process_file_embedding(file_path, data, vuln_vector, threshold, results)
                    
            # Sort by similarity score in descending order
            return sorted(results, key=lambda x: x[1], reverse=True)
                
        except Exception as e:
            logger.exception(f"Error during vulnerability search: {str(e)}")
            return []
    
    def _process_functions_embedding(self, file_path: str, data: Dict, vuln_vector: List[float], 
                                   threshold: float, results: List[Tuple[str, float]]) -> None:
        """Process functions in a file for embedding similarity"""
        if 'functions' not in data:
            return
            
        for func_id, func_data in data['functions'].items():
            if not func_data.get('embedding'):
                continue
                
            try:
                similarity = calculate_similarity(vuln_vector, func_data['embedding'])
                if similarity >= threshold:
                    results.append((func_id, similarity))
            except Exception as e:
                logger.exception(f"Error processing function {func_id}: {str(e)}")
                
    def _process_file_embedding(self, file_path: str, data: Dict, vuln_vector: List[float], 
                              threshold: float, results: List[Tuple[str, float]]) -> None:
        """Process entire file for embedding similarity"""
        try:
            # Extract embedding based on its structure
            file_vectors = self._extract_file_vectors(data)
            if not file_vectors:
                return
                
            # For multiple chunks, find the highest similarity
            if isinstance(file_vectors, list) and isinstance(file_vectors[0], list):
                highest_similarity = max(calculate_similarity(vuln_vector, vec) for vec in file_vectors)
                if highest_similarity >= threshold:
                    results.append((file_path, highest_similarity))
            else:
                # Single vector
                similarity = calculate_similarity(vuln_vector, file_vectors)
                if similarity >= threshold:
                    results.append((file_path, similarity))
        except Exception as e:
            logger.exception(f"Error processing file {file_path}: {str(e)}")
            
    def _extract_file_vectors(self, data: Dict) -> Union[List[float], List[List[float]], None]:
        """Extract embedding vectors from file data"""
        embedding = data.get('embedding')
        if not embedding:
            return None
            
        if isinstance(embedding, dict):
            return embedding.get('embedding')
        elif isinstance(embedding, list) and all(isinstance(item, list) for item in embedding):
            return embedding  # Chunked embeddings
        else:
            return embedding  # Single embedding vector

    def _analyze_file_with_agent(self, agent: SecurityAgentBase, file_path: str, 
                               similarity_score: float, vulnerability: Dict) -> Optional[Dict]:
        """Analyze a file with a specialized agent"""
        try:
            # Get file content and chunk it
            code_base = self.embedding_manager.code_base
            if file_path not in code_base:
                return None
                
            code = code_base[file_path]['content']
            chunks = chunk_content(code, MAX_CHUNK_SIZE)
            
            # Analyze chunks with the agent
            analyses = []
            for i, chunk in enumerate(chunks):
                try:
                    analysis_result = agent.analyze_chunk(chunk, vulnerability, file_path)
                    if analysis_result and not analysis_result.startswith("Error"):
                        analyses.append(f"### Chunk {i+1}\n{analysis_result}")
                except Exception as e:
                    logger.debug(f"Error analyzing chunk {i} with {agent.agent_type}: {str(e)}")
                    continue
            
            if not analyses:
                return None
            
            # Combine all analyses for this file
            combined_analysis = "\n\n---\n\n".join(analyses)
            
            return {
                'file_path': file_path,
                'similarity_score': similarity_score,
                'analysis': combined_analysis,
                'agent': agent.agent_type,
                'agent_name': agent.config.get('name', agent.agent_type),
                'vulnerability': {
                    'name': vulnerability.get('name', ''),
                    'description': vulnerability.get('description', ''),
                    'impact': vulnerability.get('impact', ''),
                    'mitigation': vulnerability.get('mitigation', '')
                }
            }
            
        except Exception as e:
            logger.exception(f"Error analyzing {file_path} with {agent.agent_type}: {str(e)}")
            return None
    
    def _correlate_agent_findings(self, all_results: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """Correlate findings between different agents"""
        correlations = []
        
        # Find files that multiple agents flagged
        file_agent_map = {}
        
        for vuln_type, results in all_results.items():
            for result in results:
                file_path = result['file_path']
                if file_path not in file_agent_map:
                    file_agent_map[file_path] = []
                file_agent_map[file_path].append({
                    'agent': result.get('agent', ''),
                    'vuln_type': vuln_type,
                    'score': result.get('similarity_score', 0),
                    'analysis': result.get('analysis', '')
                })
        
        # Identify multi-agent findings
        for file_path, findings in file_agent_map.items():
            if len(findings) > 1:
                # Multiple agents found issues in the same file
                agents_involved = [f['agent'] for f in findings]
                correlation = {
                    'file_path': file_path,
                    'agents': agents_involved,
                    'vulnerability_types': [f['vuln_type'] for f in findings],
                    'combined_risk': self._calculate_combined_risk(findings),
                    'attack_chains': self._generate_attack_chains(findings),
                    'findings': findings
                }
                correlations.append(correlation)
        
        return {
            'correlations': correlations,
            'multi_agent_files': len([c for c in correlations if len(c['agents']) > 1]),
            'total_correlated_files': len(correlations)
        }
    
    def _calculate_combined_risk(self, findings: List[Dict]) -> str:
        """Calculate combined risk from multiple agent findings"""
        scores = [f['score'] for f in findings]
        avg_score = sum(scores) / len(scores)
        
        # Risk amplification for multiple vulnerabilities
        amplification = 1.0 + (len(findings) - 1) * 0.2  # 20% increase per additional vulnerability
        combined_score = min(avg_score * amplification, 1.0)
        
        if combined_score >= 0.8:
            return "Critical"
        elif combined_score >= 0.6:
            return "High"
        elif combined_score >= 0.4:
            return "Medium"
        else:
            return "Low"
    
    def _generate_attack_chains(self, findings: List[Dict]) -> List[str]:
        """Generate potential attack chains from correlated findings"""
        attack_chains = []
        
        # Define attack chain patterns
        chain_patterns = {
            ('auth', 'sqli'): "Authentication bypass → SQL injection → Database compromise",
            ('xss', 'auth'): "XSS attack → Session hijacking → Account takeover",
            ('config', 'crypto'): "Configuration exposure → Cryptographic weakness → Data breach",
            ('sqli', 'config'): "SQL injection → Configuration disclosure → Privilege escalation",
            ('auth', 'config'): "Authentication bypass → Configuration access → System compromise"
        }
        
        # Check for known patterns
        agent_types = set(f['agent'] for f in findings)
        for pattern, chain in chain_patterns.items():
            if all(agent in agent_types for agent in pattern):
                attack_chains.append(chain)
        
        # Generate generic chain if no specific pattern matches
        if not attack_chains and len(findings) > 1:
            vuln_types = [f['vuln_type'] for f in findings]
            attack_chains.append(f"Multi-vector attack: {' → '.join(vuln_types)} → System compromise")
        
        return attack_chains
    
    def _enhance_with_mcp_tools(self, all_results: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """Enhance findings with MCP tool data"""
        enhanced_results = {}
        
        if not self.mcp_tools:
            return {}
        
        logger.info("🔧 Enhancing findings with external tool validation")
        
        for vuln_type, results in all_results.items():
            enhanced_findings = []
            
            for result in results:
                try:
                    # Enhance with CVE database lookup
                    cve_data = self.mcp_tools.lookup_cve(result)
                    
                    # Enhance with Semgrep validation
                    semgrep_data = self.mcp_tools.validate_with_semgrep(result)
                    
                    # Enhance with dependency scanning
                    dep_data = self.mcp_tools.scan_dependencies(result['file_path'])
                    
                    # Add enhancement data to result
                    enhanced_result = result.copy()
                    enhanced_result['mcp_enhancements'] = {
                        'cve_references': cve_data,
                        'semgrep_validation': semgrep_data,
                        'dependency_issues': dep_data,
                        'external_confidence': self._calculate_external_confidence(cve_data, semgrep_data)
                    }
                    
                    enhanced_findings.append(enhanced_result)
                    
                except Exception as e:
                    logger.debug(f"Error enhancing result with MCP tools: {str(e)}")
                    enhanced_findings.append(result)  # Keep original result
            
            if enhanced_findings:
                enhanced_results[f"{vuln_type}_enhanced"] = enhanced_findings
        
        return enhanced_results
    
    def _calculate_external_confidence(self, cve_data: Dict, semgrep_data: Dict) -> float:
        """Calculate confidence based on external tool validation"""
        confidence = 0.5  # Base confidence
        
        if cve_data and cve_data.get('matches'):
            confidence += 0.3  # CVE match increases confidence
        
        if semgrep_data and semgrep_data.get('findings'):
            confidence += 0.2  # Semgrep validation increases confidence
        
        return min(confidence, 1.0)
    
    def get_cache_info(self) -> str:
        """Get information about agent caches"""
        cache_info = []
        for agent_type, cache_manager in self.cache_managers.items():
            try:
                cache_files = list(cache_manager.cache_dir.glob("**/*.cache"))
                cache_info.append(f"{agent_type}: {len(cache_files)} files")
            except:
                cache_info.append(f"{agent_type}: unavailable")
        return ", ".join(cache_info)
    
    def save_all_caches(self):
        """Save all agent caches"""
        for agent_type, cache_manager in self.cache_managers.items():
            try:
                # Save caches for both analysis types
                cache_manager.save_chunk_cache("", AnalysisMode.SCAN, AnalysisType.COLLABORATIVE)
                cache_manager.save_chunk_cache("", AnalysisMode.DEEP, AnalysisType.COLLABORATIVE)
            except Exception as e:
                logger.debug(f"Error saving cache for {agent_type}: {str(e)}")
    
    def cleanup(self):
        """Cleanup agents and resources"""
        logger.info("🧹 Cleaning up agents...")
        for agent in self.agents.values():
            try:
                agent.stop_server()
            except Exception as e:
                logger.debug(f"Error stopping agent: {str(e)}")
    
    @staticmethod
    def get_vulnerabilities_to_check(args, vuln_mapping):
        """
        Determine which vulnerabilities to check based on args
        (Static method for compatibility with original code)
        """
        if args.vulns.lower() == 'all':
            return list(vuln_mapping.values()), None

        selected_tags = [tag.strip() for tag in args.vulns.split(',')]
        if invalid_tags := [
            tag for tag in selected_tags if tag not in vuln_mapping
        ]:
            logger.error(f"Invalid vulnerability tags: {', '.join(invalid_tags)}")
            logger.error("Use --help to see available tags")
            return None, invalid_tags

        return [vuln_mapping[tag] for tag in selected_tags], None

# Legacy Compatibility Classes
class LegacySecurityAnalyzer:
    """
    Backward compatibility wrapper for original SecurityAnalyzer
    Used when multi-agent mode is disabled
    """
    
    def __init__(self, args, llm_model: str, embedding_manager: EmbeddingManager, 
                 ollama_manager: OllamaManager, scan_model: str = None):
        """Initialize legacy analyzer with original interface"""
        # Import the original analyze module classes for backward compatibility
        try:
            from . import analyze
            # Create original SecurityAnalyzer instance
            self.analyzer = analyze.SecurityAnalyzer(
                args, llm_model, embedding_manager, ollama_manager, scan_model
            )
            logger.debug("✅ Legacy SecurityAnalyzer initialized")
        except ImportError:
            logger.error("Could not import original SecurityAnalyzer for legacy mode")
            raise
    
    def process_analysis_with_model(self, vulnerabilities, args, report):
        """Delegate to original SecurityAnalyzer"""
        return self.analyzer.process_analysis_with_model(vulnerabilities, args, report)

class EmbeddingAnalyzer:
    """
    Enhanced embedding analyzer with agent awareness
    Used for audit mode
    """
    
    def __init__(self, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager):
        """Initialize embedding analyzer"""
        self.embedding_manager = embedding_manager
        self.ollama_manager = ollama_manager
        self.code_base = embedding_manager.code_base
        self.embedding_model = embedding_manager.embedding_model
        self.results_cache = {}
        self.embedding_analysis_type = embedding_manager.embedding_analysis_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.analyze_type = embedding_manager.analyze_type
    
    def analyze_vulnerability(self, vuln: Dict) -> List[Dict[str, Any]]:
        """Analyze a single vulnerability type for audit"""
        cache_key = f"{sanitize_name(vuln['name'])}_{self.analyze_type}"
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]

        logger.info(f"🚨 Analyzing vulnerability: {vuln['name']}")

        # Use embedding search to find potential matches
        results = []
        try:
            vuln_vector = self.embedding_manager.get_vulnerability_embedding(vuln)
            if vuln_vector:
                for file_path, data in self.code_base.items():
                    if self.analyze_by_function:
                        self._process_functions_for_audit(file_path, data, vuln_vector, results)
                    else:
                        self._process_file_for_audit(file_path, data, vuln_vector, results)
        except Exception as e:
            logger.exception(f"Error analyzing {vuln['name']}: {str(e)}")

        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        self.results_cache[cache_key] = results
        return results
    
    def _process_functions_for_audit(self, file_path: str, data: Dict, vuln_vector: List[float], results: List[Dict]):
        """Process functions for audit analysis"""
        if 'functions' not in data:
            return
            
        for func_id, func_data in data['functions'].items():
            if not func_data.get('embedding'):
                continue
                
            try:
                similarity = calculate_similarity(vuln_vector, func_data['embedding'])
                results.append({
                    'item_id': func_id,
                    'similarity_score': similarity,
                    'is_function': True
                })
            except Exception as e:
                logger.debug(f"Error processing function {func_id}: {str(e)}")
    
    def _process_file_for_audit(self, file_path: str, data: Dict, vuln_vector: List[float], results: List[Dict]):
        """Process file for audit analysis"""
        try:
            embedding = data.get('embedding')
            if not embedding:
                return
                
            # Handle different embedding formats
            if isinstance(embedding, dict):
                file_embedding = embedding.get('embedding')
            elif isinstance(embedding, list) and isinstance(embedding[0], list):
                # Multiple chunks - use highest similarity
                similarities = [calculate_similarity(vuln_vector, vec) for vec in embedding]
                similarity = max(similarities) if similarities else 0
                results.append({
                    'item_id': file_path,
                    'similarity_score': similarity,
                    'is_function': False
                })
                return
            else:
                file_embedding = embedding
            
            if file_embedding:
                similarity = calculate_similarity(vuln_vector, file_embedding)
                results.append({
                    'item_id': file_path,
                    'similarity_score': similarity,
                    'is_function': False
                })
                
        except Exception as e:
            logger.debug(f"Error processing file {file_path}: {str(e)}")
    
    def analyze_all_vulnerabilities(self, vulnerabilities: List[Dict], 
                                   thresholds: List[float] = None,
                                   console_output: bool = True) -> Dict[str, Dict]:
        """Analyze all vulnerability types for audit"""
        all_results = {}

        if console_output:
            logger.info("\nEnhanced Embeddings Distribution Analysis")
            logger.info("========================================\n")

        # Analyze each vulnerability
        for vuln in vulnerabilities:
            vuln_name = vuln['name']

            # Get results for this vulnerability
            results = self.analyze_vulnerability(vuln)

            # Generate threshold analysis
            threshold_analysis = self.generate_threshold_analysis(results, thresholds)

            # Calculate statistics
            statistics = self.calculate_statistics(results)

            # Store in all_results
            all_results[vuln_name] = {
                'results': results,
                'threshold_analysis': threshold_analysis,
                'statistics': statistics
            }

            # Console output if requested
            if console_output:
                self._print_vulnerability_analysis(vuln_name, results, threshold_analysis, statistics)

        return all_results
    
    def generate_threshold_analysis(self, results: List[Dict], thresholds: List[float] = None) -> List[Dict]:
        """Generate threshold analysis for results"""
        if not thresholds:
            thresholds = EMBEDDING_THRESHOLDS
            
        threshold_analysis = []
        total_items = len(results)
        
        if total_items == 0:
            return []
            
        for threshold in thresholds:
            matching_items = sum(r['similarity_score'] >= threshold for r in results)
            percentage = (matching_items / total_items) * 100
            
            threshold_analysis.append({
                'threshold': threshold,
                'matching_items': matching_items,
                'percentage': percentage
            })
            
        return threshold_analysis
    
    def calculate_statistics(self, results: List[Dict]) -> Dict[str, float]:
        """Calculate statistics for results"""
        if not results:
            return {
                'avg_score': 0,
                'median_score': 0,
                'max_score': 0,
                'min_score': 0,
                'count': 0
            }
            
        scores = [r['similarity_score'] for r in results]
        
        return {
            'avg_score': sum(scores) / len(scores),
            'median_score': sorted(scores)[len(scores)//2],
            'max_score': max(scores),
            'min_score': min(scores),
            'count': len(scores)
        }
    
    def _print_vulnerability_analysis(self, vuln_name: str, results: List[Dict], 
                                     threshold_analysis: List[Dict], statistics: Dict):
        """Print vulnerability analysis to console"""
        logger.info(f"\nAnalyzing: {vuln_name}")
        logger.info("-" * (14 + len(vuln_name)))
        
        # Print threshold analysis
        logger.info("\nThreshold Analysis:")
        logger.info("----------------------")
        for analysis in threshold_analysis:
            threshold = analysis['threshold']
            matching_items = analysis['matching_items']
            percentage = analysis['percentage']
            logger.info(f"Threshold {threshold:.1f}: {matching_items:3d} items ({percentage:5.1f}%)")
        
        # Print top 5 most similar items
        logger.info("\nTop 5 Most Similar Items:")
        logger.info("----------------------------")
        for result in results[:5]:
            score = result['similarity_score']
            item_id = result['item_id']
            logger.info(f"{score:.3f} - {item_id}", extra={'emoji': False})
        
        # Print statistics
        logger.info("\nStatistics:")
        logger.info("--------------")
        logger.info(f"Average similarity: {statistics['avg_score']:.3f}")
        logger.info(f"Median similarity: {statistics['median_score']:.3f}")
        logger.info(f"Max similarity: {statistics['max_score']:.3f}")
        logger.info(f"Min similarity: {statistics['min_score']:.3f}")
        logger.info("")