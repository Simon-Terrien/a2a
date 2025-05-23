"""
OASIS Core - Main orchestrator with A2A and MCP integration
Merges: oasis.py + enums.py + __init__.py
"""
import argparse
import logging
import sys
import os
from pathlib import Path
import time
import traceback
from typing import Union, List, Dict, Any
from enum import Enum

# Load environment variables first
from dotenv import load_dotenv
load_dotenv()

# Import configuration
from .config import (
    MODEL_EMOJIS, REPORT, DEFAULT_ARGS, AGENT_CONFIG, MCP_CONFIG,
    AGENT_COLLABORATION_RULES, AGENT_PRIORITY, A2A_DEPENDENCIES
)

# Import core modules
from .utils import generate_timestamp, setup_logging, logger, display_logo, get_vulnerability_mapping
from .ollama_manager import OllamaManager
from .embedding import EmbeddingManager
from .agents import AgentOrchestrator  # New multi-agent system
from .mcp_tools import MCPToolManager  # New MCP integration
from .report import Report
from .web import WebServer
from .cache import CacheManager

# Version info
__version__ = "2.0.0"  # Updated for A2A + MCP integration

# Analysis modes and types (from enums.py)

class OasisOrchestrator:
    """
    Enhanced OASIS orchestrator with A2A agents and MCP tools
    """
    
    def __init__(self):
        """Initialize the OASIS orchestrator"""
        self.args = None
        self.ollama_manager = None
        self.embedding_manager = None
        self.agent_orchestrator = None  # New: A2A agents
        self.mcp_tools = None  # New: MCP tools
        self.output_dir = None
        self.legacy_mode = False  # For backward compatibility

    def setup_argument_parser(self):
        """Configure and return argument parser with A2A/MCP options"""
        class CustomFormatter(argparse.RawDescriptionHelpFormatter):
            def _split_lines(self, text, width):
                if text.startswith('Vulnerability types'):
                    return text.splitlines()
                return super()._split_lines(text, width)

        parser = argparse.ArgumentParser(
            description='🏝️  OASIS v2.0 - Enhanced with A2A Agents and MCP Tools',
            formatter_class=CustomFormatter
        )
        
        # Input/Output Options
        io_group = parser.add_argument_group('Input/Output Options')
        io_group.add_argument('-i', '--input', dest='input_path', type=str, 
                            help='Path to file, directory, or .txt file containing paths to analyze')
        io_group.add_argument('-of', '--output-format', type=str, default=DEFAULT_ARGS['OUTPUT_FORMAT'],
                            help=f'Output format [pdf, html, md] (default: {DEFAULT_ARGS["OUTPUT_FORMAT"]})')
        io_group.add_argument('-x', '--extensions', type=str,
                            help='Comma-separated list of file extensions to analyze (e.g., "py,js,java")')
        
        # Analysis Configuration (Enhanced)
        analysis_group = parser.add_argument_group('Analysis Configuration')
        analysis_group.add_argument('-at', '--analyze-type', choices=['standard', 'adaptive', 'collaborative'], 
                                   default=DEFAULT_ARGS['ANALYSIS_TYPE'],
                                   help=f'Analysis type (default: {DEFAULT_ARGS["ANALYSIS_TYPE"]}) - collaborative uses multi-agent')
        analysis_group.add_argument('-eat', '--embeddings-analyze-type', choices=['file', 'function'], 
                                   default=DEFAULT_ARGS['EMBEDDING_ANALYSIS_TYPE'],
                                   help=f'Analyze code by entire file or by individual functions (default: {DEFAULT_ARGS["EMBEDDING_ANALYSIS_TYPE"]})')
        analysis_group.add_argument('-ad', '--adaptive', action='store_true', 
                                   help='Use adaptive multi-level analysis that adjusts depth based on risk assessment')
        analysis_group.add_argument('-t', '--threshold', type=float, default=DEFAULT_ARGS['THRESHOLD'], 
                                   help=f'Similarity threshold (default: {DEFAULT_ARGS["THRESHOLD"]})')
        analysis_group.add_argument('-v', '--vulns', type=str, default=DEFAULT_ARGS['VULNS'], 
                                   help=self.get_vulnerability_help())
        analysis_group.add_argument('-ch', '--chunk-size', type=int,
                                   help=f'Maximum size of text chunks for embedding (default: {DEFAULT_ARGS["CHUNK_SIZE"]})')
        
        # A2A Agent Options (New)
        agent_group = parser.add_argument_group('A2A Agent Options')
        agent_group.add_argument('--multi-agent', action='store_true', default=DEFAULT_ARGS['MULTI_AGENT'],
                               help='Enable multi-agent collaborative analysis')
        agent_group.add_argument('--agent-collaboration', action='store_true', default=DEFAULT_ARGS['AGENT_COLLABORATION'],
                               help='Enable agent-to-agent collaboration')
        agent_group.add_argument('--agents', type=str,
                               help='Comma-separated list of agents to use (sqli,xss,auth,crypto,config)')
        agent_group.add_argument('--legacy-mode', action='store_true',
                               help='Use original single-model analysis (backward compatibility)')
        
        # MCP Tools Options (New)
        mcp_group = parser.add_argument_group('MCP Tools Options')
        mcp_group.add_argument('--mcp-tools', action='store_true', default=DEFAULT_ARGS['MCP_TOOLS_ENABLED'],
                             help='Enable MCP external tool integration')
        mcp_group.add_argument('--mcp-config', type=str, default='config.json',
                             help='Path to MCP configuration file')
        mcp_group.add_argument('--external-validation', action='store_true',
                             help='Validate findings with external tools (CVE DB, Semgrep)')
        
        # Model Selection (Enhanced)
        model_group = parser.add_argument_group('Model Selection')
        model_group.add_argument('-m', '--models', type=str,
                               help='Comma-separated list of models to use (bypasses interactive selection)')
        model_group.add_argument('-sm', '--scan-model', dest='scan_model', type=str,
                               help='Model to use for quick scanning (default: same as main model)')
        model_group.add_argument('-em', '--embed-model', type=str, default=DEFAULT_ARGS['EMBED_MODEL'],
                               help=f'Model to use for embeddings (default: {DEFAULT_ARGS["EMBED_MODEL"]})')
        model_group.add_argument('-lm', '--list-models', action='store_true',
                               help='List available models and exit')
        
        # Cache Management (Enhanced)
        cache_group = parser.add_argument_group('Cache Management')
        cache_group.add_argument('-cce', '--clear-cache-embeddings', action='store_true',
                               help='Clear embeddings cache before starting')
        cache_group.add_argument('-ccs', '--clear-cache-scan', action='store_true',
                               help='Clear scan analysis cache for the current analysis type')
        cache_group.add_argument('-cca', '--clear-cache-agents', action='store_true',
                               help='Clear agent-specific caches')
        cache_group.add_argument('-ccm', '--clear-cache-mcp', action='store_true',
                               help='Clear MCP tool caches')
        cache_group.add_argument('-cd', '--cache-days', type=int, default=DEFAULT_ARGS['CACHE_DAYS'], 
                               help=f'Maximum age of cache in days (default: {DEFAULT_ARGS["CACHE_DAYS"]})')
        
        # Web Interface
        web_group = parser.add_argument_group('Web Interface')
        web_group.add_argument('-w', '--web', action='store_true',
                             help='Serve reports via a web interface')
        web_group.add_argument('-we', '--web-expose', dest='web_expose', type=str, default='local',
                             help='Web interface exposure (local: 127.0.0.1, all: 0.0.0.0) (default: local)')
        web_group.add_argument('-wpw', '--web-password', dest='web_password', type=str,
                             help='Web interface password (if not specified, a random password will be generated)')
        web_group.add_argument('-wp', '--web-port', dest='web_port', type=int, default=5000,
                             help='Web interface port (default: 5000)')
        
        # Logging and Debug
        logging_group = parser.add_argument_group('Logging and Debug')
        logging_group.add_argument('-d', '--debug', action='store_true',
                                 help='Enable debug output')
        logging_group.add_argument('-s', '--silent', action='store_true',
                                 help='Disable all output messages')
        
        # Special Modes
        special_group = parser.add_argument_group('Special Modes')
        special_group.add_argument('-a', '--audit', action='store_true',
                                 help='Run embedding distribution analysis')
        special_group.add_argument('-ol', '--ollama-url', dest='ollama_url', type=str, 
                                 help='Ollama URL (default: http://localhost:11434)')
        special_group.add_argument('-V', '--version', action='store_true',
                                 help='Show OASIS version and exit')
        
        return parser

    def get_vulnerability_help(self) -> str:
        """Generate help text for vulnerability arguments"""
        vuln_map = get_vulnerability_mapping()
        vuln_list = [f"{tag:<8} - {vuln['name']}" for tag, vuln in vuln_map.items()]
        return (
            "Vulnerability types to check (comma-separated).\nAvailable tags:\n"
            + "\n".join(f"  {v}" for v in vuln_list)
            + "\n\nUse 'all' to check all vulnerabilities (default)"
        )

    def check_dependencies(self):
        """Check if A2A and MCP dependencies are available"""
        missing_deps = []
        
        try:
            import python_a2a
            logger.debug("✅ python-a2a available")
        except ImportError:
            missing_deps.append("python-a2a")
        
        try:
            import fastmcp
            logger.debug("✅ fastmcp available")
        except ImportError:
            missing_deps.append("fastmcp")
            
        if missing_deps:
            logger.warning(f"Missing dependencies for A2A/MCP: {', '.join(missing_deps)}")
            logger.info("Install with: pip install " + " ".join(A2A_DEPENDENCIES))
            logger.info("Falling back to legacy mode...")
            return False
        
        return True

    def run_analysis_mode(self, main_models, scan_model, vuln_mapping):
        """Run security analysis with specified models (enhanced for agents)"""
        # Get vulnerabilities to check
        from .agents import AgentOrchestrator
        vulnerabilities, invalid_tags = AgentOrchestrator.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        logger.info(f"\nStarting enhanced security analysis at {generate_timestamp()}\n")
        start_time = time.time()
        
        # Determine analysis approach
        if self.args.multi_agent and not self.legacy_mode:
            analysis_type = "🤝 multi-agent collaborative"
            return self._run_multi_agent_analysis(vulnerabilities, main_models, scan_model)
        else:
            analysis_type = "🧠 adaptive" if self.args.adaptive else "📋 standard"
            return self._run_legacy_analysis(vulnerabilities, main_models, scan_model)

    def _run_multi_agent_analysis(self, vulnerabilities, main_models, scan_model):
        """Run analysis with A2A agents"""
        logger.info("🤝 Starting multi-agent collaborative analysis")
        
        # Initialize agent orchestrator
        if not self.agent_orchestrator:
            self.agent_orchestrator = AgentOrchestrator(
                args=self.args,
                embedding_manager=self.embedding_manager,
                ollama_manager=self.ollama_manager,
                mcp_tools=self.mcp_tools
            )
        
        # Process analysis with agents
        try:
            all_results = self.agent_orchestrator.process_multi_agent_analysis(
                vulnerabilities, self.args, self.report
            )
            
            # Generate executive summary
            logger.info("📊 Generating executive summary")
            self.report.generate_executive_summary(all_results, "Multi-Agent Collaborative")
            
            self.report.report_generated(report_type='Multi-Agent Security', report_structure=True)
            return True
            
        except Exception as e:
            logger.exception(f"Error during multi-agent analysis: {str(e)}")
            return False

    def _run_legacy_analysis(self, vulnerabilities, main_models, scan_model):
        """Run original OASIS analysis (backward compatibility)"""
        logger.info("📋 Running legacy analysis mode")
        
        # Use original SecurityAnalyzer for backward compatibility
        from .agents import LegacySecurityAnalyzer
        
        for i, main_model in enumerate(main_models):
            msg = f"Running analysis with model {i+1}/{len(main_models)}: {main_model}"
            logger.info(f"\n{'='*len(msg)}")
            logger.info(msg)
            logger.info(f"{'='*len(msg)}")
            
            # Create legacy analyzer
            security_analyzer = LegacySecurityAnalyzer(
                args=self.args,
                llm_model=main_model,
                embedding_manager=self.embedding_manager,
                ollama_manager=self.ollama_manager,
                scan_model=scan_model
            )
            
            # Set current model for report generation
            self.report.current_model = main_model

            # Process analysis with selected model
            try:
                security_analyzer.process_analysis_with_model(
                    vulnerabilities, self.args, self.report
                )
            except Exception as e:
                logger.exception(f"Error during legacy analysis with {main_model}: {str(e)}")
                continue
        
        self.report.report_generated(report_type='Security', report_structure=True)
        return True

    def handle_audit_mode(self, vuln_mapping):
        """Handle audit mode - analyze embeddings distribution"""
        from .agents import EmbeddingAnalyzer
        
        # Get vulnerabilities to check
        vulnerabilities, invalid_tags = AgentOrchestrator.get_vulnerabilities_to_check(self.args, vuln_mapping)
        if invalid_tags:
            return False

        # Create analyzer
        embedding_analyzer = EmbeddingAnalyzer(self.embedding_manager, self.ollama_manager)

        # Analyze all vulnerabilities
        analyzer_results = embedding_analyzer.analyze_all_vulnerabilities(vulnerabilities)

        # Set current model for report generation
        self.report.current_model = embedding_analyzer.embedding_model

        # Generate audit report
        self.report.create_report_directories(self.args.input_path, models=[self.report.current_model])
        self.report.generate_audit_report(analyzer_results, self.embedding_manager)

        # Report generation
        self.report.report_generated(report_type='Audit', report_structure=True)

        logger.info(f'Audit completed successfully at {generate_timestamp()}')
        return True

    def run(self, args=None):
        """Run the enhanced OASIS scanner"""
        try:
            return self._init_oasis(args)
        except KeyboardInterrupt:
            logger.info(f"\nProcess interrupted by user at {generate_timestamp()}. Exiting...")
            self._save_cache_on_exit()
            return 1
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception(f"Full error trace: {traceback.format_exc()}", exc_info=True)
            return 1

    def _init_oasis(self, args):
        """Initialize OASIS with A2A/MCP support"""
        # Parse and validate arguments
        init_result = self._init_arguments(args)

        # Handle special early termination cases
        if init_result is None:
            return 0  # Success exit code for commands like --list-models
        elif init_result is False:
            return 1  # Error exit code for validation failures

        # Check dependencies
        if not self.check_dependencies() and (self.args.multi_agent or self.args.mcp_tools):
            logger.info("A2A/MCP features disabled due to missing dependencies")
            self.args.multi_agent = False
            self.args.mcp_tools = False
            self.legacy_mode = True

        # Initialize report
        self.report = Report(self.args.input_path, self.args.output_format)

        # Initialize Ollama and check connection
        if not self.args.web:
            if not self._init_ollama(self.args.ollama_url):
                return 1
            
            # Initialize MCP tools if enabled
            if self.args.mcp_tools and not self.legacy_mode:
                self._init_mcp_tools()
            
            # Initialize embedding manager and process input files
            return self._execute_requested_mode() if self._init_processing() else 1

        # Serve reports via web interface (enhanced with agent dashboard)
        WebServer(
            self.report, 
            debug=self.args.debug,
            web_expose=self.args.web_expose,
            web_password=self.args.web_password,
            web_port=self.args.web_port,
            agent_manager=self.agent_orchestrator,  # New: agent integration
            mcp_tools=self.mcp_tools  # New: MCP tools integration
        ).run()
        return 0

    def _init_arguments(self, args) -> Union[bool, None]:
        """Initialize and validate arguments"""
        # Parse command line arguments if not provided
        if args is None:
            parser = self.setup_argument_parser()
            self.args = parser.parse_args()
        else:
            self.args = args

        # Handle special cases that should terminate early
        if self.args.version:
            print(f"OASIS v{__version__} - Enhanced with A2A Agents and MCP Tools")
            return None
        
        if self.args.list_models:
            setup_logging(debug=self.args.debug, silent=False, error_log_file=None)
            display_logo()
            return self._handle_list_models_and_exit()
        
        # Validate required argument combinations
        if self.args.silent and not self.args.models and not self.args.audit:
            return self._handle_argument_errors(
                "When using --silent mode, you must specify models with --models/-m or use --audit"
            )
        
        # Check for required input path for normal operation
        if not self.args.input_path:
            return self._handle_argument_errors("--input/-i is required")
        
        # Set legacy mode if explicitly requested
        if self.args.legacy_mode:
            self.legacy_mode = True
            self.args.multi_agent = False
            self.args.mcp_tools = False
            logger.info("🔄 Legacy mode enabled - using original OASIS analysis")
        
        # Auto-enable multi-agent for collaborative analysis
        if self.args.analyze_type == 'collaborative':
            self.args.multi_agent = True
            self.args.agent_collaboration = True
        
        # Setup full logging with appropriate paths
        self._setup_logging()

        # Process output format
        if self.args.output_format == 'all':
            self.args.output_format = REPORT['OUTPUT_FORMATS']
        else:
            self.args.output_format = self.args.output_format.split(',')

        display_logo()
        
        # Show mode information
        if self.args.multi_agent and not self.legacy_mode:
            logger.info("🤝 Multi-agent collaborative analysis enabled")
        if self.args.mcp_tools and not self.legacy_mode:
            logger.info("🔧 MCP external tools integration enabled")
        
        return True

    def _init_ollama(self, ollama_url=None, check_embeddings=True):
        """Initialize Ollama and check connections"""
        # Initialize Ollama manager
        if ollama_url is None:
            ollama_url = self.args.ollama_url
        self.ollama_manager = OllamaManager(ollama_url)

        if self.ollama_manager.get_client() is None:
            logger.error("Ollama is not running. Please start Ollama and try again.")
            return False

        if not check_embeddings:
            return True

        # Auto-detect chunk size if not specified
        if self.args.chunk_size is None:
            self.args.chunk_size = self.ollama_manager.detect_optimal_chunk_size(self.args.embed_model)
        else:
            logger.info(f"Using manual chunk size: {self.args.chunk_size}")

        # Check Ollama connection
        if not self.ollama_manager.check_connection():
            return False

        # Check embedding model availability
        return bool(self.ollama_manager.ensure_model_available(self.args.embed_model))

    def _init_mcp_tools(self):
        """Initialize MCP tools"""
        try:
            logger.info("🔧 Initializing MCP tools...")
            self.mcp_tools = MCPToolManager(
                config_file=self.args.mcp_config,
                enabled=self.args.mcp_tools
            )
            
            # Start MCP servers
            if self.mcp_tools.start_servers():
                logger.info("✅ MCP tools initialized successfully")
            else:
                logger.warning("⚠️  Some MCP tools failed to initialize")
                
        except Exception as e:
            logger.exception(f"Error initializing MCP tools: {str(e)}")
            logger.warning("Continuing without MCP tools...")
            self.mcp_tools = None
            self.args.mcp_tools = False

    def _init_processing(self):
        """Initialize embedding manager and process input files"""
        # Initialize embedding manager
        self.embedding_manager = EmbeddingManager(self.args, self.ollama_manager)

        # Process input files
        processed_files = self.embedding_manager.process_input_files(self.args)
        
        if not processed_files:
            logger.error("No files were processed successfully")
            return False
            
        return True

    def _execute_requested_mode(self):
        """Execute requested analysis mode"""
        # Get vulnerability mapping for all modes
        vuln_mapping = get_vulnerability_mapping()

        # Determine and execute appropriate mode
        if self.args.audit:
            result = self.handle_audit_mode(vuln_mapping)
            return 0 if result else 1

        # Analysis mode
        return self._run_analysis_mode(vuln_mapping)

    def _run_analysis_mode(self, vuln_mapping):
        """Run security analysis with selected models"""
        # Get analysis type
        analysis_type = self.ollama_manager.select_analysis_type(self.args)
        if not analysis_type:
            return 1

        # Get available models
        available_models = self.ollama_manager.get_available_models()
        if not available_models:
            logger.error("No models available. Please check Ollama installation.")
            return 1

        # Get selected models (either from args or interactive selection)
        selected_model_data = self.ollama_manager.select_analysis_models(self.args, available_models)
        if not selected_model_data:
            return 1
        
        # Extract the scan model and main models
        scan_model = selected_model_data['scan_model']
        main_models = selected_model_data['main_models']
        
        if not scan_model:
            logger.error("No scan model was selected.")
            return 1
            
        if not main_models:
            logger.warning("No main models were selected, using scan model for deep analysis as well")
            main_models = [scan_model]
        
        # Store the scan model in the arguments
        self.args.scan_model = scan_model
        
        # Log model selection information
        display_scan_model = self.ollama_manager.get_model_display_name(scan_model)
        display_main_models = ", ".join([self.ollama_manager.get_model_display_name(m) for m in main_models])
        
        if len(main_models) == 1 and scan_model == main_models[0]:
            logger.info(f"{MODEL_EMOJIS['default']}Using '{display_scan_model}' for both scanning and deep analysis")
        else:
            logger.info(f"{MODEL_EMOJIS['default']}Using '{display_scan_model}' for scanning and {display_main_models} for deep analysis")
        
        # Create the report directories for all main models
        self.report.models = main_models
        self.report.create_report_directories(self.args.input_path, models=main_models)

        # Run analysis
        result = self.run_analysis_mode(main_models, scan_model, vuln_mapping)
        if not result:
            return 1

        # Output cache file location
        logger.info(f"\nCache file: {self.embedding_manager.cache_file}")
        
        # Show additional information for multi-agent mode
        if self.args.multi_agent and self.agent_orchestrator:
            logger.info(f"Agent cache files: {self.agent_orchestrator.get_cache_info()}")
            
        if self.args.mcp_tools and self.mcp_tools:
            logger.info(f"MCP tools used: {', '.join(self.mcp_tools.get_active_tools())}")
        
        return 0

    def _save_cache_on_exit(self):
        """Save cache when exiting due to interruption"""
        try:
            if hasattr(self, 'embedding_manager') and self.embedding_manager:
                self.embedding_manager.save_cache()
                logger.info("Embedding cache saved successfully.")
                
            if hasattr(self, 'agent_orchestrator') and self.agent_orchestrator:
                self.agent_orchestrator.save_all_caches()
                logger.info("Agent caches saved successfully.")
                
            if hasattr(self, 'mcp_tools') and self.mcp_tools:
                self.mcp_tools.cleanup()
                logger.info("MCP tools cleaned up successfully.")
                
        except Exception:
            logger.error("Failed to save cache on interruption.")

    def _setup_logging(self):
        """Configure logging based on arguments"""
        if self.args.silent:
            logs_dir = Path(self.args.input_path).resolve().parent / REPORT['OUTPUT_DIR'] / "logs" if self.args.input_path else Path(REPORT['OUTPUT_DIR']) / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            log_file = logs_dir / f"oasis_errors_{generate_timestamp(for_file=True)}.log"
        else:
            log_file = None
            
        setup_logging(debug=self.args.debug, silent=self.args.silent, error_log_file=log_file)

    def _handle_argument_errors(self, error_msg):
        """Handle argument validation errors"""
        setup_logging(debug=self.args.debug, silent=False, error_log_file=None)
        logger.error(error_msg)
        return False

    def _handle_list_models_and_exit(self):
        """Handle --list-models option"""
        try:
            self._init_ollama(self.args.ollama_url, check_embeddings=False)
                
            logger.info("🔎 Querying available models from Ollama...")
            
            # Display formatted list of models
            available_models = self.ollama_manager.get_available_models(show_formatted=True)
            
            if not available_models:
                logger.error("No models available. Please check your Ollama installation.")
            
            return None  # Special return value to indicate early termination
        except Exception as e:
            return self._handle_model_list_error(e)
        
    def _handle_model_list_error(self, e):
        """Handle errors when listing models"""
        logger.error(f"Error listing models: {str(e)}")
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug("Full error:", exc_info=True)
        return False

# Main functions for backward compatibility
def main():
    """Main entry point for the enhanced OASIS scanner"""
    orchestrator = OasisOrchestrator()
    return orchestrator.run()

def create_app():
    """Create Flask app for web interface"""
    # This would be used for external integrations
    orchestrator = OasisOrchestrator()
    # Initialize with minimal setup for web mode
    return orchestrator

if __name__ == "__main__":
    sys.exit(main())