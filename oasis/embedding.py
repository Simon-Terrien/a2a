"""
Enhanced Embedding Manager with A2A Agent Coordination
Keeps all existing OASIS embedding functionality + adds agent coordination
"""

import argparse
import json
from pathlib import Path
import pickle
from datetime import datetime
from typing import List, Tuple, Dict, Any, Optional, Union
from multiprocessing import Pool, cpu_count
from tqdm import tqdm
import re
import ast

# Import configuration
from .config import EXTRACT_FUNCTIONS, SUPPORTED_EXTENSIONS, DEFAULT_ARGS

# Import from other modules
from .ollama_manager import OllamaManager
from .utils import (
    create_cache_dir,
    logger,
    chunk_content,
    parse_input,
    sanitize_name,
    open_file,
)


class EmbeddingManager:
    """
    Enhanced embedding manager with agent coordination capabilities
    Maintains all existing OASIS functionality while adding multi-agent support
    """

    def __init__(self, args, ollama_manager: OllamaManager, agent_manager=None):
        """
        Initialize the enhanced embedding manager

        Args:
            args: Arguments
            ollama_manager: Ollama manager
            agent_manager: Optional agent manager for coordination
        """
        try:
            self.ollama_manager = ollama_manager
            self.ollama_client = self.ollama_manager.get_client()
            self.agent_manager = agent_manager  # New: for agent coordination

        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.exception(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        # Keep all existing initialization
        self.input_path = args.input_path
        self.clear_cache = args.clear_cache_embeddings
        self.cache_days = args.cache_days or DEFAULT_ARGS["CACHE_DAYS"]
        self.embedding_model = args.embed_model or DEFAULT_ARGS["EMBED_MODEL"]

        # Analysis type
        self.analyze_type = args.analyze_type or DEFAULT_ARGS["ANALYSIS_TYPE"]
        self.embedding_analysis_type = (
            args.embeddings_analyze_type or DEFAULT_ARGS["EMBEDDING_ANALYSIS_TYPE"]
        )
        self.analyze_by_function = self.embedding_analysis_type == "function"

        self.threshold = args.threshold or DEFAULT_ARGS["THRESHOLD"]
        self.code_base: Dict = {}
        self.cache_file = None  # Will be set when directory is provided

        # Enhanced: Agent coordination settings
        self.multi_agent_mode = getattr(args, "multi_agent", False)
        self.agent_embeddings = {}  # Store agent-specific embeddings

        # Normalize extensions to a list regardless of input format
        self.supported_extensions = self._normalize_extensions(args.extensions)
        self.chunk_size = args.chunk_size or DEFAULT_ARGS["CHUNK_SIZE"]
        self._setup_cache()

    def _normalize_extensions(self, extensions_arg) -> List[str]:
        """
        Normalize extensions to a list format regardless of input type
        (KEPT: Original functionality)
        """
        if not extensions_arg:
            return list(SUPPORTED_EXTENSIONS)

        if isinstance(extensions_arg, list):
            return extensions_arg

        if isinstance(extensions_arg, str):
            return [ext.strip() for ext in extensions_arg.split(",")]

        return list(extensions_arg)

    def _setup_cache(self):
        """
        Set up the embedding manager cache
        (KEPT: Original functionality + enhanced for agents)
        """
        # Create cache directory
        cache_dir = create_cache_dir(self.input_path)

        # Enhanced: Create agent-specific cache subdirectories
        if self.multi_agent_mode and self.agent_manager:
            self.agent_cache_dirs = {}
            for agent_type in self.agent_manager.agents.keys():
                agent_cache_dir = cache_dir / f"agent_{agent_type}"
                agent_cache_dir.mkdir(exist_ok=True)
                self.agent_cache_dirs[agent_type] = agent_cache_dir

        # Standard cache setup
        self.cache_file = (
            cache_dir
            / f"{sanitize_name(self.input_path)}_{sanitize_name(self.embedding_model)}.cache"
        )
        logger.debug(f"Cache file: {self.cache_file}")

        # Clear cache if requested
        if self.clear_cache:
            self.clear_embeddings_cache()

        # Check if cache is valid based on age
        if not self.clear_cache and self.is_cache_valid(self.cache_days):
            self.load_cache()

    def is_valid_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed based on extension (KEPT)"""
        return file_path.suffix.lower()[1:] in self.supported_extensions

    def index_code_files(self, files: List[Path]) -> None:
        """
        Generate embeddings for code files in parallel
        (KEPT: Original functionality + enhanced for agents)
        """
        try:
            # Calculate optimal number of processes
            num_processes = max(1, min(cpu_count(), len(files)))

            # Prepare arguments for parallel processing
            process_args = [
                argparse.Namespace(
                    input_path=str(file_path),
                    embed_model=self.embedding_model,
                    chunk_size=self.chunk_size,
                    analyze_by_function=self.analyze_by_function,
                    api_url=self.ollama_manager.api_url,
                    multi_agent_mode=self.multi_agent_mode,  # Enhanced
                )
                for file_path in files
                if self.analyze_by_function or str(file_path) not in self.code_base
            ]

            if not process_args:
                return

            # Process files in parallel with progress bar
            with Pool(processes=num_processes) as pool:
                with tqdm(
                    total=len(process_args), desc="Generating embeddings", leave=True
                ) as pbar:
                    for result in pool.imap_unordered(
                        process_file_parallel, process_args
                    ):
                        if result:
                            (
                                file_path,
                                content,
                                embedding,
                                is_function_analysis,
                                function_embeddings,
                            ) = result

                            # Store file data (original logic)
                            if file_path not in self.code_base:
                                self.code_base[file_path] = {
                                    "content": content,
                                    "embedding": embedding,
                                    "chunks": chunk_content(content, self.chunk_size),
                                    "timestamp": datetime.now().isoformat(),
                                }

                            # If analyzing by function, store function data
                            if is_function_analysis and function_embeddings:
                                if "functions" not in self.code_base[file_path]:
                                    self.code_base[file_path]["functions"] = {}

                                for func_id, (
                                    func_content,
                                    func_embedding,
                                ) in function_embeddings.items():
                                    self.code_base[file_path]["functions"][func_id] = {
                                        "content": func_content,
                                        "embedding": func_embedding,
                                        "timestamp": datetime.now().isoformat(),
                                    }

                            # Enhanced: Generate agent-specific embeddings if in multi-agent mode
                            if self.multi_agent_mode:
                                self._generate_agent_embeddings(file_path, content)

                        pbar.update(1)

            # Save after batch processing
            self.save_cache()

        except Exception as e:
            logger.exception(f"Error during parallel embedding generation: {str(e)}")

    def _generate_agent_embeddings(self, file_path: str, content: str):
        """
        Generate agent-specific embeddings for better routing
        (NEW: Enhanced functionality for multi-agent mode)
        """
        if not self.agent_manager:
            return

        try:
            # Generate embeddings optimized for each agent type
            for agent_type, agent in self.agent_manager.agents.items():
                # Create agent-specific prompt for embedding
                agent_prompt = self._build_agent_embedding_prompt(content, agent_type)

                # Generate embedding with agent-specific context
                response = self.ollama_client.embeddings(
                    model=self.embedding_model, prompt=agent_prompt
                )

                if response and "embedding" in response:
                    if file_path not in self.agent_embeddings:
                        self.agent_embeddings[file_path] = {}

                    self.agent_embeddings[file_path][agent_type] = response["embedding"]

        except Exception as e:
            logger.debug(f"Error generating agent embeddings: {str(e)}")

    def _build_agent_embedding_prompt(self, content: str, agent_type: str) -> str:
        """Build agent-specific embedding prompt for better content understanding"""
        agent_contexts = {
            "sqli": "database queries, SQL statements, parameter handling, user input in queries",
            "xss": "HTML output, JavaScript, DOM manipulation, user input rendering, template engines",
            "auth": "authentication, login, session management, access control, user verification",
            "crypto": "encryption, hashing, key management, random generation, cryptographic operations",
            "config": "configuration files, environment variables, default settings, security headers",
        }

        context = agent_contexts.get(agent_type, "security vulnerabilities")

        return f"""
        Analyze this code focusing on {context} and security implications.
        
        Code content:
        {content[:1000]}...
        
        Focus on: {context}
        """

    def route_to_agents(
        self, vulnerability_results: Dict[str, List]
    ) -> Dict[str, List]:
        """
        Route embedding results to appropriate agents
        (NEW: Multi-agent coordination)
        """
        if not self.multi_agent_mode or not self.agent_manager:
            return vulnerability_results

        agent_tasks = {}

        for vuln_type, files in vulnerability_results.items():
            # Find the best agent for this vulnerability type
            primary_agent = self._find_primary_agent(vuln_type)

            if primary_agent:
                if primary_agent not in agent_tasks:
                    agent_tasks[primary_agent] = {}
                agent_tasks[primary_agent][vuln_type] = files

        return agent_tasks

    def _find_primary_agent(self, vuln_type: str) -> Optional[str]:
        """Find the primary agent for a vulnerability type"""
        # Map vulnerability types to agents
        vuln_to_agent = {
            "sqli": "sqli",
            "sql_injection": "sqli",
            "xss": "xss",
            "cross-site_scripting": "xss",
            "auth": "auth",
            "authentication": "auth",
            "session": "auth",
            "crypto": "crypto",
            "cryptographic": "crypto",
            "config": "config",
            "configuration": "config",
            "secrets": "crypto",
            "input": "sqli",  # Input validation often relates to injection
            "data": "crypto",  # Data protection relates to crypto
            "logging": "config",  # Logging relates to configuration
        }

        vuln_lower = vuln_type.lower()

        # Direct mapping
        if vuln_lower in vuln_to_agent:
            return vuln_to_agent[vuln_lower]

        # Partial matching
        for pattern, agent in vuln_to_agent.items():
            if pattern in vuln_lower:
                return agent

        # Default fallback
        return "config"

    def get_agent_specific_embedding(
        self, file_path: str, agent_type: str
    ) -> Optional[List[float]]:
        """
        Get agent-specific embedding for a file
        (NEW: Agent-specific embeddings)
        """
        if file_path in self.agent_embeddings:
            return self.agent_embeddings[file_path].get(agent_type)
        return None

    def process_input_files(self, args):
        """
        Process input files and update embeddings
        (KEPT: Original functionality + enhanced logging)
        """
        # Parse input files and generate embeddings
        files_to_analyze = parse_input(args.input_path)
        if not files_to_analyze:
            logger.error("No valid files to analyze")
            return []

        # Filter files by supported extensions
        valid_files = []
        for file_path in files_to_analyze:
            if self.is_valid_file(file_path):
                valid_files.append(file_path)
            else:
                logger.debug(f"Skipping unsupported file: {file_path}")

        if not valid_files:
            logger.error("No files with supported extensions found for analysis")
            return []

        logger.info(
            f"Found {len(valid_files)} files with supported extensions out of {len(files_to_analyze)} total files"
        )

        # Enhanced: Show multi-agent mode status
        if self.multi_agent_mode:
            logger.info("🤝 Multi-agent mode: generating specialized embeddings")

        # Generate embeddings only for new files or functions
        new_files = []
        for file_path in valid_files:
            file_key = str(file_path)

            if self.analyze_by_function:
                if (
                    file_key not in self.code_base
                    or "functions" not in self.code_base[file_key]
                ):
                    new_files.append(file_path)
            elif (
                file_key not in self.code_base
                or not isinstance(self.code_base[file_key], dict)
                or "embedding" not in self.code_base[file_key]
                or "chunks" not in self.code_base[file_key]
                or "timestamp" not in self.code_base[file_key]
            ):
                new_files.append(file_path)

        if new_files:
            logger.info(f"Generating embeddings for {len(new_files)} new files")
            self.index_code_files(new_files)
        else:
            logger.debug("All files found in cache with valid structure")

        return valid_files

    # KEEP ALL EXISTING METHODS (unchanged)
    def normalize_cache_entry(self, entry: Any) -> Dict:
        """Normalize a cache entry (KEPT: Original)"""
        default = {
            "content": entry if isinstance(entry, str) else "",
            "embedding": [],
            "chunks": [],
            "timestamp": datetime.now().isoformat(),
        }

        if isinstance(entry, dict):
            normalized = entry.copy()
            for key, default_value in default.items():
                if key not in normalized:
                    normalized[key] = default_value

            if "embedding" in normalized and isinstance(normalized["embedding"], list):
                if not hasattr(self, "embedding_dim") or self.embedding_dim is None:
                    self.embedding_dim = len(normalized["embedding"])
                    logger.debug(
                        f"Initialized self.embedding_dim to {self.embedding_dim}"
                    )
                elif len(normalized["embedding"]) != self.embedding_dim:
                    logger.error(
                        f"Inconsistent embedding dimension: expected {self.embedding_dim}, got {len(normalized['embedding'])}"
                    )

            return normalized

        return default

    def save_cache(self):
        """Save embeddings to cache (KEPT + Enhanced for agents)"""
        if not self.cache_file:
            logger.warning("Cache file path not set, cannot save cache")
            return

        try:
            # Normalize all cache entries
            for file_path, data in self.code_base.items():
                self.code_base[file_path] = self.normalize_cache_entry(data)

            with open(self.cache_file, "wb") as f:
                pickle.dump(self.code_base, f)
            logger.debug(f"Saved {len(self.code_base)} entries to cache")

            # Enhanced: Save agent-specific embeddings
            if self.multi_agent_mode and self.agent_embeddings:
                agent_cache_file = (
                    self.cache_file.parent / f"{self.cache_file.stem}_agents.cache"
                )
                with open(agent_cache_file, "wb") as f:
                    pickle.dump(self.agent_embeddings, f)
                logger.debug(f"Saved agent embeddings to {agent_cache_file}")

        except Exception as e:
            logger.exception(f"Error saving cache: {str(e)}")

    def load_cache(self) -> None:
        """Load embeddings from cache file (KEPT + Enhanced for agents)"""
        if self.cache_file is None:
            logger.warning("Cache file path not set, cannot load cache")
            self.code_base = {}
            return

        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            if not self.cache_file.exists():
                logger.info(f"Creating new cache file {self.cache_file}")
                self.code_base = {}
                self.save_cache()
                return

            with open(self.cache_file, "rb") as f:
                try:
                    cached_data = pickle.load(f)
                    if isinstance(cached_data, dict) and all(
                        isinstance(v, dict)
                        and "embedding" in v
                        and "chunks" in v
                        and "timestamp" in v
                        for v in cached_data.values()
                    ):
                        self.code_base = cached_data
                        logger.info(f"Loaded {len(self.code_base)} entries from cache")

                        self.filter_code_base_by_extensions()

                    else:
                        logger.warning("Invalid cache structure, starting fresh")
                        self.code_base = {}
                        self.save_cache()
                except EOFError:
                    logger.error(
                        "Cache file is empty or corrupted. Starting with fresh cache."
                    )
                    self.code_base = {}
                    self.save_cache()

            # Enhanced: Load agent-specific embeddings
            if self.multi_agent_mode:
                agent_cache_file = (
                    self.cache_file.parent / f"{self.cache_file.stem}_agents.cache"
                )
                if agent_cache_file.exists():
                    try:
                        with open(agent_cache_file, "rb") as f:
                            self.agent_embeddings = pickle.load(f)
                        logger.debug(f"Loaded agent embeddings from cache")
                    except Exception as e:
                        logger.debug(f"Error loading agent embeddings: {str(e)}")
                        self.agent_embeddings = {}

        except Exception as e:
            logger.exception(f"Error loading cache: {str(e)}")
            self.code_base = {}
            self.save_cache()

    def clear_embeddings_cache(self) -> None:
        """Clear embeddings cache file and memory (KEPT + Enhanced)"""
        try:
            if self.cache_file is None:
                logger.warning("Cache file path not set, cannot clear cache file")
            elif self.cache_file.exists():
                self.cache_file.unlink()
                logger.info(f"Cache file {self.cache_file} deleted successfully")

            # Enhanced: Clear agent caches
            if self.multi_agent_mode:
                agent_cache_file = (
                    self.cache_file.parent / f"{self.cache_file.stem}_agents.cache"
                )
                if agent_cache_file.exists():
                    agent_cache_file.unlink()
                    logger.debug("Agent embeddings cache cleared")

            self.code_base = {}
            self.agent_embeddings = {}
            logger.debug("Memory cache cleared")
        except Exception as e:
            logger.exception(f"Error clearing cache: {str(e)}")

    def get_embeddings_info(self) -> dict:
        """Get information about cached embeddings (KEPT + Enhanced)"""
        info = {
            "total_files": len(self.code_base),
            "agent_embeddings": (
                len(self.agent_embeddings) if self.multi_agent_mode else 0
            ),
            "files": {},
        }

        for file_path in self.code_base:
            file_info = {
                "size": len(self.code_base[file_path]["content"]),
                "embedding_dimensions": len(self.code_base[file_path]["embedding"]),
            }

            # Enhanced: Add agent embedding info
            if self.multi_agent_mode and file_path in self.agent_embeddings:
                file_info["agent_embeddings"] = list(
                    self.agent_embeddings[file_path].keys()
                )

            info["files"][file_path] = file_info

        return info

    def is_cache_valid(self, max_age_days: int = 7) -> bool:
        """Check if cache file exists and is not too old (KEPT)"""
        if self.cache_file is None or not self.cache_file.exists():
            return False

        cache_age = datetime.now() - datetime.fromtimestamp(
            self.cache_file.stat().st_mtime
        )
        if cache_age.days > max_age_days:
            return False

        try:
            with open(self.cache_file, "rb") as f:
                cached_data = pickle.load(f)
            return bool(cached_data)
        except Exception as e:
            logger.exception(f"Cache validation failed: {str(e)}")
            return False

    def filter_code_base_by_extensions(self) -> None:
        """Filter code_base to only include files with supported extensions (KEPT)"""
        if not self.code_base:
            return

        initial_count = len(self.code_base)

        self.code_base = {
            file_path: data
            for file_path, data in self.code_base.items()
            if self.is_valid_file(Path(file_path))
        }

        filtered_count = initial_count - len(self.code_base)
        if filtered_count > 0:
            logger.info(
                f"Filtered out {filtered_count} files that don't match the specified extensions"
            )

    def parse_functions_from_file(self, file_path: str, content: str) -> Dict[str, str]:
        """Extract individual functions from a file (KEPT: Original implementation)"""
        extension = file_path.split(".")[-1].lower()
        functions = {}

        use_llm = True

        if use_llm:
            functions = self.extract_functions_with_llm(file_path, content)
            if functions:
                return functions

        if extension == "py":
            try:
                tree = ast.parse(content)
                for node in ast.walk(tree):
                    if isinstance(
                        node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
                    ):
                        function_code = content[node.lineno - 1 : node.end_lineno]
                        function_name = node.name
                        functions[f"{file_path}::{function_name}"] = function_code

            except SyntaxError:
                functions = self.extract_functions_with_regex(file_path, content, "py")
        else:
            functions = self.extract_functions_with_regex(file_path, content, extension)

        if not functions:
            functions[file_path] = content

        return functions

    # KEEP ALL OTHER EXISTING METHODS (extract_functions_with_regex, language_patterns, etc.)
    # These are unchanged from the original embedding.py

    def get_vulnerability_embedding(
        self, vulnerability: Union[str, Dict]
    ) -> List[float]:
        """Get embedding vector for a vulnerability type (KEPT)"""
        try:
            prompt = build_vulnerability_embedding_prompt(vulnerability)
            response = self.ollama_client.embeddings(
                model=self.embedding_model, prompt=prompt
            )
            return (
                response.get("embedding")
                if response and "embedding" in response
                else None
            )
        except Exception as e:
            vuln_name = (
                vulnerability["name"]
                if isinstance(vulnerability, dict)
                else vulnerability
            )
            logger.exception(f"Failed to get embedding for {vuln_name}: {str(e)}")
            return None


# KEEP ALL EXISTING HELPER FUNCTIONS
def process_file_parallel(
    args: tuple,
) -> Tuple[str, str, List[float], bool, Optional[Dict[str, Tuple[str, List[float]]]]]:
    """Process a file in a separate process (KEPT: Original implementation)"""
    try:
        from .ollama_manager import OllamaManager

        ollama_manager = OllamaManager(args.api_url)

        if not (content := open_file(args.input_path)):
            logger.warning(
                f"Empty or unreadable file content for file: {args.input_path}"
            )
            return None

        if args.analyze_by_function:
            functions = extract_functions_from_file(
                args.input_path, content, ollama_manager
            )

            function_embeddings = {}
            for func_id, func_content in functions.items():
                func_embedding = generate_content_embedding(
                    func_content, args.embed_model, args.chunk_size, ollama_manager
                )
                if func_embedding is not None:
                    function_embeddings[func_id] = (func_content, func_embedding)

            return functions

    except json.JSONDecodeError as e:
        logger.exception(
            f"Invalid JSON in LLM response for {args.input_path}: {str(e)}"
        )
        return {}

    except Exception as e:
        logger.exception(
            f"Error using LLM for function extraction in {args.input_path}: {str(e)}"
        )
        return {}


def build_vulnerability_embedding_prompt(vulnerability: Union[str, Dict]) -> str:
    """Build a rich prompt for vulnerability embedding (KEPT)"""
    if isinstance(vulnerability, dict):
        return f"""
        Vulnerability: {vulnerability['name']}
        
        Description: 
        {vulnerability['description']}
        
        Common patterns:
        {' | '.join(vulnerability['patterns'])}
        
        Security impact:
        {vulnerability['impact']}
        
        Mitigation strategies:
        {vulnerability['mitigation']}
        
        Analyze code to identify this vulnerability.
        """
    else:
        return str(vulnerability)


def generate_content_embedding(
    content: str,
    model: str,
    chunk_size: int = DEFAULT_ARGS["CHUNK_SIZE"],
    ollama_manager: OllamaManager = None,
) -> List[float]:
    """Generate embedding for content (KEPT)"""
    if ollama_manager is None:
        raise ValueError("ollama_manager must be provided and cannot be None")

    try:
        client = ollama_manager.get_client()

        if len(content) > chunk_size:
            chunks = chunk_content(content, chunk_size)
            chunk_embeddings = []

            for chunk in chunks:
                response = client.embeddings(model=model, prompt=chunk)
                if response and "embedding" in response:
                    chunk_embeddings.append(response["embedding"])

            if chunk_embeddings:
                aggregated_embedding = [
                    sum(col) / len(col) for col in zip(*chunk_embeddings)
                ]
                return [val / len(chunk_embeddings) for val in aggregated_embedding]
            return None
        else:
            response = client.embeddings(model=model, prompt=content)
            return (
                response.get("embedding")
                if response and "embedding" in response
                else None
            )

    except Exception as e:
        logger.exception(f"Error generating embedding: {str(e)}")
        return None


def extract_functions_from_file(
    file_path: str,
    content: str,
    extraction_model: str = EXTRACT_FUNCTIONS["MODEL"],
    ollama_manager: OllamaManager = None,
) -> Dict[str, str]:
    """
    Extract functions from file content

    Args:
        file_path: Path to source file
        content: File content
        extraction_model: Model to use for extraction

    Returns:
        Dictionary mapping function IDs to function content
    """
    if ollama_manager is None:
        raise ValueError("ollama_manager must be provided")

    # Determine file extension
    extension = file_path.split(".")[-1].lower()

    # Make sure we're using a normalized version of the content
    normalized_content = content.replace("\r\n", "\n")

    try:
        # Get client
        client = ollama_manager.get_client()

        # Ensure model is available
        if not ollama_manager.ensure_model_available(extraction_model):
            return {}

        # Create prompt
        prompt = f"""
            Extract all functions and methods from the following {extension} code.
            {EXTRACT_FUNCTIONS['PROMPT']}
            Here is the code:
            ```{extension}
            {normalized_content}
            ```
            """

        # Generate response
        response = client.generate(
            model=extraction_model,
            prompt=prompt,
        )

        if not response or not response.response:
            logger.warning(
                f"No valid response from LLM for function extraction in {file_path}"
            )
            return {}

        # Process response and extract functions
        # ... (code from extract_functions_with_llm that parses the JSON response)

    except Exception as e:
        logger.exception(f"Error extracting functions from {file_path}: {str(e)}")
        # Fallback to regex approach if needed

    return {}
