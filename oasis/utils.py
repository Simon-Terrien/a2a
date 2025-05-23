"""
Enhanced OASIS Utilities with Agent and MCP Support
Renamed from tools.py + added agent-specific utilities
"""

from datetime import datetime
import logging
from pathlib import Path
import re
import numpy as np
from typing import List, Dict, Any, Optional, Union
from weasyprint.logger import LOGGER as weasyprint_logger
import hashlib
import json

# Import configuration
from .config import KEYWORD_LISTS, MODEL_EMOJIS, VULNERABILITY_MAPPING

# Initialize logger with module name
logger = logging.getLogger("oasis")

# Suppress weasyprint warnings
logging.getLogger("weasyprint").setLevel(logging.ERROR)


class EmojiFormatter(logging.Formatter):
    """
    Custom formatter that adds contextual emojis to log messages
    Enhanced with agent and MCP-specific emojis
    """

    @staticmethod
    def has_emoji_prefix(text: str) -> bool:
        """Check if text already has emoji prefix (KEPT)"""
        emoji_ranges = [
            (0x1F300, 0x1F9FF),  # Misc Symbols & Pictographs
            (0x2600, 0x26FF),  # Misc Symbols
            (0x2700, 0x27BF),  # Dingbats
            (0x1F600, 0x1F64F),  # Emoticons
            (0x1F680, 0x1F6FF),  # Transport & Map Symbols
        ]
        if not text:
            return False
        first_char = text.strip()[0]
        code = ord(first_char)
        return any(start <= code <= end for start, end in emoji_ranges)

    def determine_icon(self, record) -> str:
        """Determine appropriate icon for log message (KEPT + Enhanced)"""
        # Early returns for non-string messages or messages with emoji prefixes
        if not isinstance(record.msg, str) or self.has_emoji_prefix(record.msg.strip()):
            return ""

        msg_lower = record.msg.lower()

        # Level-based icons
        if record.levelno == logging.DEBUG:
            return "🪲  "
        if record.levelno == logging.WARNING:
            return "⚠️  "
        if record.levelno == logging.ERROR:
            return (
                "💥 "
                if any(word in msg_lower for word in KEYWORD_LISTS["FAIL_WORDS"])
                else "❌ "
            )
        if record.levelno == logging.CRITICAL:
            return "🚨 "

        # INFO level processing - check for model names first
        if record.levelno == logging.INFO:
            # Check for model names first
            for model_name in MODEL_EMOJIS:
                if model_name.lower() in msg_lower:
                    return ""

            # Enhanced: Map keyword categories to icons (including new agent/MCP keywords)
            keyword_to_icon = {
                "INSTALL_WORDS": "📥 ",
                "START_WORDS": "🚀 ",
                "FINISH_WORDS": "🏁 ",
                "STOPPED_WORDS": "🛑 ",
                "DELETE_WORDS": "🗑️ ",
                "SUCCESS_WORDS": "✅ ",
                "GENERATION_WORDS": "⚙️  ",
                "REPORT_WORDS": "📄 ",
                "MODEL_WORDS": "🤖 ",
                "CACHE_WORDS": "💾 ",
                "SAVE_WORDS": "💾 ",
                "LOAD_WORDS": "📂 ",
                "STATISTICS_WORDS": "📊 ",
                "TOP_WORDS": "🏆 ",
                "VULNERABILITY_WORDS": "🚨 ",
                "ANALYSIS_WORDS": "🔎 ",
                "AGENT_WORDS": "🤝 ",  # NEW: Agent-specific
            }

            # Check each category and return the first matching icon
            for category, icon in keyword_to_icon.items():
                if any(word in msg_lower for word in KEYWORD_LISTS[category]):
                    return icon

        # Default: no icon
        return ""

    def format(self, record):
        """Format log record with emoji (KEPT)"""
        if hasattr(record, "emoji") and not record.emoji:
            return record.msg
        if not hasattr(record, "formatted_message"):
            icon = self.determine_icon(record)
            if record.msg.startswith("\n"):
                record.formatted_message = record.msg.replace("\n", f"\n{icon}", 1)
            else:
                record.formatted_message = f"{icon}{record.msg}"
        return record.formatted_message


def setup_logging(debug=False, silent=False, error_log_file=None):
    """
    Setup all loggers with proper configuration (KEPT)
    """
    # Set root logger level
    root_logger = logging.getLogger()

    # Avoid adding duplicate handlers if they already exist
    if root_logger.handlers:
        return

    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)

    # Configure handlers based on silent mode
    if not silent:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(EmojiFormatter())
        logger.addHandler(console_handler)

    # Add file handler for errors in silent mode
    if silent and error_log_file:
        file_handler = logging.FileHandler(error_log_file)
        file_handler.setLevel(logging.ERROR)  # Only log errors and above
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False  # Prevent duplicate logging

    # Set OASIS logger level based on mode
    if silent and not error_log_file:
        logger.setLevel(logging.CRITICAL + 1)  # Above all levels (complete silence)
    elif silent:
        logger.setLevel(logging.ERROR)  # Only errors and above if logging to file
    elif debug:
        logger.setLevel(logging.DEBUG)  # Show all messages
    else:
        logger.setLevel(logging.INFO)  # Show info, warning, error

    # Configure other loggers
    fonttools_logger = logging.getLogger("fontTools")
    fonttools_logger.setLevel(logging.ERROR)

    weasyprint_logger.setLevel(logging.ERROR)

    # Disable other verbose loggers
    logging.getLogger("PIL").setLevel(logging.WARNING)
    logging.getLogger("markdown").setLevel(logging.WARNING)


def chunk_content(content: str, max_length: int = 2048) -> List[str]:
    """
    Split content into chunks of maximum length while preserving line integrity (KEPT)
    """
    if len(content) <= max_length:
        return [content]

    chunks = []
    lines = content.splitlines()
    current_chunk = []
    current_length = 0

    for line in lines:
        line_length = len(line) + 1  # +1 for newline
        if current_length + line_length > max_length:
            if current_chunk:
                chunks.append("\n".join(current_chunk))
            current_chunk = [line]
            current_length = line_length
        else:
            current_chunk.append(line)
            current_length += line_length

    if current_chunk:
        chunks.append("\n".join(current_chunk))

    logger.debug(f"Split content of {len(content)} chars into {len(chunks)} chunks")

    return chunks


def extract_clean_path(input_path: str | Path) -> Path:
    """
    Extract a clean path from input that might contain additional arguments (KEPT)
    """
    # Determine input type to preserve it for output
    is_path_object = isinstance(input_path, Path)

    # Convert to string for processing
    input_path_str = str(input_path)

    # Extract the actual path before any arguments
    path_parts = input_path_str.split()
    actual_path = path_parts[0] if path_parts else input_path_str

    # Handle quoted paths (remove quotes if present)
    if actual_path.startswith('"') and actual_path.endswith('"'):
        actual_path = actual_path[1:-1]
    elif actual_path.startswith("'") and actual_path.endswith("'"):
        actual_path = actual_path[1:-1]

    logger.debug(f"Extracted clean path: {actual_path} from input: {input_path_str}")

    # Return in the same format as input
    return Path(actual_path) if is_path_object else actual_path


def parse_input(input_path: str | Path) -> List[Path]:
    """
    Parse input path and return list of files to analyze (KEPT)
    """
    # Get clean path without arguments, and ensure it's a Path object
    clean_path_str = extract_clean_path(input_path)
    input_path = Path(clean_path_str)  # Convert to Path object for processing

    files_to_analyze = []

    # Case 1: Input is a file containing paths
    if input_path.suffix == ".txt":
        try:
            with open(input_path, "r") as f:
                paths = [line.strip() for line in f if line.strip()]
                for path in paths:
                    p = Path(path)
                    if p.is_file():
                        files_to_analyze.append(p)
                    elif p.is_dir():
                        files_to_analyze.extend(f for f in p.rglob("*") if f.is_file())
        except Exception as e:
            logger.exception(f"Error reading paths file: {str(e)}")
            return []

    # Case 2: Input is a single file
    elif input_path.is_file():
        files_to_analyze.append(input_path)

    # Case 3: Input is a directory
    elif input_path.is_dir():
        files_to_analyze.extend(f for f in input_path.rglob("*") if f.is_file())

    else:
        logger.error(f"Invalid input path: {input_path}")
        return []

    return files_to_analyze


def sanitize_name(string: str) -> str:
    """
    Sanitize string for file name creation (KEPT)
    """
    # Get the last part after the last slash (if any)
    base_name = string.split("/")[-1]
    return re.sub(r"[^a-zA-Z0-9]", "_", base_name)


def display_logo():
    """
    Display the enhanced OASIS logo (ENHANCED)
    """
    logo = """
     .d88b.    db    .d8888.  _\\\\|//_ .d8888. 
    .8P  Y8.  d88b   88'  YP    \\\\//  88'  YP 
    88    88 d8'`8b  `8bo.       ||     `8bo.   
    88    88 88ooo88   `Y8b.     ||       `Y8b. 
    `8b  d8' 88~~~88 db   8D    /||\\   db   8D 
     `Y88P'  YP  YP  `8888Y' __/_||_\\_ `8888Y' 

╔════════════════════════════════════════════════╗
║ OASIS v2.0 - Enhanced Security Intelligence   ║
║ 🤝 A2A Agents + 🔧 MCP Tools Integration      ║
╚════════════════════════════════════════════════╝
"""
    logger.info(logo)


def calculate_similarity(embedding1: List[float], embedding2: List[float]) -> float:
    """
    Calculate cosine similarity between two embeddings (KEPT)
    """
    # Convert to numpy arrays for efficient computation
    vec1 = np.array(embedding1)
    vec2 = np.array(embedding2)

    # Calculate cosine similarity
    dot_product = np.dot(vec1, vec2)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)

    if norm1 == 0 or norm2 == 0:
        return 0.0

    return float(dot_product / (norm1 * norm2))


def open_file(file_path: str) -> str:
    """
    Open a file and return its content (KEPT)
    """
    # Try different encodings
    encodings = ["utf-8", "latin-1", "cp1252", "iso-8859-1"]
    content = None

    errors = []
    for encoding in encodings:
        try:
            with open(file_path, "r", encoding=encoding) as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            errors.append(f"Failed to decode with {encoding}")
            continue
        except Exception as e:
            error_msg = f"Error reading {file_path} with {encoding}: {e.__class__.__name__}: {str(e)}"
            logger.exception(error_msg)
            errors.append(error_msg)
            continue

    if content is None:
        error_details = "; ".join(errors)
        logger.error(
            f"Failed to read {file_path}: Tried encodings {', '.join(encodings)}. Errors: {error_details}"
        )
        return None

    return content


def get_vulnerability_mapping() -> Dict[str, Dict[str, any]]:
    """
    Return the vulnerability mapping (KEPT)
    """
    return VULNERABILITY_MAPPING


def generate_timestamp(for_file: bool = False) -> str:
    """
    Generate a timestamp (KEPT)
    """
    if for_file:
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    else:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_iso_date(date_string):
    """
    Parse ISO format date string with error handling (KEPT)
    """
    if not date_string:
        return None

    try:
        # Handle 'Z' UTC indicator in ISO format
        if date_string.endswith("Z"):
            date_string = date_string.replace("Z", "+00:00")

        # Parse ISO format date string
        return datetime.fromisoformat(date_string)
    except (ValueError, TypeError) as e:
        print(f"Error parsing date '{date_string}': {e}")
        return None


def parse_report_date(date_string):
    """
    Parse report date string with error handling (KEPT)
    """
    if not date_string:
        return None

    try:
        # Parse date in format used by reports
        dt = datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
        # Add UTC timezone if not present
        if dt.tzinfo is None:
            from datetime import timezone

            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError) as e:
        print(f"Error parsing report date '{date_string}': {e}")
        return None


def create_cache_dir(input_path: str | Path) -> Path:
    """
    Create a cache directory for the input path (KEPT)
    """
    # Create base cache directory
    input_path = Path(input_path).resolve()  # Get absolute path
    base_cache_dir = input_path.parent / ".oasis_cache"
    base_cache_dir.mkdir(exist_ok=True)

    # Create project-specific cache directory using the final folder name
    project_name = sanitize_name(input_path.name)
    cache_dir = base_cache_dir / project_name
    cache_dir.mkdir(exist_ok=True)
    return cache_dir


# NEW: Agent-specific utility functions
def correlate_agent_findings(
    findings_by_agent: Dict[str, List[Dict]],
) -> Dict[str, Any]:
    """
    Correlate findings across multiple agents to identify complex vulnerabilities

    Args:
        findings_by_agent: Dictionary mapping agent types to their findings

    Returns:
        Dictionary containing correlation analysis
    """
    correlations = []
    file_agent_map = {}

    # Map files to agents that found issues
    for agent_type, findings in findings_by_agent.items():
        for finding in findings:
            file_path = finding.get("file_path", "")
            if file_path not in file_agent_map:
                file_agent_map[file_path] = []

            file_agent_map[file_path].append(
                {
                    "agent": agent_type,
                    "finding": finding,
                    "confidence": finding.get("confidence", 0.5),
                }
            )

    # Identify multi-agent correlations
    for file_path, agent_findings in file_agent_map.items():
        if len(agent_findings) > 1:
            correlation = {
                "file_path": file_path,
                "agents_involved": [af["agent"] for af in agent_findings],
                "combined_confidence": _calculate_combined_confidence(agent_findings),
                "potential_attack_chains": _generate_attack_chains(agent_findings),
                "risk_amplification": _calculate_risk_amplification(agent_findings),
            }
            correlations.append(correlation)

    return {
        "correlations": correlations,
        "multi_agent_files": len(correlations),
        "total_files_analyzed": len(file_agent_map),
    }


def _calculate_combined_confidence(agent_findings: List[Dict]) -> float:
    """Calculate combined confidence from multiple agent findings"""
    confidences = [af["confidence"] for af in agent_findings]

    # Use weighted average with diminishing returns for additional agents
    if not confidences:
        return 0.0

    base_confidence = max(confidences)  # Start with highest confidence
    additional_confidence = sum(confidences) - base_confidence

    # Diminishing returns: each additional agent adds less confidence
    combined = base_confidence + (additional_confidence * 0.3)

    return min(combined, 1.0)  # Cap at 1.0


def _generate_attack_chains(agent_findings: List[Dict]) -> List[str]:
    """Generate potential attack chains from correlated findings"""
    agents = [af["agent"] for af in agent_findings]

    # Define known attack chain patterns
    attack_patterns = {
        ("auth", "sqli"): "Authentication bypass → SQL injection → Data exfiltration",
        ("xss", "auth"): "XSS exploitation → Session hijacking → Account takeover",
        (
            "config",
            "crypto",
        ): "Configuration exposure → Weak cryptography → Data breach",
        (
            "sqli",
            "config",
        ): "SQL injection → Configuration disclosure → Privilege escalation",
        (
            "crypto",
            "config",
        ): "Weak encryption → Configuration access → System compromise",
    }

    chains = []

    # Check for known patterns
    for pattern, description in attack_patterns.items():
        if all(agent in agents for agent in pattern):
            chains.append(description)

    # Generate generic chain if no specific pattern
    if not chains and len(agents) > 1:
        chains.append(f"Multi-vector attack: {' + '.join(agents)} → System compromise")

    return chains


def _calculate_risk_amplification(agent_findings: List[Dict]) -> float:
    """Calculate risk amplification factor for multiple vulnerabilities"""
    base_risk = max(af["confidence"] for af in agent_findings)

    # Risk amplification: multiple vulnerabilities increase overall risk
    amplification_factor = (
        1.0 + (len(agent_findings) - 1) * 0.25
    )  # 25% increase per additional vuln

    return min(base_risk * amplification_factor, 1.0)


def build_attack_chains(related_findings: List[Dict]) -> List[str]:
    """
    Build attack chains from related security findings

    Args:
        related_findings: List of related vulnerability findings

    Returns:
        List of attack chain descriptions
    """
    if len(related_findings) < 2:
        return []

    chains = []
    vulnerability_types = [f.get("vulnerability_type", "") for f in related_findings]

    # Build step-by-step attack chains
    if "authentication" in str(vulnerability_types).lower():
        if "sql" in str(vulnerability_types).lower():
            chains.append(
                "1. Bypass authentication → 2. Exploit SQL injection → 3. Extract sensitive data"
            )
        elif "xss" in str(vulnerability_types).lower():
            chains.append(
                "1. Exploit XSS vulnerability → 2. Steal session tokens → 3. Bypass authentication"
            )

    if "configuration" in str(vulnerability_types).lower():
        if "crypto" in str(vulnerability_types).lower():
            chains.append(
                "1. Access misconfigured system → 2. Exploit weak cryptography → 3. Decrypt sensitive data"
            )

    # Generic chain for any combination
    if not chains:
        chain_steps = [f"Exploit {vt}" for vt in vulnerability_types[:3]]
        chains.append(" → ".join(chain_steps) + " → System compromise")
    return chains


def generate_hash(content: str) -> str:
    """
    Generate a SHA-256 hash of the given content (KEPT)
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(content.encode("utf-8"))
    return sha256_hash.hexdigest()


def save_json(data: Any, file_path: str | Path) -> None:
    """
    Save data to a JSON file (KEPT)
    """
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=4)
    logger.debug(f"Saved JSON data to {file_path}")


def load_json(file_path: str | Path) -> Any:
    """
    Load data from a JSON file (KEPT)
    """
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    logger.debug(f"Loaded JSON data from {file_path}")
    return data


def get_file_extension(file_path: str | Path) -> str:
    """
    Get the file extension from a file path (KEPT)
    """
    if isinstance(file_path, Path):
        return file_path.suffix
    else:
        return Path(file_path).suffix


def get_file_name(file_path: str | Path) -> str:
    """
    Get the file name from a file path (KEPT)
    """
    if isinstance(file_path, Path):
        return file_path.name
    else:
        return Path(file_path).name


def get_file_size(file_path: str | Path) -> int:
    """
    Get the file size in bytes (KEPT)
    """
    if isinstance(file_path, Path):
        return file_path.stat().st_size
    else:
        return Path(file_path).stat().st_size


def get_file_modification_time(file_path: str | Path) -> datetime:
    """
    Get the file modification time (KEPT)
    """
    if isinstance(file_path, Path):
        return datetime.fromtimestamp(file_path.stat().st_mtime)
    else:
        return datetime.fromtimestamp(Path(file_path).stat().st_mtime)


def get_file_creation_time(file_path: str | Path) -> datetime:
    """
    Get the file creation time (KEPT)
    """
    if isinstance(file_path, Path):
        return datetime.fromtimestamp(file_path.stat().st_ctime)
    else:
        return datetime.fromtimestamp(Path(file_path).stat().st_ctime)


def get_file_access_time(file_path: str | Path) -> datetime:
    """
    Get the file access time (KEPT)
    """
    if isinstance(file_path, Path):
        return datetime.fromtimestamp(file_path.stat().st_atime)
    else:
        return datetime.fromtimestamp(Path(file_path).stat().st_atime)


def get_file_hash(file_path: str | Path) -> str:
    """
    Get the SHA-256 hash of a file (KEPT)
    """
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
