"""
OASIS v2.0 - Enhanced with A2A Agents and MCP Tools
Ollama Automated Security Intelligence Scanner
"""

from .core import main, OasisOrchestrator

__version__ = "2.0.0"
__author__ = "OASIS Team"
__description__ = "Enhanced Ollama Automated Security Intelligence Scanner with A2A Agents and MCP Tools"

# Main exports
__all__ = ["main", "OasisOrchestrator", "__version__"]


# Feature availability checks
def check_a2a_availability():
    """Check if A2A features are available"""
    try:
        import python_a2a

        return True
    except ImportError:
        return False


def check_mcp_availability():
    """Check if MCP features are available"""
    try:
        import fastmcp

        return True
    except ImportError:
        return False


# Feature flags
A2A_AVAILABLE = check_a2a_availability()
MCP_AVAILABLE = check_mcp_availability()

# Show feature availability on import
if __name__ != "__main__":
    if not A2A_AVAILABLE:
        print("⚠️  A2A features not available - install with: pip install python-a2a")
    if not MCP_AVAILABLE:
        print("⚠️  MCP features not available - install with: pip install fastmcp")
