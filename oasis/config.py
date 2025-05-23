"""
Enhanced Configuration constants for OASIS with A2A and MCP support
"""

from enum import Enum
import os
from typing import Set, Dict, Any
from pathlib import Path

# Load environment variables
from dotenv import load_dotenv

load_dotenv()

# Analysis version (increment when analysis behavior changes)
ANALYSIS_VERSION = "2.0"  # Updated for A2A + MCP integration

# Default args values (enhanced)
DEFAULT_ARGS = {
    "THRESHOLD": 0.5,
    "CHUNK_SIZE": "auto-detected",
    "VULNS": "all",
    "OUTPUT_FORMAT": "all",
    "ANALYSIS_TYPE": "standard",
    "EMBEDDING_ANALYSIS_TYPE": "file",
    "CACHE_DAYS": 7,
    "EMBED_MODEL": "nomic-embed-text:latest",
    "SCAN_MODEL": None,
    "MULTI_AGENT": os.getenv("DEFAULT_MULTI_AGENT", "false").lower() == "true",
    "AGENT_COLLABORATION": os.getenv("AGENT_COLLABORATION", "true").lower() == "true",
    "MCP_TOOLS_ENABLED": os.getenv("MCP_TOOLS_ENABLED", "true").lower() == "true",
}

# A2A Agent Configuration
AGENT_CONFIG = {
    "sqli": {
        "name": "SQL Injection Expert",
        "model": os.getenv("SQLI_AGENT_MODEL", "codellama:13b"),
        "port": int(os.getenv("A2A_BASE_PORT", 5000)) + 1,
        "description": "Specialized in SQL injection vulnerabilities and database security",
        "skills": ["SQL Injection Detection", "Database Security", "Query Analysis"],
    },
    "xss": {
        "name": "XSS Security Expert",
        "model": os.getenv("XSS_AGENT_MODEL", "gemma:7b"),
        "port": int(os.getenv("A2A_BASE_PORT", 5000)) + 2,
        "description": "Expert in Cross-Site Scripting vulnerabilities and web security",
        "skills": ["XSS Detection", "DOM Analysis", "Content Security Policy"],
    },
    "auth": {
        "name": "Authentication Expert",
        "model": os.getenv("AUTH_AGENT_MODEL", "mistral"),
        "port": int(os.getenv("A2A_BASE_PORT", 5000)) + 3,
        "description": "Specialized in authentication and authorization vulnerabilities",
        "skills": ["Auth Bypass", "Session Management", "Access Control"],
    },
    "crypto": {
        "name": "Cryptography Expert",
        "model": os.getenv("CRYPTO_AGENT_MODEL", "llama2:13b"),
        "port": int(os.getenv("A2A_BASE_PORT", 5000)) + 4,
        "description": "Expert in cryptographic vulnerabilities and secure implementations",
        "skills": ["Weak Encryption", "Key Management", "Random Number Generation"],
    },
    "config": {
        "name": "Configuration Expert",
        "model": os.getenv("CONFIG_AGENT_MODEL", "gemma:2b"),
        "port": int(os.getenv("A2A_BASE_PORT", 5000)) + 5,
        "description": "Specialized in security misconfigurations and hardening",
        "skills": ["Security Hardening", "Default Configurations", "Exposure Analysis"],
    },
}

# MCP Tools Configuration
MCP_CONFIG = {
    "base_port": int(os.getenv("MCP_BASE_PORT", 7000)),
    "enabled": os.getenv("MCP_TOOLS_ENABLED", "true").lower() == "true",
    "cache_days": int(os.getenv("MCP_CACHE_DAYS", 1)),
    "tools": {
        "nvd": {
            "name": "NVD Vulnerability Database",
            "description": "Query NIST National Vulnerability Database",
            "enabled": True,
            "api_key_env": "NVD_API_KEY",
            "port_offset": 1,
        },
        "semgrep": {
            "name": "Semgrep Static Analysis",
            "description": "Static analysis tool for security patterns",
            "enabled": True,
            "api_key_env": "SEMGREP_API_KEY",
            "port_offset": 2,
        },
        "git_analyzer": {
            "name": "Git History Analyzer",
            "description": "Analyze git history for security patterns",
            "enabled": True,
            "port_offset": 3,
        },
        "dependency_scanner": {
            "name": "Dependency Scanner",
            "description": "Scan dependencies for known vulnerabilities",
            "enabled": True,
            "port_offset": 4,
        },
    },
}

# Agent Collaboration Rules
AGENT_COLLABORATION_RULES = {
    "sqli": [
        "auth",
        "input",
    ],  # SQL injection often related to auth bypass and input validation
    "xss": ["input", "config"],  # XSS related to input validation and CSP configuration
    "auth": [
        "session",
        "config",
    ],  # Auth issues often relate to session and configuration
    "crypto": [
        "secrets",
        "config",
    ],  # Crypto issues relate to secrets and configuration
    "config": ["auth", "crypto"],  # Configuration affects auth and crypto
}

# Agent Priority (for resource allocation)
AGENT_PRIORITY = {
    "sqli": 1,  # High priority - very common and dangerous
    "xss": 1,  # High priority - very common
    "auth": 2,  # Medium-high priority
    "crypto": 2,  # Medium-high priority
    "config": 3,  # Medium priority
}

# Existing configurations (keep all from original)
SUPPORTED_EXTENSIONS: Set[str] = {
    # Web Development
    "html",
    "htm",
    "css",
    "js",
    "jsx",
    "ts",
    "tsx",
    "asp",
    "aspx",
    "jsp",
    "vue",
    "svelte",
    # Programming Languages
    "py",
    "pyc",
    "pyd",
    "pyo",
    "pyw",  # Python
    "java",
    "class",
    "jar",  # Java
    "cpp",
    "c",
    "cc",
    "cxx",
    "h",
    "hpp",
    "hxx",  # C/C++
    "cs",  # C#
    "go",  # Go
    "rs",  # Rust
    "rb",
    "rbw",  # Ruby
    "swift",  # Swift
    "kt",
    "kts",  # Kotlin
    "scala",  # Scala
    "pl",
    "pm",  # Perl
    "php",
    "phtml",
    "php3",
    "php4",
    "php5",
    "phps",  # PHP
    # Mobile Development
    "m",
    "mm",  # Objective-C
    "dart",  # Flutter
    # Shell Scripts
    "sh",
    "bash",
    "csh",
    "tcsh",
    "zsh",
    "fish",
    "bat",
    "cmd",
    "ps1",  # Windows Scripts
    # Database
    "sql",
    "mysql",
    "pgsql",
    "sqlite",
    # Configuration & Data
    "xml",
    "yaml",
    "yml",
    "json",
    "ini",
    "conf",
    "config",
    "toml",
    "env",
    # System Programming
    "asm",
    "s",  # Assembly
    "f",
    "for",
    "f90",
    "f95",  # Fortran
    # Other Languages
    "lua",  # Lua
    "r",
    "R",  # R
    "matlab",  # MATLAB
    "groovy",  # Groovy
    "erl",  # Erlang
    "ex",
    "exs",  # Elixir
    "hs",  # Haskell
    "lisp",
    "lsp",
    "cl",  # Lisp
    "clj",
    "cljs",  # Clojure
    # Smart Contracts
    "sol",  # Solidity
    # Template Files
    "tpl",
    "tmpl",
    "template",
    # Documentation
    "md",
    "rst",
    "adoc",  # Documentation files
    # Build & Package
    "gradle",
    "maven",
    "rake",
    "gemspec",
    "cargo",
    "cabal",
    "cmake",
    "make",
    # Container & Infrastructure
    "dockerfile",
    "containerfile",
    "tf",
    "tfvars",  # Terraform
    # Version Control
    "gitignore",
    "gitattributes",
    "gitmodules",
}

# Chunk configuration
MAX_CHUNK_SIZE = 2048
CHUNK_ANALYZE_TIMEOUT = 120
EMBEDDING_THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

# Ollama API endpoint
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434")

# Models configuration (keep existing)
EXCLUDED_MODELS = ["embed", "instructor", "text-", "minilm", "e5-", "cline"]

DEFAULT_MODELS = [
    "llama2",
    "llama2:13b",
    "codellama",
    "codellama:13b",
    "gemma:2b",
    "gemma:7b",
    "mistral",
    "mixtral",
]

# Keywords lists for logging emojis (keep existing)
KEYWORD_LISTS = {
    "INSTALL_WORDS": ["installing", "download", "pulling", "fetching"],
    "START_WORDS": ["starting", "beginning", "beginning", "starting"],
    "FINISH_WORDS": ["finished", "completed", "done", "finished"],
    "SUCCESS_WORDS": ["success", "done"],
    "FAIL_WORDS": ["failed", "error", "crash", "exception"],
    "STOPPED_WORDS": ["interrupted", "stopped"],
    "ANALYSIS_WORDS": [
        "analyzing",
        "analysis",
        "scanning",
        "checking",
        "inspecting",
        "examining",
        "found",
        "querying",
    ],
    "GENERATION_WORDS": ["generating", "creating", "building", "processing"],
    "REPORT_WORDS": ["report"],
    "MODEL_WORDS": ["model", "ai", "llm"],
    "CACHE_WORDS": ["cache", "stored", "saving"],
    "SAVE_WORDS": ["saved", "written", "exported"],
    "LOAD_WORDS": ["loading", "reading", "importing", "loaded"],
    "DELETE_WORDS": ["deleting", "removing", "deleted"],
    "STATISTICS_WORDS": ["statistics"],
    "TOP_WORDS": ["top", "highest", "most", "better"],
    "VULNERABILITY_WORDS": ["vulnerability", "vulnerabilities"],
    "AGENT_WORDS": ["agent", "agents", "collaboration", "coordinating"],  # New
}

# Model emojis mapping (keep existing + new)
MODEL_EMOJIS = {
    # General models
    "deepseek": "🧠 ",
    "llama": "🦙 ",
    "gemma": "💎 ",
    "mistral": "💨 ",
    "mixtral": "🌪️ ",
    "qwen": "🐧 ",
    "phi": "φ ",
    "yi": "🌐 ",
    # Code models
    "codestral": "🌠 ",
    "starcoder": "⭐ ",
    # Interaction models
    "instruct": "💬 ",
    "chat": "💬 ",
    # Cybersecurity models
    "cybersecurity": "🛡️  ",
    "whiterabbit": "🐇 ",
    "sast": "🛡️  ",
    # Other models
    "research": "🔬 ",
    "openhermes": "🌟 ",
    "solar": "☀️ ",
    "neural-chat": "🧠💬 ",
    "nous": "👥 ",
    "default": "🤖 ",
    # A2A Agents
    "agent": "🤝 ",
    "sqli_agent": "💉 ",
    "xss_agent": "🔀 ",
    "auth_agent": "🔑 ",
    "crypto_agent": "🔒 ",
    "config_agent": "⚙️ ",
}

# Vulnerability emojis (keep existing)
VULN_EMOJIS = {
    # Injection vulnerabilities
    "sql_injection": "💉 ",
    "remote_code_execution": "🔥 ",
    "cross-site_scripting_(xss)": "🔀 ",
    "xml_external_entity_injection": "📄 ",
    "server-side_request_forgery": "🔄 ",
    "command_injection": "⌨️ ",
    "code_injection": "📝 ",
    # Authentication and Authorization
    "authentication_issues": "🔑 ",
    "cross-site_request_forgery": "↔️ ",
    "insecure_direct_object_reference": "🔢 ",
    "session_management_issues": "🍪 ",
    "auth_bypass": "🔓 ",
    "missing_access_control": "🚫 ",
    "privilege_escalation": "🔝 ",
    # Data Security
    "sensitive_data_exposure": "🕵️ ",
    "hardcoded_secrets": "🔐 ",
    "sensitive_data_logging": "📝 ",
    "information_disclosure": "📢 ",
    # File System
    "path_traversal": "📂 ",
    "lfi": "📁 ",
    "rfi": "📡 ",
    # Configuration
    "security_misconfiguration": "⚙️ ",
    "outdated_component": "⌛ ",
    "open_redirect": "↪️ ",
    # Input Validation
    "insufficient_input_validation": "⚠️ ",
    "crlf": "↩️ ",
    # Cryptographic
    "insecure_cryptographic_usage": "🔒 ",
    "weak_crypto": "🔒 ",
    "cert_validation": "📜 ",
    "insecure_random": "🎲 ",
    # Deserialization
    "insecure_deserialization": "📦 ",
    "unsafe_yaml": "📋 ",
    "pickle_issues": "🥒 ",
    # Performance and DoS
    "dos": "💥 ",
    "race_condition": "🏁 ",
    "buffer_overflow": "📊 ",
    "integer_overflow": "🔢 ",
    "memory_leak": "💧 ",
    # Other
    "mitm": "🕸️ ",
    "business_logic": "💼 ",
    "weak_credentials": "🔏 ",
    # Risk Categories
    "high_risk": "🚨 ",
    "medium_risk": "⚠️ ",
    "low_risk": "📌 ",
    "info": "ℹ️ ",
    "unclassified": "❓ ",
}

# Vulnerability mappings (keep existing - this is core OASIS value)
VULNERABILITY_MAPPING = {
    "sqli": {
        "name": "SQL Injection",
        "description": "Code that might allow an attacker to inject SQL statements",
        "patterns": [
            "string concatenation in SQL query",
            "user input directly in query",
            "lack of parameterized queries",
            "dynamic SQL generation",
            "raw input in database operations",
            "query parameters from request",
            "execute raw SQL",
            "format string in SQL",
            "SQL query string interpolation",
            "unsafe database.execute",
            "LIKE operator with user input",
            "ORDER BY with unsanitized input",
            "MySQL query concatenation",
            "PostgreSQL dynamic query",
            "SQLite direct parameter",
            "UNION injection vulnerability",
            "database.query with variable",
            "SQL WHERE clause with input",
            "executeQuery with variable",
            "createStatement().execute",
            "executeSql with template",
        ],
        "impact": "Can lead to data theft, data loss, authentication bypass, or complete system compromise",
        "mitigation": "Use parameterized queries or prepared statements, apply input validation, and use ORMs correctly",
        "agent": "sqli",  # New: map to specialized agent
    },
    "xss": {
        "name": "Cross-Site Scripting (XSS)",
        "description": "Vulnerabilities that allow attackers to inject client-side scripts",
        "patterns": [
            "unescaped output to HTML",
            "innerHTML with user input",
            "document.write with variables",
            "eval with user content",
            "rendering content without sanitization",
            "dangerous DOM operations",
            "raw user data in templates",
            "bypass content sanitization",
            "script injection vulnerability",
            "missing HTML encoding",
            "dangerouslySetInnerHTML",
            "template literals with user data",
            "attribute injection vulnerability",
            "data-* attribute with user input",
            "event handler assignment",
            "href with javascript: protocol",
            "DOM manipulation with createElement",
            "React props sanitization missing",
            "Vue v-html directive with data",
            "Angular [innerHTML] binding",
            "svg onload attribute",
            "CSS expression with user input",
            "postMessage without origin check",
        ],
        "impact": "Can lead to session hijacking, credential theft, or delivery of malware to users",
        "mitigation": "Apply context-aware output encoding, use Content-Security-Policy, validate and sanitize all inputs",
        "agent": "xss",
    },
    "input": {
        "name": "Insufficient Input Validation",
        "description": "Vulnerabilities due to inadequate validation of user inputs",
        "patterns": [
            "input validation missing",
            "unvalidated user input",
            "unsafe type casting",
            "buffer overflow risk",
            "command injection risk",
            "path traversal vulnerability",
            "unsafe deserialization",
            "user-controlled parameter",
            "direct use of request parameters",
            "no input sanitization",
            "raw form data processing",
            "missing input boundary checks",
            "format string vulnerability",
            "input whitelist missing",
            "untrusted data handling",
            "user input without validation",
            "integer overflow vulnerability",
            "type confusion vulnerability",
            "unchecked array bounds",
            "memory corruption risk",
            "lack of input length checks",
            "improper input canonicalization",
            "regex without timeout",
            "client-side validation only",
            "header injection vulnerability",
            "content-type validation missing",
            "file upload filtering bypass",
            "numeric input without bounds check",
        ],
        "impact": "Can lead to various attacks including injections, buffer overflows, and logical flaws",
        "mitigation": "Implement strict input validation, use type checking, and sanitize all user inputs",
        "agent": "sqli",  # Input validation often relates to SQL injection
    },
    "data": {
        "name": "Sensitive Data Exposure",
        "description": "Instances where sensitive information is not properly protected",
        "patterns": [
            "sensitive data exposure",
            "plaintext credentials",
            "hardcoded secrets",
            "API keys in code",
            "unencrypted sensitive data",
            "information disclosure",
            "data leakage",
            "sensitive data in client-side code",
            "personal data mishandling",
            "insufficient data protection",
            "cleartext transmission of data",
            "missing data encryption",
            "PII exposure risk",
            "credentials in config files",
            "insufficient access controls",
            "sensitive data caching",
            "insecure data storage",
            "PCI data mishandling",
            "health information exposure",
            "social security numbers unprotected",
            "email addresses unsecured",
            "financial data in plaintext",
            "credentials in URL parameters",
            "debug information disclosure",
            "internal IP disclosure",
            "server version exposure",
            "technology stack disclosure",
            "database connection string exposure",
            "sensitive data in error messages",
            "sensitive data in HTML comments",
        ],
        "impact": "Exposure of confidential information, credentials, or personal data leading to unauthorized access",
        "mitigation": "Encrypt sensitive data, use secure storage solutions, and avoid hardcoding secrets",
        "agent": "crypto",  # Data protection relates to cryptography
    },
    "session": {
        "name": "Session Management Issues",
        "description": "Problems with how user sessions are created, maintained, and terminated",
        "patterns": [
            "session fixation",
            "insecure session handling",
            "session hijacking risk",
            "missing session timeout",
            "weak session ID generation",
            "session token exposure",
            "cookie security missing",
            "insufficient session expiration",
            "missing secure flag",
            "missing httpOnly flag",
            "session data in URL",
            "no session validation",
            "predictable session tokens",
            "persistent session without verification",
            "client-side session storage",
            "missing SameSite attribute",
            "cross-domain cookie sharing",
            "CSRF token missing",
            "insecure JWT handling",
            "JWT without expiration",
            "JWT signature validation missing",
            "session reuse vulnerability",
            "lack of session regeneration",
            "concurrent session control missing",
            "session token in logs",
            "insecure cookie attributes",
            "cookie without path restriction",
            "OAuth state parameter missing",
            "cookie prefixing missing",
            "session token in referrer header",
        ],
        "impact": "Account takeover, session hijacking, and unauthorized access to user accounts",
        "mitigation": "Implement secure session handling, use proper timeout settings, and protect session tokens",
        "agent": "auth",  # Sessions relate to authentication
    },
    "config": {
        "name": "Security Misconfiguration",
        "description": "Insecure configuration settings that can expose vulnerabilities",
        "patterns": [
            "security misconfiguration",
            "default credentials",
            "debug mode enabled",
            "insecure permissions",
            "unnecessary features enabled",
            "missing security headers",
            "verbose error messages",
            "directory listing enabled",
            "default accounts enabled",
            "unnecessary services running",
            "insecure HTTP methods allowed",
            "default configuration unchanged",
            "development settings in production",
            "outdated software components",
            "missing CORS protections",
            "insecure TLS configuration",
            "dangerous HTTP headers",
            "default error pages",
            "information disclosure in responses",
            "HTTP header misconfiguration",
            "X-Frame-Options missing",
            "Content-Security-Policy missing",
            "missing X-Content-Type-Options",
            "insecure deserialization settings",
            "missing rate limiting",
            "HSTS not implemented",
            "unnecessary HTTP methods enabled",
            "open cloud storage buckets",
            "insecure file permissions",
            "database exposed to internet",
            "unauthenticated API endpoints",
            "CORS wildcard origin",
            "weak password policy configuration",
        ],
        "impact": "Information disclosure, unauthorized access, or system compromise through exposed functionality",
        "mitigation": "Use secure configuration templates, disable unnecessary features, and implement proper security headers",
        "agent": "config",
    },
    "logging": {
        "name": "Sensitive Data Logging",
        "description": "Exposure of sensitive information through application logs",
        "patterns": [
            "sensitive data in logs",
            "password logging",
            "PII in logs",
            "credit card logging",
            "token logging",
            "unsafe error logging",
            "debug logging in production",
            "authentication data in logs",
            "session identifiers logged",
            "biometric data logging",
            "health information logged",
            "authorization tokens in logs",
            "secret keys in log output",
            "API keys in debug logs",
            "query parameters logged",
            "financial data in logs",
            "unmasked credentials in traces",
            "personal addresses logged",
            "log files with excessive permissions",
            "log data without anonymization",
        ],
        "impact": "Disclosure of sensitive user data, credentials, or security tokens via log files",
        "mitigation": "Filter sensitive data from logs, use proper log levels, and implement secure logging practices",
        "agent": "config",  # Logging configuration relates to security configuration
    },
    "crypto": {
        "name": "Insecure Cryptographic Usage",
        "description": "Use of weak or deprecated cryptographic algorithms or practices",
        "patterns": [
            "weak encryption",
            "insecure random number generation",
            "weak hash algorithm",
            "MD5 usage",
            "SHA1 usage",
            "ECB mode encryption",
            "static initialization vector",
            "hardcoded encryption key",
            "insufficient key size",
            "broken cipher implementation",
            "predictable random generator",
            "insufficient entropy",
            "math.random for cryptography",
            "cryptographic key reuse",
            "non-cryptographic PRNG",
            "CBC without MAC",
            "missing key rotation",
            "RC4 cipher usage",
            "DES or 3DES usage",
            "RSA with weak padding",
            "incorrect certificate validation",
            "custom cryptographic algorithms",
            "use of broken cryptographic libraries",
            "hardcoded salt values",
        ],
        "impact": "Data compromise through cryptographic attacks, leading to confidentiality breaches",
        "mitigation": "Use modern encryption standards, secure key management, and proper cryptographic implementations",
        "agent": "crypto",
    },
    "rce": {
        "name": "Remote Code Execution",
        "description": "Vulnerabilities allowing execution of arbitrary code",
        "patterns": [
            "eval with user input",
            "exec function with variables",
            "system call with parameters",
            "deserialization of untrusted data",
            "child_process.exec",
            "os.system with variables",
            "subprocess module with user input",
            "template rendering with code execution",
            "shell command injection",
            "dynamic code evaluation",
            "unsafe reflection",
            "unsafe use of Runtime.exec",
            "popen in python",
            "ProcessBuilder in Java",
            "unsafe pickle loading",
            "yaml.load without safe flag",
            "json.loads with custom decoder",
            "unserialize in PHP",
            "eval in JavaScript",
            "Function constructor with input",
            "new Function with variable",
            "Groovy script execution",
            "template expression evaluation",
            "JSP expression injection",
            "code interpolation in string",
            "RCE through SSTI",
        ],
        "impact": "Complete system compromise, data theft, or service disruption",
        "mitigation": "Avoid dangerous functions, use allowlists for commands, validate and sanitize all inputs",
        "agent": "sqli",  # RCE often relates to injection attacks
    },
    "ssrf": {
        "name": "Server-Side Request Forgery",
        "description": "Vulnerabilities that allow attackers to induce the server to make requests",
        "patterns": [
            "URL fetching from user input",
            "request module with variable URL",
            "http client with dynamic endpoint",
            "webhook implementation",
            "remote file inclusion",
            "dynamic API requests",
            "URL parsing without validation",
            "fetch with user-provided URL",
            "unsafe URL redirection",
            "axios.get with variable",
            "curl functions with parameters",
            "http.get with user input",
            "urllib request with variable",
            "requests.post with dynamic URL",
            "guzzle client with user URL",
            "java URL connection with variable",
            "open redirect to internal hosts",
            "no URL schema validation",
            "IP address filtering bypass",
            "DNS rebinding vulnerability",
            "localhost access through SSRF",
            "cloud metadata API access",
            "internal service discovery",
            "webhook callback without validation",
            "file:// protocol allowed",
        ],
        "impact": "Access to internal services, data theft, or system compromise via internal network",
        "mitigation": "Validate and sanitize URLs, use allowlists, block private IPs and local hostnames",
        "agent": "config",  # SSRF often relates to configuration issues
    },
    "xxe": {
        "name": "XML External Entity Injection",
        "description": "Attacks against applications that parse XML input",
        "patterns": [
            "XML parser without entity restrictions",
            "XML processing without disabling DTD",
            "DocumentBuilder without secure settings",
            "SAX parser with default configuration",
            "XmlReader without proper settings",
            "SOAP message parsing",
            "external entity resolution enabled",
            "XXE vulnerability",
            "unsafe DOM parser",
            "XML libraries with dangerous defaults",
            "libxml2 without noent",
            "XMLReader with external entities",
            "XmlDocument with DTD processing",
            "insecure XML deserialization",
            "XML with custom entity handling",
            "JAXP without secure processing",
            "untrusted DOCX/XLSX processing",
            "SVG with embedded XXE",
            "RSS/Atom feed parsing vulnerability",
            "XML without schema validation",
            "XSLT processing with external entities",
            "XPath evaluation with untrusted XML",
            "XML bomb vulnerability",
            "XML parser with custom resolvers",
        ],
        "impact": "File disclosure, SSRF, denial of service, or data theft",
        "mitigation": "Disable DTDs and external entities in XML parsers, validate and sanitize inputs",
        "agent": "config",  # XXE relates to parser configuration
    },
    "pathtra": {
        "name": "Path Traversal",
        "description": "Vulnerabilities allowing access to files outside intended directory",
        "patterns": [
            "file operations with user input",
            "path concatenation without validation",
            "directory traversal vulnerability",
            "reading files with variable paths",
            "filepath not normalized",
            "unsafe file access",
            "open function with user parameters",
            "path manipulation risk",
            "file include vulnerability",
            "dot-dot-slash in paths",
            "missing filepath sanitization",
            "relative path navigation",
            "zip slip vulnerability",
            "path.join with user input",
            "file.readFile with dynamic path",
            "filesystem access without validation",
            "pathname not canonicalized",
            "archive extraction vulnerability",
            "symlink following risk",
            "file download with arbitrary path",
            "file.read without basedir check",
            "directory traversal with encoded slash",
            "file upload path manipulation",
            "path normalization bypass",
        ],
        "impact": "Unauthorized access to sensitive files, configuration data, or credentials",
        "mitigation": "Validate file paths, use allowlists, avoid using user input in file operations",
        "agent": "config",  # Path traversal often relates to configuration
    },
    "idor": {
        "name": "Insecure Direct Object Reference",
        "description": "Vulnerabilities exposing direct references to internal objects",
        "patterns": [
            "user ID in URL parameters",
            "missing access control checks",
            "direct object reference in request",
            "lack of authorization validation",
            "resource ID manipulation vulnerability",
            "authorization bypass risk",
            "direct reference to database records",
            "object level authorization missing",
            "unsafe parameter handling",
            "insufficient permission checking",
            "horizontal privilege escalation risk",
            "account enumeration vulnerability",
            "numeric identifier manipulation",
            "UUID predictability issue",
            "missing row-level security",
            "incremental reference exploitation",
            "API endpoint without ownership check",
            "user data access without verification",
            "mass assignment vulnerability",
            "blind IDOR vulnerability",
            "parameter tampering vulnerability",
            "access control matrix missing",
            "insufficient object property filtering",
            "user impersonation through reference",
            "cross-tenant data access",
        ],
        "impact": "Unauthorized access to data, privilege escalation, or data theft",
        "mitigation": "Implement proper access controls, use indirect references, validate user authorization",
        "agent": "auth",  # IDOR relates to authorization
    },
    "secrets": {
        "name": "Hardcoded Secrets",
        "description": "Sensitive data embedded directly in code",
        "patterns": [
            "hardcoded API key",
            "password in source code",
            "hardcoded credentials",
            "embedded secret",
            "private key in code",
            "OAuth token in variables",
            "secret key declaration",
            "cleartext password",
            "connection string with credentials",
            "JWT secret in code",
            "database password hardcoded",
            "encryption key in source",
            "AWS access key hardcoded",
            "Azure connection string in code",
            "Google API key in source",
            "Firebase credentials embedded",
            "SSH private key in repository",
            "certificate private key in code",
            "auth token hardcoded",
            "cryptographic seed hardcoded",
            "sensitive data in client-side code",
            "access token in JavaScript",
            "plaintext secrets in comments",
            "hardcoded test credentials",
            "sensitive values in configuration",
            "admin password default",
        ],
        "impact": "Credential exposure leading to unauthorized access or account compromise",
        "mitigation": "Use environment variables or secure vaults, avoid hardcoding any secrets",
        "agent": "crypto",  # Secrets relate to cryptography and key management
    },
    "auth": {
        "name": "Authentication Issues",
        "description": "Weaknesses in authentication mechanisms",
        "patterns": [
            "weak password requirements",
            "missing multi-factor authentication",
            "insufficient credential handling",
            "authentication bypass vulnerability",
            "insecure password storage",
            "broken authentication flow",
            "credential reset weakness",
            "session fixation vulnerability",
            "insecure remember me function",
            "inadequate brute force protection",
            "default or weak credentials",
            "password check timing attack",
            "lack of account lockout mechanism",
            "insecure password recovery",
            "missing CAPTCHA protection",
            "plain text password storage",
            "credential stuffing vulnerability",
            "password reuse vulnerability",
            "authorization header exposure",
            "OAuth redirect URI validation",
            "JWT without signature verification",
            "missing identity federation security",
            "insecure authentication protocol",
            "passwordless authentication risks",
            "knowledge-based authentication weakness",
            "shared account vulnerability",
        ],
        "impact": "Account compromise, privilege escalation, or unauthorized access",
        "mitigation": "Implement strong password policies, use MFA, secure session handling",
        "agent": "auth",
    },
    "csrf": {
        "name": "Cross-Site Request Forgery",
        "description": "Attacks that force users to execute unwanted actions",
        "patterns": [
            "missing CSRF token",
            "state-changing operation without protection",
            "form submission without CSRF verification",
            "cookie-only authentication",
            "missing SameSite attribute",
            "actions without user confirmation",
            "lack of request origin validation",
            "session handling vulnerability",
            "missing anti-forgery token",
            "insecure cross-domain requests",
            "automatic actions without validation",
            "CSRF token validation missing",
            "CSRF token leakage",
            "improper token binding to session",
            "token reuse vulnerability",
            "lack of double submit cookie",
            "GET request with state change",
            "failure to check referer header",
            "CORS misconfiguration for CSRF",
            "XHR without same-origin policy",
            "JSON request without CSRF protection",
            "cross-subdomain CSRF",
            "CORS preflight bypass",
            "CSRF via SVG or image upload",
            "browser cookie handling vulnerability",
        ],
        "impact": "Unauthorized actions performed on behalf of authenticated users",
        "mitigation": "Use CSRF tokens, SameSite cookies, and verify request origins",
        "agent": "auth",  # CSRF relates to authentication and session management
    },
}

# Prompt extension for vulnerability analysis (keep existing)
VULNERABILITY_PROMPT_EXTENSION = """
    When analyzing code for security vulnerabilities:
    1. Consider both direct and indirect vulnerabilities
    2. Check for proper input validation and sanitization
    3. Evaluate authentication and authorization mechanisms
    4. Look for insecure dependencies or API usage
    5. Identify potential logic flaws that could lead to security bypasses
    6. Consider the context and environment in which the code will run
    """

# Model and prompt for function extraction (keep existing)
EXTRACT_FUNCTIONS = {
    "MODEL": "gemma:2b",
    "ANALYSIS_TYPE": "file",
    "PROMPT": """
        For each function, return:
        1. The function name
        2. The exact start and end position (character index) in the source code
        3. The source code, it's mandatory to be base64 encoded
        4. The entire function body, it's mandatory to be base64 encoded
        5. The function parameters
        6. The function return type

        Format your response as JSON:
        {{
            "functions": [
                {{
                    "name": "function_name",
                    "start": 123,
                    "end": 456,
                    "source_code": "source_code",
                    "body": "function_body",
                    "parameters": ["param1", "param2"],
                    "return_type": "return_type"
                }}
            ]
        }}
        I want the Full List of Functions, not just a few.
        Do not have any other text, advice or thinking.
        """,
}

# Report configuration (keep existing + enhance)
REPORT = {
    "OUTPUT_FORMATS": ["pdf", "html", "md"],
    "OUTPUT_DIR": "security_reports",
    "BACKGROUND_COLOR": "#F5F2E9",
    "EXPLAIN_ANALYSIS": """
## About This Report
This security analysis report uses advanced multi-agent collaboration and embedding similarity to identify potential vulnerabilities in your codebase.

## Enhanced Multi-Agent Analysis
This version of OASIS uses specialized security agents that collaborate to provide deeper analysis:

- **SQL Injection Expert**: Specialized in database security vulnerabilities
- **XSS Security Expert**: Focused on client-side script injection attacks  
- **Authentication Expert**: Specialized in auth/session vulnerabilities
- **Cryptography Expert**: Focused on encryption and key management issues
- **Configuration Expert**: Specialized in security misconfigurations

## Agent Collaboration
Agents work together to identify complex attack chains and cross-domain vulnerabilities that single-model analysis might miss.

## External Tool Integration
Findings are enhanced with data from external security tools:
- **NVD Database**: Cross-reference with known CVEs
- **Semgrep Analysis**: Static analysis validation
- **Dependency Scanner**: Package vulnerability checking
- **Git History**: Context about when issues were introduced

## Understanding Code Embeddings
Code embeddings convert your code into numerical vectors capturing meaning and context:
- Embeddings understand the **purpose** of code, not just its syntax
- They can detect similar **concepts** across different programming styles
- They provide a **measure of relevance** through similarity scores (0.0-1.0)

## Working with Similarity Scores
- **High (≥0.6)**: Strong contextual match requiring immediate attention
- **Medium (0.4-0.6)**: Partial match worth investigating
- **Low (<0.4)**: Minimal contextual relationship, often false positives

<div class="page-break"></div>

## How to Use This Report
- **Start with high scores**: Focus first on findings above your threshold (default 0.5)
- **Review agent consensus**: Pay attention when multiple agents agree
- **Check external validations**: Look for CVE matches and tool confirmations
- **Use distribution insights**: The threshold analysis shows how vulnerabilities cluster
- **Consider context**: Some clean code may naturally resemble vulnerable patterns

## Optimizing Your Analysis
- Use `--multi-agent` flag to enable collaborative analysis
- Increase threshold (`--threshold 0.6`) when experiencing too many false positives
- Decrease threshold (`--threshold 0.3`) when conducting thorough security audits
- Run audit mode (`--audit`) to understand your codebase's embedding distribution
- Customize vulnerability types (`--vulns sqli,xss,rce`) to focus on specific risks
- Adjust chunk size (`--chunk-size 2048`) for more contextual analysis of larger functions

## Next Steps
- Review all high-risk findings immediately
- Schedule code reviews for medium-risk items
- Consider incorporating these checks into your CI/CD pipeline
- Use the executive summary to communicate risks to management
    """,
    "EXPLAIN_EXECUTIVE_SUMMARY": """
## Executive Summary
This report provides a high-level overview of security vulnerabilities detected through advanced multi-agent analysis.
    """,
}

# MCP Configuration File Path
MCP_CONFIG_FILE = Path(__file__).parent / "config.json"

# A2A Dependencies
A2A_DEPENDENCIES = ["python-a2a>=0.1.0", "fastmcp>=0.1.0", "python-dotenv>=1.0.0"]


class AnalysisMode(Enum):
    SCAN = "scan"
    DEEP = "deep"
    AGENT = "agent"  # New: A2A agent mode


class AnalysisType(Enum):
    STANDARD = "standard"
    ADAPTIVE = "adaptive"
    COLLABORATIVE = "collaborative"  # New: multi-agent collaborative
