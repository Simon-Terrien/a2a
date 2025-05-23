#!/usr/bin/env python3
"""
Enhanced Configuration Management for Code Review System
Provides centralized configuration with validation and environment support
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path
import logging

@dataclass
class ServerConfig:
    """Configuration for individual servers"""
    host: str = "localhost"
    port: Optional[int] = None
    auto_port: bool = True
    port_range_start: int = 5000
    port_range_size: int = 20

@dataclass
class AgentConfig:
    """Configuration for AI agents"""
    model: str = "gpt-4o"
    temperature: float = 0.1
    max_tokens: int = 1500
    timeout: int = 30
    retry_attempts: int = 3

@dataclass
class CacheConfig:
    """Configuration for caching"""
    enabled: bool = True
    type: str = "memory"  # memory, redis, file
    ttl: int = 3600  # Time to live in seconds
    max_size: int = 1000
    redis_url: Optional[str] = None

@dataclass
class DatabaseConfig:
    """Configuration for database"""
    enabled: bool = True
    type: str = "sqlite"  # sqlite, postgresql, mysql
    url: str = "sqlite:///code_review.db"
    pool_size: int = 5

@dataclass
class SecurityConfig:
    """Configuration for security"""
    authentication_enabled: bool = False
    jwt_secret: Optional[str] = None
    api_key_header: str = "X-API-Key"
    allowed_origins: list = field(default_factory=lambda: ["*"])

@dataclass
class LoggingConfig:
    """Configuration for logging"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file_enabled: bool = True
    file_path: str = "logs/code_review.log"
    rotation_size: str = "10MB"
    rotation_count: int = 5

@dataclass
class AnalysisConfig:
    """Configuration for analysis"""
    parallel_execution: bool = True
    max_workers: int = 3
    analysis_timeout: int = 60
    include_automated_scans: bool = True
    include_ai_analysis: bool = True

@dataclass
class CodeReviewConfig:
    """Main configuration class"""
    # Server configurations
    security_server: ServerConfig = field(default_factory=ServerConfig)
    performance_server: ServerConfig = field(default_factory=ServerConfig)
    style_server: ServerConfig = field(default_factory=ServerConfig)
    mcp_server: ServerConfig = field(default_factory=ServerConfig)
    
    # Component configurations
    agent: AgentConfig = field(default_factory=AgentConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    
    # Environment settings
    openai_api_key: Optional[str] = None
    environment: str = "development"  # development, production, testing
    debug: bool = False

class ConfigManager:
    """Manages configuration loading, validation, and environment overrides"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._find_config_file()
        self.config = self._load_config()
    
    def _find_config_file(self) -> str:
        """Find configuration file in standard locations"""
        possible_paths = [
            "config.yaml",
            "config.yml",
            os.path.expanduser("~/.code_review/config.yaml"),
            "/etc/code_review/config.yaml"
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                return path
        
        # Create default config if none found
        return self._create_default_config()
    
    def _create_default_config(self) -> str:
        """Create a default configuration file"""
        config_dir = Path("config")
        config_dir.mkdir(exist_ok=True)
        
        config_path = config_dir / "config.yaml"
        default_config = self._get_default_config()
        
        with open(config_path, 'w') as f:
            yaml.dump(default_config, f, default_flow_style=False)
        
        print(f"✅ Created default configuration at {config_path}")
        return str(config_path)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration as dictionary"""
        return {
            'security_server': {
                'port_range_start': 5000
            },
            'performance_server': {
                'port_range_start': 5100
            },
            'style_server': {
                'port_range_start': 5200
            },
            'mcp_server': {
                'port_range_start': 7000
            },
            'agent': {
                'model': 'gpt-4o',
                'temperature': 0.1,
                'max_tokens': 1500
            },
            'cache': {
                'enabled': True,
                'type': 'memory',
                'ttl': 3600
            },
            'database': {
                'enabled': True,
                'type': 'sqlite',
                'url': 'sqlite:///code_review.db'
            },
            'logging': {
                'level': 'INFO',
                'file_enabled': True,
                'file_path': 'logs/code_review.log'
            },
            'analysis': {
                'parallel_execution': True,
                'max_workers': 3,
                'analysis_timeout': 60
            }
        }
    
    def _load_config(self) -> CodeReviewConfig:
        """Load configuration from file and environment"""
        # Load from file
        config_data = {}
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as f:
                config_data = yaml.safe_load(f) or {}
        
        # Apply environment overrides
        config_data = self._apply_environment_overrides(config_data)
        
        # Create config object
        return self._create_config_object(config_data)
    
    def _apply_environment_overrides(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Apply environment variable overrides"""
        env_mappings = {
            'OPENAI_API_KEY': ['openai_api_key'],
            'CODE_REVIEW_DEBUG': ['debug'],
            'CODE_REVIEW_ENVIRONMENT': ['environment'],
            'CODE_REVIEW_LOG_LEVEL': ['logging', 'level'],
            'CODE_REVIEW_CACHE_TYPE': ['cache', 'type'],
            'CODE_REVIEW_DB_URL': ['database', 'url'],
            'CODE_REVIEW_MODEL': ['agent', 'model'],
            'CODE_REVIEW_TEMPERATURE': ['agent', 'temperature'],
        }
        
        for env_var, config_path in env_mappings.items():
            env_value = os.environ.get(env_var)
            if env_value is not None:
                self._set_nested_value(config_data, config_path, env_value)
        
        return config_data
    
    def _set_nested_value(self, data: Dict[str, Any], path: list, value: Any):
        """Set a nested value in a dictionary"""
        for key in path[:-1]:
            data = data.setdefault(key, {})
        
        # Convert string values to appropriate types
        final_key = path[-1]
        if final_key in ['debug'] and isinstance(value, str):
            value = value.lower() in ('true', '1', 'yes', 'on')
        elif final_key in ['temperature'] and isinstance(value, str):
            value = float(value)
        elif final_key in ['port', 'max_tokens', 'timeout', 'max_workers'] and isinstance(value, str):
            value = int(value)
        
        data[final_key] = value
    
    def _create_config_object(self, config_data: Dict[str, Any]) -> CodeReviewConfig:
        """Create CodeReviewConfig object from dictionary"""
        # Create nested config objects
        server_configs = {}
        for server_name in ['security_server', 'performance_server', 'style_server', 'mcp_server']:
            server_data = config_data.get(server_name, {})
            server_configs[server_name] = ServerConfig(**server_data)
        
        # Create other config objects
        component_configs = {}
        for component in ['agent', 'cache', 'database', 'security', 'logging', 'analysis']:
            component_data = config_data.get(component, {})
            component_class = {
                'agent': AgentConfig,
                'cache': CacheConfig,
                'database': DatabaseConfig,
                'security': SecurityConfig,
                'logging': LoggingConfig,
                'analysis': AnalysisConfig
            }[component]
            component_configs[component] = component_class(**component_data)
        
        # Create main config
        main_config_data = {
            key: value for key, value in config_data.items()
            if key not in ['security_server', 'performance_server', 'style_server', 'mcp_server',
                          'agent', 'cache', 'database', 'security', 'logging', 'analysis']
        }
        
        return CodeReviewConfig(
            **server_configs,
            **component_configs,
            **main_config_data
        )
    
    def validate_config(self) -> bool:
        """Validate configuration"""
        errors = []
        
        # Validate OpenAI API key
        if not self.config.openai_api_key:
            errors.append("OpenAI API key is required")
        
        # Validate model
        valid_models = ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo']
        if self.config.agent.model not in valid_models:
            errors.append(f"Invalid model: {self.config.agent.model}. Valid models: {valid_models}")
        
        # Validate temperature
        if not 0 <= self.config.agent.temperature <= 2:
            errors.append("Temperature must be between 0 and 2")
        
        # Validate cache type
        valid_cache_types = ['memory', 'redis', 'file']
        if self.config.cache.type not in valid_cache_types:
            errors.append(f"Invalid cache type: {self.config.cache.type}. Valid types: {valid_cache_types}")
        
        # Validate database type
        valid_db_types = ['sqlite', 'postgresql', 'mysql']
        if self.config.database.type not in valid_db_types:
            errors.append(f"Invalid database type: {self.config.database.type}. Valid types: {valid_db_types}")
        
        if errors:
            for error in errors:
                logging.error(f"Configuration error: {error}")
            return False
        
        return True
    
    def get_config(self) -> CodeReviewConfig:
        """Get the loaded configuration"""
        return self.config
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """Save current configuration to file"""
        save_path = config_path or self.config_path
        
        # Convert config object to dictionary
        config_dict = self._config_to_dict(self.config)
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        
        with open(save_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
        
        print(f"✅ Configuration saved to {save_path}")
    
    def _config_to_dict(self, config: CodeReviewConfig) -> Dict[str, Any]:
        """Convert configuration object to dictionary"""
        result = {}
        
        # Handle server configs
        for attr_name in ['security_server', 'performance_server', 'style_server', 'mcp_server']:
            server_config = getattr(config, attr_name)
            result[attr_name] = {
                'host': server_config.host,
                'port': server_config.port,
                'auto_port': server_config.auto_port,
                'port_range_start': server_config.port_range_start,
                'port_range_size': server_config.port_range_size
            }
        
        # Handle component configs
        component_attrs = ['agent', 'cache', 'database', 'security', 'logging', 'analysis']
        for attr_name in component_attrs:
            component_config = getattr(config, attr_name)
            result[attr_name] = {
                field.name: getattr(component_config, field.name)
                for field in component_config.__dataclass_fields__.values()
            }
        
        # Handle main config attributes
        main_attrs = ['openai_api_key', 'environment', 'debug']
        for attr_name in main_attrs:
            result[attr_name] = getattr(config, attr_name)
        
        return result

# Convenience functions
def load_config(config_path: Optional[str] = None) -> CodeReviewConfig:
    """Load configuration with validation"""
    manager = ConfigManager(config_path)
    
    if not manager.validate_config():
        raise ValueError("Configuration validation failed")
    
    return manager.get_config()

def create_default_config(output_path: str = "config/config.yaml") -> None:
    """Create a default configuration file"""
    manager = ConfigManager()
    manager.save_config(output_path)

# Example usage
if __name__ == "__main__":
    # Create default configuration
    create_default_config()
    
    # Load and validate configuration
    try:
        config = load_config()
        print("✅ Configuration loaded successfully")
        print(f"Model: {config.agent.model}")
        print(f"Cache enabled: {config.cache.enabled}")
        print(f"Database URL: {config.database.url}")
    except Exception as e:
        print(f"❌ Configuration error: {e}")