#!/usr/bin/env python3
"""
Enhanced Logging System for Code Review
Provides structured logging with rotation, context, and performance tracking
"""

import logging
import logging.handlers
import json
import time
import functools
import traceback
from typing import Dict, Any, Optional, Callable
from pathlib import Path
from datetime import datetime
import threading
from contextlib import contextmanager

class CodeReviewFormatter(logging.Formatter):
    """Custom formatter for code review system with JSON support"""
    
    def __init__(self, json_format: bool = False):
        self.json_format = json_format
        if json_format:
            super().__init__()
        else:
            super().__init__(
                fmt='%(asctime)s | %(levelname)-8s | %(name)-20s | %(funcName)-15s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
    
    def format(self, record):
        if self.json_format:
            return self._format_json(record)
        else:
            return self._format_text(record)
    
    def _format_json(self, record):
        """Format log record as JSON"""
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'function': record.funcName,
            'line': record.lineno,
            'message': record.getMessage(),
            'thread': threading.current_thread().name
        }
        
        # Add extra fields
        if hasattr(record, 'agent_name'):
            log_data['agent_name'] = record.agent_name
        if hasattr(record, 'analysis_id'):
            log_data['analysis_id'] = record.analysis_id
        if hasattr(record, 'execution_time'):
            log_data['execution_time'] = record.execution_time
        if hasattr(record, 'error_type'):
            log_data['error_type'] = record.error_type
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        return json.dumps(log_data)
    
    def _format_text(self, record):
        """Format log record as text with colors"""
        # Add color codes for different levels
        colors = {
            'DEBUG': '\033[36m',    # Cyan
            'INFO': '\033[32m',     # Green
            'WARNING': '\033[33m',  # Yellow
            'ERROR': '\033[31m',    # Red
            'CRITICAL': '\033[35m'  # Magenta
        }
        reset = '\033[0m'
        
        formatted = super().format(record)
        
        # Add color if terminal supports it
        if hasattr(record, 'no_color') and record.no_color:
            return formatted
        
        color = colors.get(record.levelname, '')
        return f"{color}{formatted}{reset}"

class ContextFilter(logging.Filter):
    """Filter to add contextual information to log records"""
    
    def __init__(self):
        super().__init__()
        self.context = threading.local()
    
    def filter(self, record):
        # Add context information if available
        if hasattr(self.context, 'agent_name'):
            record.agent_name = self.context.agent_name
        if hasattr(self.context, 'analysis_id'):
            record.analysis_id = self.context.analysis_id
        if hasattr(self.context, 'request_id'):
            record.request_id = self.context.request_id
        
        return True
    
    def set_context(self, **kwargs):
        """Set context for current thread"""
        for key, value in kwargs.items():
            setattr(self.context, key, value)
    
    def clear_context(self):
        """Clear context for current thread"""
        self.context = threading.local()

class PerformanceLogger:
    """Logger for tracking performance metrics"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.metrics = {}
    
    def log_execution_time(self, operation: str, execution_time: float, 
                          success: bool = True, **kwargs):
        """Log execution time for an operation"""
        self.logger.info(
            f"Operation '{operation}' completed in {execution_time:.3f}s",
            extra={
                'execution_time': execution_time,
                'operation': operation,
                'success': success,
                **kwargs
            }
        )
        
        # Track metrics
        if operation not in self.metrics:
            self.metrics[operation] = []
        self.metrics[operation].append({
            'time': execution_time,
            'success': success,
            'timestamp': datetime.now()
        })
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of performance metrics"""
        summary = {}
        for operation, measurements in self.metrics.items():
            times = [m['time'] for m in measurements]
            successes = [m for m in measurements if m['success']]
            
            summary[operation] = {
                'count': len(measurements),
                'success_count': len(successes),
                'success_rate': len(successes) / len(measurements) if measurements else 0,
                'avg_time': sum(times) / len(times) if times else 0,
                'min_time': min(times) if times else 0,
                'max_time': max(times) if times else 0,
                'total_time': sum(times)
            }
        
        return summary

class CodeReviewLogger:
    """Main logger class for the code review system"""
    
    def __init__(self, config=None):
        self.config = config
        self.context_filter = ContextFilter()
        self.performance_logger = None
        self._setup_logging()
    
    def _setup_logging(self):
        """Setup logging configuration"""
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        root_logger.handlers.clear()
        
        # Setup console handler
        self._setup_console_handler(root_logger)
        
        # Setup file handler
        if self.config and self.config.logging.file_enabled:
            self._setup_file_handler(root_logger)
        
        # Setup performance logger
        perf_logger = logging.getLogger('performance')
        self.performance_logger = PerformanceLogger(perf_logger)
        
        # Add context filter to all handlers
        for handler in root_logger.handlers:
            handler.addFilter(self.context_filter)
    
    def _setup_console_handler(self, logger):
        """Setup console logging handler"""
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(CodeReviewFormatter(json_format=False))
        logger.addHandler(console_handler)
    
    def _setup_file_handler(self, logger):
        """Setup file logging handler with rotation"""
        log_file = self.config.logging.file_path if self.config else "logs/code_review.log"
        
        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        
        # Use JSON format for file logs
        file_handler.setFormatter(CodeReviewFormatter(json_format=True))
        logger.addHandler(file_handler)
    
    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger with the specified name"""
        logger = logging.getLogger(name)
        
        # Set level based on config
        if self.config:
            level = getattr(logging, self.config.logging.level.upper())
            logger.setLevel(level)
        
        return logger
    
    @contextmanager
    def log_context(self, **kwargs):
        """Context manager for adding context to logs"""
        self.context_filter.set_context(**kwargs)
        try:
            yield
        finally:
            self.context_filter.clear_context()
    
    def log_agent_activity(self, agent_name: str, activity: str, **kwargs):
        """Log agent activity with context"""
        logger = self.get_logger(f'agent.{agent_name}')
        with self.log_context(agent_name=agent_name):
            logger.info(f"Agent activity: {activity}", extra=kwargs)
    
    def log_analysis_start(self, analysis_id: str, code_length: int, analysis_type: str):
        """Log the start of an analysis"""
        logger = self.get_logger('analysis')
        with self.log_context(analysis_id=analysis_id):
            logger.info(
                f"Starting {analysis_type} analysis",
                extra={
                    'code_length': code_length,
                    'analysis_type': analysis_type
                }
            )
    
    def log_analysis_complete(self, analysis_id: str, duration: float, 
                            issues_found: int, success: bool = True):
        """Log the completion of an analysis"""
        logger = self.get_logger('analysis')
        with self.log_context(analysis_id=analysis_id):
            if success:
                logger.info(
                    f"Analysis completed in {duration:.3f}s, found {issues_found} issues",
                    extra={
                        'duration': duration,
                        'issues_found': issues_found,
                        'success': success
                    }
                )
            else:
                logger.error(
                    f"Analysis failed after {duration:.3f}s",
                    extra={
                        'duration': duration,
                        'success': success
                    }
                )
        
        # Log performance metrics
        if self.performance_logger:
            self.performance_logger.log_execution_time(
                'code_analysis',
                duration,
                success=success,
                issues_found=issues_found
            )
    
    def log_error(self, logger_name: str, error: Exception, context: Dict[str, Any] = None):
        """Log an error with full context and traceback"""
        logger = self.get_logger(logger_name)
        
        extra = {
            'error_type': type(error).__name__,
            'error_message': str(error)
        }
        
        if context:
            extra.update(context)
        
        logger.error(f"Error occurred: {str(error)}", extra=extra, exc_info=True)
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics summary"""
        if self.performance_logger:
            return self.performance_logger.get_metrics_summary()
        return {}

# Decorators for logging
def log_performance(operation_name: str = None):
    """Decorator to log function execution time"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            operation = operation_name or f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Get logger from global instance
                logger = logging.getLogger('performance')
                logger.info(
                    f"Function '{operation}' completed in {execution_time:.3f}s",
                    extra={'execution_time': execution_time, 'operation': operation}
                )
                
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                
                logger = logging.getLogger('performance')
                logger.error(
                    f"Function '{operation}' failed after {execution_time:.3f}s: {str(e)}",
                    extra={
                        'execution_time': execution_time,
                        'operation': operation,
                        'error': str(e)
                    }
                )
                raise
        
        return wrapper
    return decorator

def log_agent_method(agent_name: str):
    """Decorator to log agent method calls"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(f'agent.{agent_name}')
            
            # Log method entry
            logger.debug(f"Calling method: {func.__name__}")
            
            try:
                result = func(*args, **kwargs)
                logger.debug(f"Method {func.__name__} completed successfully")
                return result
            except Exception as e:
                logger.error(f"Method {func.__name__} failed: {str(e)}", exc_info=True)
                raise
        
        return wrapper
    return decorator

# Global logger instance
_global_logger_instance = None

def setup_logging(config=None) -> CodeReviewLogger:
    """Setup global logging configuration"""
    global _global_logger_instance
    _global_logger_instance = CodeReviewLogger(config)
    return _global_logger_instance

def get_logger(name: str) -> logging.Logger:
    """Get a logger instance"""
    if _global_logger_instance:
        return _global_logger_instance.get_logger(name)
    else:
        # Fallback to basic logging
        return logging.getLogger(name)

def log_context(**kwargs):
    """Context manager for adding context to logs"""
    if _global_logger_instance:
        return _global_logger_instance.log_context(**kwargs)
    else:
        from contextlib import nullcontext
        return nullcontext()

# Example usage and testing
if __name__ == "__main__":
    # Setup logging
    logger_system = setup_logging()
    
    # Get different loggers
    main_logger = get_logger('main')
    agent_logger = get_logger('agent.security')
    analysis_logger = get_logger('analysis')
    
    # Test basic logging
    main_logger.info("Starting code review system")
    main_logger.debug("Debug information")
    main_logger.warning("This is a warning")
    
    # Test context logging
    with log_context(analysis_id="test-001", agent_name="security"):
        agent_logger.info("Performing security analysis")
        analysis_logger.info("Found potential security issue")
    
    # Test performance logging
    @log_performance("test_operation")
    def test_function():
        time.sleep(0.1)
        return "test result"
    
    result = test_function()
    
    # Test error logging
    try:
        raise ValueError("Test error for logging")
    except Exception as e:
        logger_system.log_error('test', e, {'context': 'testing error logging'})
    
    # Test agent activity logging
    logger_system.log_agent_activity(
        'security',
        'vulnerability_scan',
        vulnerabilities_found=3,
        scan_duration=2.5
    )
    
    # Test analysis logging
    import uuid
    analysis_id = str(uuid.uuid4())
    
    logger_system.log_analysis_start(analysis_id, 1500, 'security')
    time.sleep(0.1)
    logger_system.log_analysis_complete(analysis_id, 0.1, 5, True)
    
    # Get performance metrics
    metrics = logger_system.get_performance_metrics()
    if metrics:
        main_logger.info(f"Performance metrics: {json.dumps(metrics, indent=2)}")
    
    print("✅ Logging system test completed")