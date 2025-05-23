#!/usr/bin/env python3
"""
Enhanced Caching System for Code Review
Provides multiple caching backends with TTL, compression, and analytics
"""

import json
import pickle
import hashlib
import time
import threading
import gzip
from abc import ABC, abstractmethod
from typing import Any, Optional, Dict, List, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from pathlib import Path
import logging

@dataclass
class CacheEntry:
    """Represents a cache entry with metadata"""
    key: str
    value: Any
    created_at: datetime
    accessed_at: datetime
    access_count: int
    ttl: Optional[int]
    compressed: bool = False
    size_bytes: int = 0

@dataclass
class CacheStats:
    """Cache statistics for monitoring"""
    hits: int = 0
    misses: int = 0
    evictions: int = 0
    total_size: int = 0
    entry_count: int = 0
    
    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0

class CacheBackend(ABC):
    """Abstract base class for cache backends"""
    
    @abstractmethod
    def get(self, key: str) -> Optional[CacheEntry]:
        """Get a value from cache"""
        pass
    
    @abstractmethod
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        pass
    
    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        pass
    
    @abstractmethod
    def clear(self) -> bool:
        """Clear all cache entries"""
        pass
    
    @abstractmethod
    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        pass
    
    @abstractmethod
    def cleanup_expired(self) -> int:
        """Remove expired entries, return count removed"""
        pass

class MemoryCache(CacheBackend):
    """In-memory cache implementation with LRU eviction"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache: Dict[str, CacheEntry] = {}
        self._access_order: List[str] = []
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self.logger = logging.getLogger(f'{__name__}.MemoryCache')
    
    def get(self, key: str) -> Optional[CacheEntry]:
        """Get a value from cache"""
        with self._lock:
            entry = self._cache.get(key)
            
            if entry is None:
                self._stats.misses += 1
                return None
            
            # Check if expired
            if self._is_expired(entry):
                self.delete(key)
                self._stats.misses += 1
                return None
            
            # Update access info
            entry.accessed_at = datetime.now()
            entry.access_count += 1
            
            # Move to end for LRU
            if key in self._access_order:
                self._access_order.remove(key)
            self._access_order.append(key)
            
            self._stats.hits += 1
            return entry
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        with self._lock:
            try:
                # Serialize and compress if needed
                serialized_value, compressed = self._serialize_value(value)
                size_bytes = len(serialized_value) if isinstance(serialized_value, bytes) else len(str(serialized_value))
                
                # Create cache entry
                entry = CacheEntry(
                    key=key,
                    value=serialized_value,
                    created_at=datetime.now(),
                    accessed_at=datetime.now(),
                    access_count=0,
                    ttl=ttl or self.default_ttl,
                    compressed=compressed,
                    size_bytes=size_bytes
                )
                
                # Remove old entry if exists
                if key in self._cache:
                    old_entry = self._cache[key]
                    self._stats.total_size -= old_entry.size_bytes
                    if key in self._access_order:
                        self._access_order.remove(key)
                
                # Check if we need to evict
                while len(self._cache) >= self.max_size:
                    self._evict_lru()
                
                # Add new entry
                self._cache[key] = entry
                self._access_order.append(key)
                self._stats.total_size += size_bytes
                self._stats.entry_count = len(self._cache)
                
                self.logger.debug(f"Cached entry: {key} ({size_bytes} bytes)")
                return True
                
            except Exception as e:
                self.logger.error(f"Error setting cache entry {key}: {e}")
                return False
    
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        with self._lock:
            if key in self._cache:
                entry = self._cache.pop(key)
                self._stats.total_size -= entry.size_bytes
                
                if key in self._access_order:
                    self._access_order.remove(key)
                
                self._stats.entry_count = len(self._cache)
                self.logger.debug(f"Deleted cache entry: {key}")
                return True
            return False
    
    def clear(self) -> bool:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._access_order.clear()
            self._stats.total_size = 0
            self._stats.entry_count = 0
            self.logger.info("Cache cleared")
            return True
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        with self._lock:
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                total_size=self._stats.total_size,
                entry_count=self._stats.entry_count
            )
    
    def cleanup_expired(self) -> int:
        """Remove expired entries"""
        with self._lock:
            expired_keys = []
            now = datetime.now()
            
            for key, entry in self._cache.items():
                if self._is_expired(entry, now):
                    expired_keys.append(key)
            
            for key in expired_keys:
                self.delete(key)
            
            if expired_keys:
                self.logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
            
            return len(expired_keys)
    
    def _serialize_value(self, value: Any) -> Tuple[Any, bool]:
        """Serialize and optionally compress value"""
        try:
            # Serialize to JSON first for most data types
            if isinstance(value, (dict, list, str, int, float, bool)) or value is None:
                serialized = json.dumps(value, default=str).encode('utf-8')
            else:
                # Use pickle for complex objects
                serialized = pickle.dumps(value)
            
            # Compress if size is large enough
            if len(serialized) > 1024:  # 1KB threshold
                compressed = gzip.compress(serialized)
                if len(compressed) < len(serialized):
                    return compressed, True
            
            return serialized, False
            
        except Exception as e:
            self.logger.warning(f"Error serializing value: {e}")
            return str(value).encode('utf-8'), False
    
    def _deserialize_value(self, entry: CacheEntry) -> Any:
        """Deserialize and decompress value"""
        try:
            data = entry.value
            
            # Decompress if needed
            if entry.compressed:
                data = gzip.decompress(data)
            
            # Try JSON first
            try:
                if isinstance(data, bytes):
                    return json.loads(data.decode('utf-8'))
                else:
                    return json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Fall back to pickle
                return pickle.loads(data)
                
        except Exception as e:
            self.logger.error(f"Error deserializing cache entry: {e}")
            return None
    
    def _is_expired(self, entry: CacheEntry, now: datetime = None) -> bool:
        """Check if cache entry is expired"""
        if entry.ttl is None:
            return False
        
        if now is None:
            now = datetime.now()
        
        expiry_time = entry.created_at + timedelta(seconds=entry.ttl)
        return now > expiry_time
    
    def _evict_lru(self):
        """Evict least recently used entry"""
        if self._access_order:
            lru_key = self._access_order[0]
            self.delete(lru_key)
            self._stats.evictions += 1

class FileCache(CacheBackend):
    """File-based cache implementation"""
    
    def __init__(self, cache_dir: str = "cache", max_size_mb: int = 100, default_ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.default_ttl = default_ttl
        self._lock = threading.RLock()
        self._stats = CacheStats()
        self.logger = logging.getLogger(f'{__name__}.FileCache')
        
        # Load existing cache metadata
        self._load_metadata()
    
    def get(self, key: str) -> Optional[CacheEntry]:
        """Get a value from cache"""
        with self._lock:
            file_path = self._get_file_path(key)
            
            if not file_path.exists():
                self._stats.misses += 1
                return None
            
            try:
                with open(file_path, 'rb') as f:
                    entry_data = pickle.load(f)
                
                entry = CacheEntry(**entry_data)
                
                # Check if expired
                if self._is_expired(entry):
                    self.delete(key)
                    self._stats.misses += 1
                    return None
                
                # Update access info
                entry.accessed_at = datetime.now()
                entry.access_count += 1
                
                # Save updated metadata
                with open(file_path, 'wb') as f:
                    pickle.dump(entry.__dict__, f)
                
                self._stats.hits += 1
                return entry
                
            except Exception as e:
                self.logger.error(f"Error reading cache file {file_path}: {e}")
                self._stats.misses += 1
                return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Set a value in cache"""
        with self._lock:
            try:
                file_path = self._get_file_path(key)
                
                # Serialize value
                serialized_value = pickle.dumps(value)
                
                # Create cache entry
                entry = CacheEntry(
                    key=key,
                    value=value,
                    created_at=datetime.now(),
                    accessed_at=datetime.now(),
                    access_count=0,
                    ttl=ttl or self.default_ttl,
                    size_bytes=len(serialized_value)
                )
                
                # Check size limits
                if entry.size_bytes > self.max_size_bytes:
                    self.logger.warning(f"Cache entry {key} too large ({entry.size_bytes} bytes)")
                    return False
                
                # Clean up if needed
                self._ensure_space(entry.size_bytes)
                
                # Write to file
                with open(file_path, 'wb') as f:
                    pickle.dump(entry.__dict__, f)
                
                self._update_stats()
                self.logger.debug(f"Cached entry to file: {key} ({entry.size_bytes} bytes)")
                return True
                
            except Exception as e:
                self.logger.error(f"Error setting cache entry {key}: {e}")
                return False
    
    def delete(self, key: str) -> bool:
        """Delete a value from cache"""
        with self._lock:
            file_path = self._get_file_path(key)
            
            if file_path.exists():
                try:
                    file_path.unlink()
                    self._update_stats()
                    self.logger.debug(f"Deleted cache file: {key}")
                    return True
                except Exception as e:
                    self.logger.error(f"Error deleting cache file {file_path}: {e}")
            
            return False
    
    def clear(self) -> bool:
        """Clear all cache entries"""
        with self._lock:
            try:
                for file_path in self.cache_dir.glob("*.cache"):
                    file_path.unlink()
                
                self._stats = CacheStats()
                self.logger.info("File cache cleared")
                return True
            except Exception as e:
                self.logger.error(f"Error clearing cache: {e}")
                return False
    
    def get_stats(self) -> CacheStats:
        """Get cache statistics"""
        with self._lock:
            self._update_stats()
            return CacheStats(
                hits=self._stats.hits,
                misses=self._stats.misses,
                evictions=self._stats.evictions,
                total_size=self._stats.total_size,
                entry_count=self._stats.entry_count
            )
    
    def cleanup_expired(self) -> int:
        """Remove expired entries"""
        with self._lock:
            expired_count = 0
            now = datetime.now()
            
            for file_path in self.cache_dir.glob("*.cache"):
                try:
                    with open(file_path, 'rb') as f:
                        entry_data = pickle.load(f)
                    
                    entry = CacheEntry(**entry_data)
                    
                    if self._is_expired(entry, now):
                        file_path.unlink()
                        expired_count += 1
                        
                except Exception as e:
                    self.logger.warning(f"Error checking cache file {file_path}: {e}")
                    # Remove corrupted files
                    try:
                        file_path.unlink()
                        expired_count += 1
                    except:
                        pass
            
            if expired_count > 0:
                self.logger.info(f"Cleaned up {expired_count} expired cache files")
                self._update_stats()
            
            return expired_count
    
    def _get_file_path(self, key: str) -> Path:
        """Get file path for cache key"""
        # Hash the key to create a safe filename
        key_hash = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.cache"
    
    def _load_metadata(self):
        """Load existing cache metadata"""
        self._update_stats()
    
    def _update_stats(self):
        """Update cache statistics"""
        total_size = 0
        entry_count = 0
        
        for file_path in self.cache_dir.glob("*.cache"):
            try:
                total_size += file_path.stat().st_size
                entry_count += 1
            except:
                pass
        
        self._stats.total_size = total_size
        self._stats.entry_count = entry_count
    
    def _ensure_space(self, needed_bytes: int):
        """Ensure enough space for new entry"""
        current_size = sum(f.stat().st_size for f in self.cache_dir.glob("*.cache"))
        
        if current_size + needed_bytes > self.max_size_bytes:
            # Remove oldest files until we have space
            files_by_age = sorted(
                self.cache_dir.glob("*.cache"),
                key=lambda f: f.stat().st_mtime
            )
            
            for file_path in files_by_age:
                try:
                    file_size = file_path.stat().st_size
                    file_path.unlink()
                    current_size -= file_size
                    self._stats.evictions += 1
                    
                    if current_size + needed_bytes <= self.max_size_bytes:
                        break
                except:
                    pass
    
    def _is_expired(self, entry: CacheEntry, now: datetime = None) -> bool:
        """Check if cache entry is expired"""
        if entry.ttl is None:
            return False
        
        if now is None:
            now = datetime.now()
        
        expiry_time = entry.created_at + timedelta(seconds=entry.ttl)
        return now > expiry_time

class CodeAnalysisCache:
    """High-level cache for code analysis results"""
    
    def __init__(self, backend: CacheBackend):
        self.backend = backend
        self.logger = logging.getLogger(f'{__name__}.CodeAnalysisCache')
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def get_analysis_result(self, code: str, analysis_type: str) -> Optional[Dict]:
        """Get cached analysis result"""
        cache_key = self._generate_cache_key(code, analysis_type)
        
        entry = self.backend.get(cache_key)
        if entry:
            try:
                if hasattr(self.backend, '_deserialize_value'):
                    return self.backend._deserialize_value(entry)
                else:
                    return entry.value
            except Exception as e:
                self.logger.error(f"Error deserializing cache entry: {e}")
                self.backend.delete(cache_key)
        
        return None
    
    def cache_analysis_result(self, code: str, analysis_type: str, 
                            result: Dict, ttl: Optional[int] = None) -> bool:
        """Cache analysis result"""
        cache_key = self._generate_cache_key(code, analysis_type)
        
        # Add metadata to result
        cached_result = {
            'analysis_type': analysis_type,
            'result': result,
            'cached_at': datetime.now().isoformat(),
            'code_hash': self._hash_code(code)
        }
        
        success = self.backend.set(cache_key, cached_result, ttl)
        
        if success:
            self.logger.debug(f"Cached {analysis_type} analysis result")
        else:
            self.logger.warning(f"Failed to cache {analysis_type} analysis result")
        
        return success
    
    def invalidate_analysis(self, code: str, analysis_type: str = None) -> bool:
        """Invalidate cached analysis for specific code"""
        if analysis_type:
            cache_key = self._generate_cache_key(code, analysis_type)
            return self.backend.delete(cache_key)
        else:
            # Invalidate all analysis types for this code
            code_hash = self._hash_code(code)
            # This is a simplified implementation - in practice you'd need
            # to track all cache keys or use pattern matching
            return True
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        stats = self.backend.get_stats()
        
        return {
            'hit_rate': f"{stats.hit_rate:.2%}",
            'total_entries': stats.entry_count,
            'total_size_mb': f"{stats.total_size / (1024*1024):.2f}",
            'hits': stats.hits,
            'misses': stats.misses,
            'evictions': stats.evictions
        }
    
    def _generate_cache_key(self, code: str, analysis_type: str) -> str:
        """Generate cache key for code and analysis type"""
        code_hash = self._hash_code(code)
        return f"analysis:{analysis_type}:{code_hash}"
    
    def _hash_code(self, code: str) -> str:
        """Generate hash for code content"""
        # Normalize code (remove extra whitespace, etc.)
        normalized_code = ' '.join(code.split())
        return hashlib.sha256(normalized_code.encode()).hexdigest()[:16]
    
    def _start_cleanup_thread(self):
        """Start background thread for cache cleanup"""
        def cleanup_loop():
            while True:
                try:
                    time.sleep(300)  # Clean up every 5 minutes
                    expired_count = self.backend.cleanup_expired()
                    if expired_count > 0:
                        self.logger.info(f"Cleaned up {expired_count} expired cache entries")
                except Exception as e:
                    self.logger.error(f"Error during cache cleanup: {e}")
        
        cleanup_thread = threading.Thread(target=cleanup_loop, daemon=True)
        cleanup_thread.start()

# Factory function to create cache based on configuration
def create_cache(config) -> CodeAnalysisCache:
    """Create cache instance based on configuration"""
    if not config.cache.enabled:
        # Return a null cache that doesn't actually cache anything
        class NullBackend(CacheBackend):
            def get(self, key: str) -> Optional[CacheEntry]: return None
            def set(self, key: str, value: Any, ttl: Optional[int] = None) -> bool: return True
            def delete(self, key: str) -> bool: return True
            def clear(self) -> bool: return True
            def get_stats(self) -> CacheStats: return CacheStats()
            def cleanup_expired(self) -> int: return 0
        
        return CodeAnalysisCache(NullBackend())
    
    if config.cache.type == "memory":
        backend = MemoryCache(
            max_size=config.cache.max_size,
            default_ttl=config.cache.ttl
        )
    elif config.cache.type == "file":
        backend = FileCache(
            cache_dir="cache",
            max_size_mb=100,
            default_ttl=config.cache.ttl
        )
    else:
        raise ValueError(f"Unsupported cache type: {config.cache.type}")
    
    return CodeAnalysisCache(backend)

# Example usage
if __name__ == "__main__":
    # Test memory cache
    memory_cache = MemoryCache(max_size=10)
    
    # Test basic operations
    memory_cache.set("test_key", {"data": "test_value"}, ttl=60)
    entry = memory_cache.get("test_key")
    
    if entry:
        print(f"Retrieved: {entry.value}")
    
    # Test with code analysis cache
    analysis_cache = CodeAnalysisCache(memory_cache)
    
    test_code = """
def test_function():
    return "hello world"
    """
    
    test_result = {
        "issues": [],
        "summary": "No issues found"
    }
    
    # Cache analysis result
    analysis_cache.cache_analysis_result(test_code, "security", test_result)
    
    # Retrieve cached result
    cached_result = analysis_cache.get_analysis_result(test_code, "security")
    if cached_result:
        print(f"Cached result: {cached_result}")
    
    # Get stats
    stats = analysis_cache.get_cache_stats()
    print(f"Cache stats: {stats}")
    
    print("✅ Cache system test completed")