// Update Check Cache
//
// Provides caching for update check results to avoid redundant API calls

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use super::traits::UpdateCheckResult;

/// Cache entry with timestamp
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Cached result
    pub result: UpdateCheckResult,
    
    /// When this entry was created
    #[serde(skip, default = "Instant::now")]
    pub created_at: Instant,
    
    /// How long this entry is valid
    pub ttl: Duration,
}

impl CacheEntry {
    pub fn new(result: UpdateCheckResult, ttl: Duration) -> Self {
        Self {
            result,
            created_at: Instant::now(),
            ttl,
        }
    }

    /// Check if this cache entry is still valid
    pub fn is_valid(&self) -> bool {
        self.created_at.elapsed() < self.ttl
    }

    /// Get the remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        let elapsed = self.created_at.elapsed();
        if elapsed >= self.ttl {
            Duration::ZERO
        } else {
            self.ttl - elapsed
        }
    }
}

/// Thread-safe cache for update check results
#[derive(Debug)]
pub struct UpdateCache {
    /// Cache storage
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    
    /// Default TTL for cache entries
    default_ttl: Duration,
    
    /// Maximum number of cache entries
    max_entries: usize,
}

impl UpdateCache {
    pub fn new(default_ttl: Duration, max_entries: usize) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            default_ttl,
            max_entries,
        }
    }

    /// Get a cached result
    pub async fn get(&self, key: &str) -> Option<UpdateCheckResult> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(key) {
            if entry.is_valid() {
                return Some(entry.result.clone());
            }
        }
        None
    }

    /// Store a result in the cache
    pub async fn set(&self, key: String, result: UpdateCheckResult) {
        let mut cache = self.cache.write().await;
        
        // Check if we need to evict old entries
        if cache.len() >= self.max_entries {
            self.evict_expired_entries(&mut cache).await;
        }
        
        let entry = CacheEntry::new(result, self.default_ttl);
        cache.insert(key, entry);
    }

    /// Store a result with custom TTL
    pub async fn set_with_ttl(&self, key: String, result: UpdateCheckResult, ttl: Duration) {
        let mut cache = self.cache.write().await;
        
        // Check if we need to evict old entries
        if cache.len() >= self.max_entries {
            self.evict_expired_entries(&mut cache).await;
        }
        
        let entry = CacheEntry::new(result, ttl);
        cache.insert(key, entry);
    }

    /// Remove a specific cache entry
    pub async fn remove(&self, key: &str) -> Option<UpdateCheckResult> {
        let mut cache = self.cache.write().await;
        cache.remove(key).map(|entry| entry.result)
    }

    /// Clear all cache entries
    pub async fn clear(&self) {
        let mut cache = self.cache.write().await;
        cache.clear();
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let cache = self.cache.read().await;
        let total_entries = cache.len();
        let mut valid_entries = 0;
        let mut expired_entries = 0;
        
        for entry in cache.values() {
            if entry.is_valid() {
                valid_entries += 1;
            } else {
                expired_entries += 1;
            }
        }
        
        CacheStats {
            total_entries,
            valid_entries,
            expired_entries,
            max_entries: self.max_entries,
        }
    }

    /// Clean up expired entries
    pub async fn cleanup(&self) -> usize {
        let mut cache = self.cache.write().await;
        self.evict_expired_entries(&mut cache).await
    }

    /// Evict expired entries from the cache
    async fn evict_expired_entries(&self, cache: &mut HashMap<String, CacheEntry>) -> usize {
        let initial_len = cache.len();
        cache.retain(|_, entry| entry.is_valid());
        initial_len - cache.len()
    }

    /// Generate cache key for a package manager and package
    pub fn cache_key(manager: &str, package: &str) -> String {
        format!("{}:{}", manager, package)
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    /// Total number of cache entries
    pub total_entries: usize,
    
    /// Number of valid (non-expired) entries
    pub valid_entries: usize,
    
    /// Number of expired entries
    pub expired_entries: usize,
    
    /// Maximum number of entries allowed
    pub max_entries: usize,
}

impl Default for UpdateCache {
    fn default() -> Self {
        Self::new(Duration::from_secs(300), 1000) // 5 minutes TTL, 1000 max entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let cache = UpdateCache::new(Duration::from_secs(1), 10);
        
        let result = UpdateCheckResult::success(
            false,
            Some("1.0.0".to_string()),
            Some("1.0.0".to_string()),
            "test".to_string(),
            None,
            None,
        );
        
        // Test set and get
        cache.set("test:package".to_string(), result.clone()).await;
        let cached = cache.get("test:package").await;
        assert!(cached.is_some());
        assert_eq!(cached.unwrap().current_version, result.current_version);
        
        // Test removal
        let removed = cache.remove("test:package").await;
        assert!(removed.is_some());
        
        // Test get after removal
        let cached = cache.get("test:package").await;
        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let cache = UpdateCache::new(Duration::from_millis(100), 10);
        
        let result = UpdateCheckResult::success(
            false,
            Some("1.0.0".to_string()),
            Some("1.0.0".to_string()),
            "test".to_string(),
            None,
            None,
        );
        
        // Set entry
        cache.set("test:package".to_string(), result).await;
        
        // Should be available immediately
        assert!(cache.get("test:package").await.is_some());
        
        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(150)).await;
        
        // Should be expired
        assert!(cache.get("test:package").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let cache = UpdateCache::new(Duration::from_secs(1), 10);
        
        let result = UpdateCheckResult::success(
            false,
            Some("1.0.0".to_string()),
            Some("1.0.0".to_string()),
            "test".to_string(),
            None,
            None,
        );
        
        // Add some entries
        cache.set("test:package1".to_string(), result.clone()).await;
        cache.set("test:package2".to_string(), result.clone()).await;
        
        let stats = cache.stats().await;
        assert_eq!(stats.total_entries, 2);
        assert_eq!(stats.valid_entries, 2);
        assert_eq!(stats.expired_entries, 0);
        assert_eq!(stats.max_entries, 10);
    }

    #[tokio::test]
    async fn test_cache_key_generation() {
        assert_eq!(UpdateCache::cache_key("npm", "package"), "npm:package");
        assert_eq!(UpdateCache::cache_key("go", "tool"), "go:tool");
    }
}
