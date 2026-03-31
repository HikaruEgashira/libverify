use std::path::{Path, PathBuf};

use crate::evidence::EvidenceBundle;

/// Trait for caching collected evidence bundles.
///
/// Implementors store and retrieve [`EvidenceBundle`] by a string key,
/// enabling incremental verification and multi-policy evaluation without
/// redundant API calls.
pub trait EvidenceCache: Send + Sync {
    /// Retrieve a cached bundle, or `None` if not present / expired.
    fn get(&self, key: &str) -> Option<EvidenceBundle>;
    /// Store a bundle under the given key.
    fn put(&self, key: &str, bundle: &EvidenceBundle);
}

/// Build a deterministic cache key from a subject type and identifier.
///
/// # Examples
/// ```
/// use libverify_core::cache::cache_key;
/// assert_eq!(cache_key("pr", "owner/repo#42", "abc1234"), "pr:owner/repo#42:abc1234");
/// ```
pub fn cache_key(subject_type: &str, subject_id: &str, revision: &str) -> String {
    format!("{subject_type}:{subject_id}:{revision}")
}

/// A no-op cache that never stores or retrieves anything.
pub struct NoCache;

impl EvidenceCache for NoCache {
    fn get(&self, _key: &str) -> Option<EvidenceBundle> {
        None
    }
    fn put(&self, _key: &str, _bundle: &EvidenceBundle) {}
}

/// Filesystem-backed evidence cache.
///
/// Stores bundles as JSON files in a directory, keyed by a sanitized
/// filename derived from the cache key. Files older than `ttl` seconds
/// are treated as expired.
pub struct FsCache {
    dir: PathBuf,
    ttl_secs: u64,
}

impl FsCache {
    /// Create a new filesystem cache rooted at `dir` with the given TTL.
    ///
    /// The directory is created if it does not exist.
    pub fn new(dir: impl Into<PathBuf>, ttl_secs: u64) -> std::io::Result<Self> {
        let dir = dir.into();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir, ttl_secs })
    }

    fn path_for(&self, key: &str) -> PathBuf {
        let sanitized: String = key
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.dir.join(format!("{sanitized}.json"))
    }

    fn is_fresh(path: &Path, ttl_secs: u64) -> bool {
        path.metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|mtime| mtime.elapsed().ok())
            .is_some_and(|age| age.as_secs() < ttl_secs)
    }
}

impl EvidenceCache for FsCache {
    fn get(&self, key: &str) -> Option<EvidenceBundle> {
        let path = self.path_for(key);
        if !Self::is_fresh(&path, self.ttl_secs) {
            return None;
        }
        let data = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn put(&self, key: &str, bundle: &EvidenceBundle) {
        let path = self.path_for(key);
        if let Ok(json) = serde_json::to_string(bundle) {
            let _ = std::fs::write(&path, json);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_key_format() {
        assert_eq!(
            cache_key("pr", "owner/repo#42", "abc1234"),
            "pr:owner/repo#42:abc1234"
        );
    }

    #[test]
    fn no_cache_always_misses() {
        let cache = NoCache;
        assert!(cache.get("anything").is_none());
    }

    #[test]
    fn fs_cache_round_trip() {
        let dir = std::env::temp_dir().join("libverify-cache-test");
        let _ = std::fs::remove_dir_all(&dir);
        let cache = FsCache::new(&dir, 3600).unwrap();

        let bundle = EvidenceBundle::default();
        cache.put("test-key", &bundle);

        let retrieved = cache.get("test-key");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), bundle);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fs_cache_expired_returns_none() {
        let dir = std::env::temp_dir().join("libverify-cache-expire-test");
        let _ = std::fs::remove_dir_all(&dir);
        // TTL of 0 seconds means everything is expired immediately
        let cache = FsCache::new(&dir, 0).unwrap();

        let bundle = EvidenceBundle::default();
        cache.put("expired-key", &bundle);

        assert!(cache.get("expired-key").is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
