use super::ffi;
use super::storage::SQLiteBatchStorage;
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub struct OZKSError(String);

impl fmt::Display for OZKSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "OZKS Error: {}", self.0)
    }
}

impl Error for OZKSError {}

/// OZKS configuration
pub struct OZKSConfig {
    pub payload_commitment_type: u32,
    pub label_type: u32,
    pub trie_type: u32,
}

impl OZKSConfig {
    /// Create default config (CommitedPayload, VRFLabels, Stored)
    pub fn new() -> Self {
        OZKSConfig {
            payload_commitment_type: 1, // CommitedPayload
            label_type: 0,              // VRFLabels
            trie_type: 0,               // Stored
        }
    }
}

/// Commitment returned by OZKS
pub struct Commitment {
    root: Vec<u8>,
}

impl Commitment {
    pub fn new(root: Vec<u8>) -> Self {
        Commitment { root }
    }

    pub fn root_commitment(&self) -> &[u8] {
        &self.root
    }
}

/// Query result
pub struct QueryResult {
    is_member: bool,
}

impl QueryResult {
    pub fn new(is_member: bool) -> Self {
        QueryResult { is_member }
    }

    pub fn is_member(&self) -> bool {
        self.is_member
    }
}

/// OZKS instance wrapper
pub struct OZKS {
    handle: ffi::bindings::OZKSHandle,
    trie_id: i64,
}

impl OZKS {
    /// Create new OZKS instance with SQLite storage backend
    pub fn new(config: OZKSConfig, _storage: &SQLiteBatchStorage) -> Result<Self, Box<dyn Error>> {
        unsafe {
            let handle = ffi::bindings::ozks_create(
                config.payload_commitment_type,
                config.label_type,
                config.trie_type,
                std::ptr::null_mut(),
            );

            if handle == 0 {
                return Err(Box::new(OZKSError(
                    "Failed to create OZKS instance".to_string(),
                )));
            }

            let trie_id = ffi::bindings::ozks_get_id(handle) as i64;

            Ok(OZKS { handle, trie_id })
        }
    }

    /// Get instance ID (trie_id)
    pub fn id(&self) -> i64 {
        self.trie_id
    }

    /// Insert batch of key-value pairs
    pub fn insert(&mut self, batch: &[(Vec<u8>, Vec<u8>)]) -> Result<(), Box<dyn Error>> {
        if batch.is_empty() {
            return Ok(());
        }

        unsafe {
            let keys: Vec<*const u8> = batch.iter().map(|(k, _)| k.as_ptr()).collect();
            let key_lens: Vec<usize> = batch.iter().map(|(k, _)| k.len()).collect();
            let payloads: Vec<*const u8> = batch.iter().map(|(_, p)| p.as_ptr()).collect();
            let payload_lens: Vec<usize> = batch.iter().map(|(_, p)| p.len()).collect();

            let result = ffi::bindings::ozks_insert_batch(
                self.handle,
                keys.as_ptr() as *const *const u8,
                key_lens.as_ptr(),
                payloads.as_ptr() as *const *const u8,
                payload_lens.as_ptr(),
                batch.len(),
            );

            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to insert batch: error code {}",
                    result
                ))));
            }

            Ok(())
        }
    }

    /// Flush to storage backend
    pub fn flush(&mut self) -> Result<(), Box<dyn Error>> {
        unsafe {
            let result = ffi::bindings::ozks_flush(self.handle);
            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to flush: error code {}",
                    result
                ))));
            }
            Ok(())
        }
    }

    /// Save OZKS metadata to bytes
    pub fn save(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        unsafe {
            // First call to get required size
            let mut size: usize = 0;
            let result = ffi::bindings::ozks_save(self.handle, std::ptr::null_mut(), &mut size);

            if result != -1 && size == 0 {
                return Ok(Vec::new());
            }

            // Allocate buffer and get data
            let mut buf = vec![0u8; size];
            let result = ffi::bindings::ozks_save(self.handle, buf.as_mut_ptr(), &mut size);

            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to save OZKS: error code {}",
                    result
                ))));
            }

            buf.truncate(size);
            Ok(buf)
        }
    }

    /// Get commitment (root hash only)
    pub fn get_commitment(&self) -> Result<Commitment, Box<dyn Error>> {
        unsafe {
            let mut commitment = vec![0u8; 32];
            let mut size: usize = 32;

            let result =
                ffi::bindings::ozks_get_commitment(self.handle, commitment.as_mut_ptr(), &mut size);

            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to get commitment: error code {}",
                    result
                ))));
            }

            commitment.truncate(size);
            Ok(Commitment::new(commitment))
        }
    }

    /// Get the full serialized Commitment object (VRF public key + root hash)
    pub fn get_commitment_serialized(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        unsafe {
            // First call to get required size
            let mut size: usize = 0;
            let result = ffi::bindings::ozks_get_commitment_serialized(
                self.handle,
                std::ptr::null_mut(),
                &mut size,
            );

            if result != -1 && size == 0 {
                return Err(Box::new(OZKSError(
                    "Failed to get commitment serialized size".to_string(),
                )));
            }

            // Allocate buffer and get data
            let mut buf = vec![0u8; size];
            let result = ffi::bindings::ozks_get_commitment_serialized(
                self.handle,
                buf.as_mut_ptr(),
                &mut size,
            );

            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to get serialized commitment: error code {}",
                    result
                ))));
            }

            buf.truncate(size);
            Ok(buf)
        }
    }

    /// Query for a key (returns membership status only)
    pub fn query(&self, key: &[u8]) -> Result<QueryResult, Box<dyn Error>> {
        unsafe {
            let result = ffi::bindings::ozks_query(self.handle, key.as_ptr(), key.len());

            if result < 0 {
                return Err(Box::new(OZKSError(format!(
                    "Query failed: error code {}",
                    result
                ))));
            }

            Ok(QueryResult::new(result == 1))
        }
    }

    /// Query for a key and return the serialized QueryResult (full proof data)
    pub fn query_proof(&self, key: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
        unsafe {
            // First call to get required size
            let mut size: usize = 0;
            let result = ffi::bindings::ozks_query_proof(
                self.handle,
                key.as_ptr(),
                key.len(),
                std::ptr::null_mut(),
                &mut size,
            );

            if result != -1 && size == 0 {
                return Err(Box::new(OZKSError(
                    "Failed to get query proof size".to_string(),
                )));
            }

            // Allocate buffer and get data
            let mut buf = vec![0u8; size];
            let result = ffi::bindings::ozks_query_proof(
                self.handle,
                key.as_ptr(),
                key.len(),
                buf.as_mut_ptr(),
                &mut size,
            );

            if result != 0 {
                return Err(Box::new(OZKSError(format!(
                    "Failed to get query proof: error code {}",
                    result
                ))));
            }

            buf.truncate(size);
            Ok(buf)
        }
    }

    /// Load OZKS from serialized data
    pub fn load(
        data: &[u8],
        _storage: &SQLiteBatchStorage,
    ) -> Result<(Self, usize), Box<dyn Error>> {
        unsafe {
            let handle = ffi::bindings::ozks_load(data.as_ptr(), data.len(), std::ptr::null_mut());

            if handle == 0 {
                return Err(Box::new(OZKSError(
                    "Failed to load OZKS instance".to_string(),
                )));
            }

            let trie_id = ffi::bindings::ozks_get_id(handle) as i64;

            Ok((OZKS { handle, trie_id }, data.len()))
        }
    }
}

impl Drop for OZKS {
    fn drop(&mut self) {
        unsafe {
            ffi::bindings::ozks_destroy(self.handle);
        }
    }
}

/// Initialize the OZKS C++ backend with SQLite storage
pub fn init_sqlite_storage(db_path: &str) -> Result<(), Box<dyn Error>> {
    unsafe {
        let c_path = std::ffi::CString::new(db_path)?;
        ffi::bindings::ozks_init_sqlite(c_path.as_ptr());
    }
    Ok(())
}
