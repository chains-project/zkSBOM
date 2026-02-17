// C FFI Wrapper for oZKS
// Provides simple C-compatible interfaces to the C++ oZKS library
// This allows Rust code to call oZKS functionality through FFI

#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle types
typedef uint64_t OZKSHandle;
typedef uint64_t TrieId;

// ============================================================
// SQLite Storage Initialization
// ============================================================

/**
 * Initialize the SQLite storage backend for OZKS persistence.
 * This must be called once before creating any OZKS instances.
 *
 * @param db_path Path to the SQLite database file
 */
void ozks_init_sqlite(const char* db_path);

// ============================================================
// OZKS Instance Management
// ============================================================

/**
 * Create a new OZKS instance with the given configuration.
 *
 * @param payload_commitment_type 0 = Uncommitted, 1 = Committed
 * @param label_type 0 = VRFLabels, 1 = HashedLabels
 * @param trie_type 0 = Stored, 1 = Linked, 2 = LinkedNoStorage
 * @param storage_ptr Pointer to a Storage backend (cast from Rust)
 * @return Handle to the OZKS instance, or 0 on error
 */
OZKSHandle ozks_create(
    uint32_t payload_commitment_type,
    uint32_t label_type,
    uint32_t trie_type,
    void* storage_ptr);

/**
 * Get the trie ID of an OZKS instance.
 *
 * @param handle The OZKS instance handle
 * @return The trie ID
 */
TrieId ozks_get_id(OZKSHandle handle);

/**
 * Destroy an OZKS instance and free its resources.
 *
 * @param handle The OZKS instance handle
 */
void ozks_destroy(OZKSHandle handle);

// ============================================================
// Insert Operations
// ============================================================

/**
 * Insert a batch of key-value pairs into the OZKS instance.
 *
 * @param handle The OZKS instance handle
 * @param keys Array of key byte arrays
 * @param key_lens Array of key lengths
 * @param payloads Array of payload byte arrays
 * @param payload_lens Array of payload lengths
 * @param count Number of key-value pairs
 * @return 0 on success, non-zero on error
 */
int ozks_insert_batch(
    OZKSHandle handle,
    const uint8_t* const* keys,
    const size_t* key_lens,
    const uint8_t* const* payloads,
    const size_t* payload_lens,
    size_t count);

/**
 * Flush pending insertions to the storage backend.
 *
 * @param handle The OZKS instance handle
 * @return 0 on success, non-zero on error
 */
int ozks_flush(OZKSHandle handle);

// ============================================================
// Query Operations
// ============================================================

/**
 * Query for a key in the OZKS instance.
 *
 * @param handle The OZKS instance handle
 * @param key The key bytes
 * @param key_len Length of the key
 * @return 1 if the key is found (is_member), 0 if not found, -1 on error
 */
int ozks_query(OZKSHandle handle, const uint8_t* key, size_t key_len);

// ============================================================
// Commitment Operations
// ============================================================

/**
 * Get the current commitment of the OZKS instance.
 * The commitment is a 32-byte hash.
 *
 * @param handle The OZKS instance handle
 * @param out_buf Output buffer for the commitment (must be at least 32 bytes)
 * @param out_len Will be set to the commitment size (32)
 * @return 0 on success, non-zero on error
 */
int ozks_get_commitment(OZKSHandle handle, uint8_t* out_buf, size_t* out_len);

// ============================================================
// Serialization
// ============================================================

/**
 * Serialize the OZKS instance to a byte buffer.
 *
 * @param handle The OZKS instance handle
 * @param out_buf Output buffer for serialized data
 * @param out_len Input: buffer size, Output: bytes written
 * @return 0 on success, -1 if buffer too small, other error codes on failure
 */
int ozks_save(OZKSHandle handle, uint8_t* out_buf, size_t* out_len);

/**
 * Deserialize and load an OZKS instance from a byte buffer.
 *
 * @param data Serialized OZKS data
 * @param len Length of the data
 * @param storage_ptr Pointer to a Storage backend
 * @return Handle to the loaded OZKS instance, or 0 on error
 */
OZKSHandle ozks_load(const uint8_t* data, size_t len, void* storage_ptr);

// ============================================================
// VRF Key Management
// ============================================================

/**
 * Get the VRF secret key for serialization.
 * The key is 32 bytes.
 *
 * @param handle The OZKS instance handle
 * @param out_buf Output buffer for the VRF key
 * @param out_len Will be set to the key size
 * @return 0 on success, non-zero on error
 */
int ozks_get_vrf_secret_key(OZKSHandle handle, uint8_t* out_buf, size_t* out_len);

/**
 * Set the VRF secret key for restoration.
 *
 * @param handle The OZKS instance handle
 * @param key VRF key bytes
 * @param key_len Length of the key
 * @return 0 on success, non-zero on error
 */
int ozks_set_vrf_secret_key(OZKSHandle handle, const uint8_t* key, size_t key_len);

// ============================================================
// Serialized Commitment and Proof Operations
// ============================================================

/**
 * Get the full serialized Commitment object (VRF public key + root hash).
 * Uses two-call pattern: first call with out_buf=NULL to get required size,
 * then call again with allocated buffer.
 *
 * @param handle The OZKS instance handle
 * @param out_buf Output buffer for serialized commitment (NULL to query size)
 * @param out_len Input: buffer size, Output: bytes written/required
 * @return 0 on success, -1 if buffer too small or NULL (size written to out_len)
 */
int ozks_get_commitment_serialized(OZKSHandle handle, uint8_t* out_buf, size_t* out_len);

/**
 * Query for a key and return the serialized QueryResult (full proof data).
 * Uses two-call pattern: first call with out_buf=NULL to get required size,
 * then call again with allocated buffer.
 *
 * @param handle The OZKS instance handle
 * @param key The key bytes to query
 * @param key_len Length of the key
 * @param out_buf Output buffer for serialized QueryResult (NULL to query size)
 * @param out_len Input: buffer size, Output: bytes written/required
 * @return 0 on success, -1 if buffer too small or NULL (size written to out_len), -2 on error
 */
int ozks_query_proof(OZKSHandle handle, const uint8_t* key, size_t key_len,
                     uint8_t* out_buf, size_t* out_len);

#ifdef __cplusplus
}
#endif
