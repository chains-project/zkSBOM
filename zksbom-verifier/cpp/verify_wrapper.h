// C FFI Wrapper for oZKS Verification
// Provides a simple C-compatible interface for verifying oZKS proofs
// No database or OZKS instance management required — verification only

#pragma once

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify an oZKS proof against a commitment.
 *
 * Takes serialized Commitment and QueryResult byte arrays (deserialized from hex),
 * deserializes them using the oZKS library, and verifies the proof.
 * Optionally extracts the key from the proof for caller-side verification.
 *
 * @param commitment_bytes Serialized Commitment object bytes
 * @param commitment_len Length of commitment bytes
 * @param proof_bytes Serialized QueryResult object bytes
 * @param proof_len Length of proof bytes
 * @param out_key Output buffer for the key embedded in the proof (NULL to skip)
 * @param out_key_len Input: buffer size, Output: actual key size
 * @return 0 = valid and key is member,
 *         1 = valid but key is not member,
 *         2 = not valid,
 *        -1 = error (deserialization or other failure)
 */
int ozks_verify_proof(
    const uint8_t* commitment_bytes, size_t commitment_len,
    const uint8_t* proof_bytes, size_t proof_len,
    uint8_t* out_key, size_t* out_key_len);

#ifdef __cplusplus
}
#endif
