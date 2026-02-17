// C FFI Wrapper Implementation for oZKS Verification
// Standalone verification using the oZKS library — no database dependency

#include "verify_wrapper.h"
#include <iostream>
#include <vector>
#include <cstddef>
#include <cstring>

// oZKS includes
#include "oZKS/commitment.h"
#include "oZKS/query_result.h"
#include "oZKS/ozks_config.h"

extern "C" {

int ozks_verify_proof(
    const uint8_t* commitment_bytes, size_t commitment_len,
    const uint8_t* proof_bytes, size_t proof_len,
    uint8_t* out_key, size_t* out_key_len)
{
    try {
        // Deserialize commitment
        std::vector<std::byte> commitment_vec(
            reinterpret_cast<const std::byte*>(commitment_bytes),
            reinterpret_cast<const std::byte*>(commitment_bytes) + commitment_len
        );
        auto [commitment, bytes_read_c] = ozks::Commitment::Load(commitment_vec);

        // Create default config for deserialization
        // Default: CommitedPayload, VRFLabels, MemoryStorage (no database needed)
        ozks::OZKSConfig config;

        // Deserialize query result (proof)
        std::vector<std::byte> proof_vec(
            reinterpret_cast<const std::byte*>(proof_bytes),
            reinterpret_cast<const std::byte*>(proof_bytes) + proof_len
        );
        auto [query_result, bytes_read_q] = ozks::QueryResult::Load(config, proof_vec);

        // Extract the key from the proof if caller wants it
        if (out_key && out_key_len) {
            const auto& key = query_result.key();
            if (*out_key_len >= key.size()) {
                std::memcpy(out_key, key.data(), key.size());
            }
            *out_key_len = key.size();
        }

        // Verify proof against commitment
        auto result = query_result.verify(commitment);

        switch (result) {
            case ozks::QueryVerificationResult::ValidIsMember:
                return 0;
            case ozks::QueryVerificationResult::ValidNotMember:
                return 1;
            case ozks::QueryVerificationResult::NotValid:
                return 2;
            default:
                return -1;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_verify_proof: " << e.what() << std::endl;
        return -1;
    } catch (...) {
        std::cerr << "Unknown error in ozks_verify_proof" << std::endl;
        return -1;
    }
}

} // extern "C"
