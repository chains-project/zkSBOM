// C FFI Wrapper Implementation for oZKS
// Real integration with C++ oZKS library

#include "cpp_wrapper.h"
#include <iostream>
#include <memory>
#include <map>
#include <mutex>
#include <cstring>
#include <vector>
#include <cstdint>

// oZKS includes
#include "oZKS/ozks_config.h"
#include "oZKS/defines.h"
#include "oZKS/storage/memory_storage_batch_inserter.h"
#include "gsl/span"

// SQLite storage backend
#include "../storage/sqlite/file_storage_sqlite.h"

// Example OZKS wrapper
#include "ozks.h"

using namespace ozks;
using namespace ozks::storage;
using namespace ozks_simple;

// ============================================================
// Instance Management
// ============================================================

struct OZKSInstance {
    std::shared_ptr<OZKS> ozks;
    std::shared_ptr<SQLiteBatchStorage> storage;
    uint64_t trie_id;
};

static std::map<OZKSHandle, OZKSInstance> g_instances;
static OZKSHandle g_next_handle = 1;
static std::mutex g_instances_mutex;
static std::shared_ptr<SQLiteBatchStorage> g_sqlite_storage;

static OZKSHandle allocate_handle() {
    OZKSHandle handle = g_next_handle;
    g_next_handle++;
    if (g_next_handle == 0) g_next_handle = 1;
    return handle;
}

static OZKSInstance* get_instance(OZKSHandle handle) {
    auto it = g_instances.find(handle);
    if (it == g_instances.end()) return nullptr;
    return &it->second;
}

// ============================================================
// SQLite Storage Initialization
// ============================================================

void ozks_init_sqlite(const char* db_path) {
    try {
        if (!g_sqlite_storage) {
            g_sqlite_storage = std::make_shared<SQLiteBatchStorage>(db_path);
        }
    } catch (const std::exception& e) {
        std::cerr << "Error initializing SQLite storage: " << e.what() << std::endl;
    }
}

// ============================================================
// OZKS Instance Management
// ============================================================

OZKSHandle ozks_create(
    uint32_t payload_commitment_type,
    uint32_t label_type,
    uint32_t trie_type,
    void* /* storage_ptr */)
{
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);

        if (!g_sqlite_storage) {
            std::cerr << "Error in ozks_create: SQLite storage not initialized. Call ozks_init_sqlite first." << std::endl;
            return 0;
        }

        // Create batch inserter wrapping SQLite storage
        auto batch_inserter = std::make_shared<MemoryStorageBatchInserter>(g_sqlite_storage);

        // Create OZKS with the specified configuration
        OZKSConfig config{
            static_cast<PayloadCommitmentType>(payload_commitment_type),
            static_cast<LabelType>(label_type),
            static_cast<TrieType>(trie_type),
            batch_inserter
        };

        auto ozks = std::make_shared<OZKS>(config);

        OZKSHandle handle = allocate_handle();
        g_instances[handle] = {ozks, g_sqlite_storage, ozks->id()};

        return handle;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_create: " << e.what() << std::endl;
        return 0;
    }
}

TrieId ozks_get_id(OZKSHandle handle) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return 0;
        return inst->ozks->id();
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_get_id: " << e.what() << std::endl;
        return 0;
    }
}

void ozks_destroy(OZKSHandle handle) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        g_instances.erase(handle);
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_destroy: " << e.what() << std::endl;
    }
}

// ============================================================
// Insert Operations
// ============================================================

int ozks_insert_batch(
    OZKSHandle handle,
    const uint8_t* const* keys,
    const size_t* key_lens,
    const uint8_t* const* payloads,
    const size_t* payload_lens,
    size_t count)
{
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        key_payload_batch_type batch;
        for (size_t i = 0; i < count; i++) {
            if (!keys[i] || !payloads[i]) return -1;

            key_type key(
                reinterpret_cast<const std::byte*>(keys[i]),
                reinterpret_cast<const std::byte*>(keys[i]) + key_lens[i]
            );
            payload_type payload(
                reinterpret_cast<const std::byte*>(payloads[i]),
                reinterpret_cast<const std::byte*>(payloads[i]) + payload_lens[i]
            );
            batch.push_back({key, payload});
        }

        inst->ozks->insert(batch);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_insert_batch: " << e.what() << std::endl;
        return -1;
    }
}

int ozks_flush(OZKSHandle handle) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;
        inst->ozks->flush();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_flush: " << e.what() << std::endl;
        return -1;
    }
}

// ============================================================
// Query Operations
// ============================================================

int ozks_query(OZKSHandle handle, const uint8_t* key, size_t key_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        key_type k(
            reinterpret_cast<const std::byte*>(key),
            reinterpret_cast<const std::byte*>(key) + key_len
        );

        auto result = inst->ozks->query(k);
        return result.is_member() ? 1 : 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_query: " << e.what() << std::endl;
        return -1;
    }
}

// ============================================================
// Commitment Operations
// ============================================================

int ozks_get_commitment(OZKSHandle handle, uint8_t* out_buf, size_t* out_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        auto commitment = inst->ozks->get_commitment();
        auto root = commitment.root_commitment();

        if (!out_buf || *out_len < root.size()) {
            *out_len = root.size();
            return -1;
        }

        std::memcpy(out_buf, root.data(), root.size());
        *out_len = root.size();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_get_commitment: " << e.what() << std::endl;
        return -1;
    }
}

// ============================================================
// Serialization
// ============================================================

int ozks_save(OZKSHandle handle, uint8_t* out_buf, size_t* out_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        std::vector<std::byte> serialized;
        inst->ozks->save(serialized);

        if (!out_buf || *out_len < serialized.size()) {
            *out_len = serialized.size();
            return -1;
        }

        std::memcpy(out_buf, serialized.data(), serialized.size());
        *out_len = serialized.size();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_save: " << e.what() << std::endl;
        return -1;
    }
}

OZKSHandle ozks_load(const uint8_t* data, size_t len, void* /* storage_ptr */) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);

        if (!g_sqlite_storage) {
            std::cerr << "Error in ozks_load: SQLite storage not initialized. Call ozks_init_sqlite first." << std::endl;
            return 0;
        }

        std::vector<std::byte> vec(
            reinterpret_cast<const std::byte*>(data),
            reinterpret_cast<const std::byte*>(data) + len
        );

        // Create batch inserter wrapping SQLite storage
        auto batch_inserter = std::make_shared<MemoryStorageBatchInserter>(g_sqlite_storage);

        // Load OZKS from serialized data with SQLite storage backend
        auto [ozks, bytes_read] = OZKS::Load(batch_inserter, vec);

        OZKSHandle handle = allocate_handle();
        g_instances[handle] = {
            std::make_shared<OZKS>(ozks),
            g_sqlite_storage,
            ozks.id()
        };

        return handle;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_load: " << e.what() << std::endl;
        return 0;
    }
}

// ============================================================
// VRF Key Management
// ============================================================

int ozks_get_vrf_secret_key(OZKSHandle handle, uint8_t* out_buf, size_t* out_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        auto vrf_sk = inst->ozks->get_vrf_secret_key();

        // VRF secret key has a fixed save size
        constexpr size_t vrf_key_size = 32;  // Adjust if needed based on actual implementation
        std::array<std::byte, vrf_key_size> vrf_buf{};

        try {
            // Try to save to the fixed-size span
            vrf_sk.save(gsl::span<std::byte, vrf_key_size>(vrf_buf));

            if (!out_buf || *out_len < vrf_key_size) {
                *out_len = vrf_key_size;
                return -1;
            }

            std::memcpy(out_buf, vrf_buf.data(), vrf_key_size);
            *out_len = vrf_key_size;
            return 0;
        } catch (...) {
            // If save size is different, return 0 size
            *out_len = 0;
            return 0;
        }
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_get_vrf_secret_key: " << e.what() << std::endl;
        return -1;
    }
}

int ozks_set_vrf_secret_key(OZKSHandle handle, const uint8_t* key, size_t key_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -1;

        // Validate key size matches expected VRF key size
        constexpr size_t vrf_key_size = 32;
        if (key_len != vrf_key_size) {
            return -1;
        }

        VRFSecretKey vrf_sk;
        std::vector<std::byte> temp(
            reinterpret_cast<const std::byte*>(key),
            reinterpret_cast<const std::byte*>(key) + key_len
        );

        // Create a span from the vector data
        vrf_sk.load(gsl::span<const std::byte, vrf_key_size>(
            reinterpret_cast<const std::byte*>(temp.data()), vrf_key_size
        ));

        inst->ozks->set_vrf_secret_key(vrf_sk);
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_set_vrf_secret_key: " << e.what() << std::endl;
        return -1;
    }
}

// ============================================================
// Serialized Commitment and Proof Operations
// ============================================================

int ozks_get_commitment_serialized(OZKSHandle handle, uint8_t* out_buf, size_t* out_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -2;

        auto commitment = inst->ozks->get_commitment();

        std::vector<std::byte> serialized;
        commitment.save(serialized);

        if (!out_buf || *out_len < serialized.size()) {
            *out_len = serialized.size();
            return -1;
        }

        std::memcpy(out_buf, serialized.data(), serialized.size());
        *out_len = serialized.size();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_get_commitment_serialized: " << e.what() << std::endl;
        return -2;
    }
}

int ozks_query_proof(OZKSHandle handle, const uint8_t* key, size_t key_len,
                     uint8_t* out_buf, size_t* out_len) {
    try {
        std::lock_guard<std::mutex> lock(g_instances_mutex);
        auto inst = get_instance(handle);
        if (!inst) return -2;

        key_type k(
            reinterpret_cast<const std::byte*>(key),
            reinterpret_cast<const std::byte*>(key) + key_len
        );

        auto result = inst->ozks->query(k);

        std::vector<std::byte> serialized;
        result.save(serialized);

        if (!out_buf || *out_len < serialized.size()) {
            *out_len = serialized.size();
            return -1;
        }

        std::memcpy(out_buf, serialized.data(), serialized.size());
        *out_len = serialized.size();
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error in ozks_query_proof: " << e.what() << std::endl;
        return -2;
    }
}
