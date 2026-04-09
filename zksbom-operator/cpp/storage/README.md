# Storage Backend Architecture

This directory contains implementations for persisting OZKS state and data to various storage backends.

## Design Pattern

Storage backends follow a common interface pattern:
- Header file defines the storage interface
- Implementation file provides backend-specific logic
- All backends are compiled together and exposed through the FFI wrapper

## Current Backends

### sqlite/
SQLite-based persistent storage backend.

**Characteristics:**
- File-based database
- Good for single-machine deployments
- ACID compliance via SQLite
- Suitable for moderate data volumes

See `sqlite/README.md` for implementation details.

## Future Backend Ideas

### rocksdb/
High-performance embedded key-value store
- Usage: High-throughput, latency-sensitive applications
- Note: Would require RocksDB C library linking

### postgres/
Distributed SQL database backend
- Usage: Multi-node deployments
- Note: Would require PostgreSQL client library

### memory/
In-memory storage (no persistence)
- Usage: Testing, temporary data
- Note: Data lost on shutdown

## Adding a New Backend

To add a new storage backend:

1. Create a new subdirectory: `storage/[backend_name]/`
2. Implement `[backend_name]_storage.h` and `.cpp` with the storage interface
3. Update `build.rs` to compile the new backend:
   ```rust
   .file("cpp/storage/[backend_name]/[backend_name]_storage.cpp")
   ```
4. Add initialization function to FFI wrapper if needed
5. Document backend-specific behavior in a README

## Storage Interface Contract

All backends should expose functions following the pattern:
```c
// Initialize storage
int storage_init(const char* config);

// Store a node/entry
int storage_store(const char* key, const uint8_t* value, size_t value_len);

// Retrieve a node/entry
int storage_retrieve(const char* key, uint8_t* buffer, size_t* buffer_len);

// Close/cleanup storage
void storage_close(void);
```

## Current Status

**Implemented:** SQLite backend
**Planned:** None currently, but architecture supports easy expansion
