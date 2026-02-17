# SQLite Storage Backend

SQLite-based persistent storage for OZKS instance state and merkle tree node data.

## Overview

`file_storage_sqlite.h` and `file_storage_sqlite.cpp` implement storage operations using SQLite as the underlying database engine.

## Functionality

### Database Initialization
- Creates database file if it doesn't exist
- Initializes required tables for storing:
  - Merkle tree nodes (key-value pairs with metadata)
  - OZKS instance state and configuration
  - Commitment history

### Key Operations
- **Store**: Persist key-value pairs (nodes) with timestamps
- **Retrieve**: Query nodes by key with consistency guarantees
- **Update**: Modify existing node values
- **Delete**: Remove nodes if needed
- **Batch Operations**: Efficiently store/retrieve multiple nodes

### Data Persistence
- ACID transactions ensure consistency
- Crash-safe: Uncommitted changes are rolled back
- Suitable for long-running processes with periodic checkpoints

## Database Schema

Tables created by this backend:
- `nodes` - Merkle tree nodes (key, value, timestamp, metadata)
- `instances` - OZKS instance metadata (instance_id, commitment, state)
- `metadata` - Storage configuration and version info

## Configuration

SQLite storage typically requires:
- Database file path
- Optional: WAL (Write-Ahead Logging) mode for better concurrency
- Optional: Page size and cache size tuning

## Performance Characteristics

- **Throughput**: Good for moderate insert rates (1K-10K ops/sec depending on fsync policy)
- **Latency**: Low latency with WAL mode enabled
- **Storage**: Disk-space efficient with compression
- **Concurrent Reads**: Multiple readers supported (WAL mode)
- **Concurrent Writes**: Serialized (single writer at a time)

## Limitations

- **Single-machine only**: No distributed capability
- **Write throughput**: Limited by single-writer model
- **Large datasets**: Suitable up to ~1TB with proper indexing
- **Network access**: Not suitable for network-shared storage (NFS stability issues)

## Compilation

Compiled as part of `ozks_wrapper` static library. Depends on:
- SQLite3 C library (bundled by rusqlite Rust crate)
- Standard C++ library

## Future Optimizations

- Index optimization for common query patterns
- Connection pooling for concurrent access
- Incremental backup support
- Read-only replica support

See `../README.md` for storage backend architecture and design pattern.
