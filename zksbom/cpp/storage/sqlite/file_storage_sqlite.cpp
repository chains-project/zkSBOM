#include "file_storage_sqlite.h"
#include <sstream>
#include <stdexcept>
#include <cstring>
#include "gsl/span"

using namespace std;
using namespace ozks;
using namespace ozks::storage;

// ============================================================
// Construction / destruction
// ============================================================

SQLiteBatchStorage::SQLiteBatchStorage(const string& db_path)
    : db_(nullptr), db_path_(db_path)
{
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        throw runtime_error("Failed to open SQLite database: " + string(sqlite3_errmsg(db_)));
    }
    initialize_database();
}

SQLiteBatchStorage::~SQLiteBatchStorage()
{
    if (db_) {
        sqlite3_close(db_);
    }
}

void SQLiteBatchStorage::exec_sql(const char* sql)
{
    char* err_msg = nullptr;
    int rc = sqlite3_exec(db_, sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        string error = err_msg ? string(err_msg) : "Unknown error";
        sqlite3_free(err_msg);
        throw runtime_error("SQL error: " + error);
    }
}

void SQLiteBatchStorage::initialize_database()
{
    const char* schema = R"(
        CREATE TABLE IF NOT EXISTS ct_nodes (
            trie_id   INTEGER NOT NULL,
            label     BLOB    NOT NULL,
            data      BLOB    NOT NULL,
            PRIMARY KEY (trie_id, label)
        );

        CREATE TABLE IF NOT EXISTS compressed_tries (
            trie_id   INTEGER PRIMARY KEY,
            data      BLOB    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS store_elements (
            trie_id   INTEGER NOT NULL,
            key       BLOB    NOT NULL,
            payload   BLOB    NOT NULL,
            randomness BLOB   NOT NULL,
            PRIMARY KEY (trie_id, key)
        );

        CREATE TABLE IF NOT EXISTS ozks_data (
            trie_id   INTEGER PRIMARY KEY,
            data      BLOB    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS instance_manifest (
            instance_index  INTEGER PRIMARY KEY,
            trie_id         INTEGER NOT NULL,
            name            TEXT    NOT NULL
        );
    )";
    exec_sql(schema);
}

// ============================================================
// Instance manifest (maps creation order to trie_id)
// ============================================================

void SQLiteBatchStorage::save_instance_manifest(
    int instance_index,
    trie_id_type trie_id,
    const string& name)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql =
        "INSERT OR REPLACE INTO instance_manifest (instance_index, trie_id, name) "
        "VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_int(stmt, 1, instance_index);
    sqlite3_bind_int64(stmt, 2, trie_id);
    sqlite3_bind_text(stmt, 3, name.c_str(), -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

vector<pair<int, pair<trie_id_type, string>>> SQLiteBatchStorage::load_instance_manifest()
{
    vector<pair<int, pair<trie_id_type, string>>> result;
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT instance_index, trie_id, name FROM instance_manifest ORDER BY instance_index;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return result;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int idx = sqlite3_column_int(stmt, 0);
        trie_id_type tid = sqlite3_column_int64(stmt, 1);
        const char* name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
        result.push_back({idx, {tid, name ? string(name) : ""}});
    }
    sqlite3_finalize(stmt);
    return result;
}

// ============================================================
// PartialLabel helpers
// ============================================================

vector<byte> SQLiteBatchStorage::serialize_label(const PartialLabel& label)
{
    vector<byte> buf(PartialLabel::SaveSize);
    label.save(gsl::span<byte, PartialLabel::SaveSize>(buf.data(), buf.size()));
    return buf;
}

PartialLabel SQLiteBatchStorage::deserialize_label(const byte* data, size_t size)
{
    if (size != PartialLabel::SaveSize) {
        throw runtime_error("Invalid PartialLabel size");
    }
    PartialLabel label;
    // Create a mutable copy so we can pass a non-const span
    vector<byte> buf(data, data + size);
    label.load(gsl::span<byte, PartialLabel::SaveSize>(buf.data(), buf.size()));
    return label;
}

// ============================================================
// CTNode load / save
// ============================================================

bool SQLiteBatchStorage::load_ctnode(
    trie_id_type trie_id,
    const PartialLabel& node_id,
    shared_ptr<Storage> /* storage */,
    CTNodeStored& node)
{
    auto label_blob = serialize_label(node_id);

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT data FROM ct_nodes WHERE trie_id = ? AND label = ?;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_bind_blob(stmt, 2, label_blob.data(), label_blob.size(), SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt, 0);
        int sz = sqlite3_column_bytes(stmt, 0);
        if (data && sz > 0) {
            vector<byte> vec(static_cast<const byte*>(data), static_cast<const byte*>(data) + sz);
            auto [loaded_node, left_label, right_label, bytes_read] =
                CTNodeStored::Load(vec, nullptr, 0);
            node = CTNodeStored(nullptr, loaded_node.label(), loaded_node.hash(),
                                left_label, right_label);
            found = true;
        }
    }

    sqlite3_finalize(stmt);
    return found;
}

void SQLiteBatchStorage::save_ctnode(trie_id_type trie_id, const CTNodeStored& node)
{
    auto label_blob = serialize_label(node.label());

    // Serialize the node
    vector<byte> node_data;
    node.save(node_data);

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO ct_nodes (trie_id, label, data) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_bind_blob(stmt, 2, label_blob.data(), label_blob.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, node_data.data(), node_data.size(), SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ============================================================
// CompressedTrie load / save
// ============================================================

bool SQLiteBatchStorage::load_compressed_trie(trie_id_type trie_id, CompressedTrie& trie)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT data FROM compressed_tries WHERE trie_id = ?;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, trie_id);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* data = sqlite3_column_blob(stmt, 0);
        int sz = sqlite3_column_bytes(stmt, 0);
        if (data && sz > 0) {
            vector<byte> vec(static_cast<const byte*>(data), static_cast<const byte*>(data) + sz);
            auto [loaded_trie, bytes_read] = CompressedTrie::Load(vec, nullptr, 0);
            if (loaded_trie) {
                trie = *loaded_trie;
                found = true;
            }
        }
    }

    sqlite3_finalize(stmt);
    return found;
}

void SQLiteBatchStorage::save_compressed_trie(const CompressedTrie& trie)
{
    vector<byte> trie_data;
    trie.save(trie_data);

    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO compressed_tries (trie_id, data) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_int64(stmt, 1, trie.id());
    sqlite3_bind_blob(stmt, 2, trie_data.data(), trie_data.size(), SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ============================================================
// Store element load / save
// ============================================================

bool SQLiteBatchStorage::load_store_element(
    trie_id_type trie_id,
    const vector<byte>& key,
    store_value_type& value)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT payload, randomness FROM store_elements WHERE trie_id = ? AND key = ?;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_bind_blob(stmt, 2, key.data(), key.size(), SQLITE_STATIC);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* payload_data = sqlite3_column_blob(stmt, 0);
        int payload_sz = sqlite3_column_bytes(stmt, 0);
        const void* rand_data = sqlite3_column_blob(stmt, 1);
        int rand_sz = sqlite3_column_bytes(stmt, 1);

        if (payload_data && rand_data && rand_sz == static_cast<int>(randomness_size)) {
            value.payload.assign(
                static_cast<const byte*>(payload_data),
                static_cast<const byte*>(payload_data) + payload_sz);
            memcpy(value.randomness.data(), rand_data, randomness_size);
            found = true;
        }
    }

    sqlite3_finalize(stmt);
    return found;
}

void SQLiteBatchStorage::save_store_element(
    trie_id_type trie_id,
    const vector<byte>& key,
    const store_value_type& value)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql =
        "INSERT OR REPLACE INTO store_elements (trie_id, key, payload, randomness) "
        "VALUES (?, ?, ?, ?);";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_bind_blob(stmt, 2, key.data(), key.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, value.payload.data(), value.payload.size(), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 4, value.randomness.data(), value.randomness.size(), SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
}

// ============================================================
// Flush
// ============================================================

void SQLiteBatchStorage::flush(trie_id_type)
{
    // Single-element flush: nothing special needed
}

void SQLiteBatchStorage::flush(
    trie_id_type trie_id,
    const vector<CTNodeStored>& nodes,
    const vector<CompressedTrie>& tries,
    const vector<pair<vector<byte>, store_value_type>>& store_elements)
{
    exec_sql("BEGIN TRANSACTION;");

    for (const auto& node : nodes) {
        save_ctnode(trie_id, node);
    }

    for (const auto& trie : tries) {
        save_compressed_trie(trie);
    }

    for (const auto& [key, value] : store_elements) {
        save_store_element(trie_id, key, value);
    }

    exec_sql("COMMIT;");
}

// ============================================================
// Add methods (for populating storage with existing data)
// ============================================================

void SQLiteBatchStorage::add_ctnode(trie_id_type trie_id, const CTNodeStored& node)
{
    save_ctnode(trie_id, node);
}

void SQLiteBatchStorage::add_compressed_trie(const CompressedTrie& trie)
{
    save_compressed_trie(trie);
}

void SQLiteBatchStorage::add_store_element(
    trie_id_type trie_id,
    const vector<byte>& key,
    const store_value_type& value)
{
    save_store_element(trie_id, key, value);
}

// ============================================================
// Epoch / utility methods
// ============================================================

size_t SQLiteBatchStorage::get_compressed_trie_epoch(trie_id_type trie_id)
{
    CompressedTrie trie;
    if (load_compressed_trie(trie_id, trie)) {
        return trie.epoch();
    }
    return 0;
}

void SQLiteBatchStorage::load_updated_elements(
    size_t /* epoch */,
    trie_id_type /* trie_id */,
    shared_ptr<Storage> /* storage */)
{
    // Not needed for this implementation
}

void SQLiteBatchStorage::delete_ozks(trie_id_type trie_id)
{
    exec_sql("BEGIN TRANSACTION;");

    sqlite3_stmt* stmt = nullptr;

    const char* del_nodes = "DELETE FROM ct_nodes WHERE trie_id = ?;";
    sqlite3_prepare_v2(db_, del_nodes, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const char* del_tries = "DELETE FROM compressed_tries WHERE trie_id = ?;";
    sqlite3_prepare_v2(db_, del_tries, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const char* del_store = "DELETE FROM store_elements WHERE trie_id = ?;";
    sqlite3_prepare_v2(db_, del_store, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    const char* del_ozks = "DELETE FROM ozks_data WHERE trie_id = ?;";
    sqlite3_prepare_v2(db_, del_ozks, -1, &stmt, nullptr);
    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    exec_sql("COMMIT;");
}

// ============================================================
// OZKS instance data (VRF key + metadata)
// ============================================================

bool SQLiteBatchStorage::save_ozks_data(
    trie_id_type trie_id,
    const vector<byte>& data)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "INSERT OR REPLACE INTO ozks_data (trie_id, data) VALUES (?, ?);";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, trie_id);
    sqlite3_bind_blob(stmt, 2, data.data(), data.size(), SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool SQLiteBatchStorage::load_ozks_data(
    trie_id_type trie_id,
    vector<byte>& data)
{
    sqlite3_stmt* stmt = nullptr;
    const char* sql = "SELECT data FROM ozks_data WHERE trie_id = ?;";
    if (sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_int64(stmt, 1, trie_id);

    bool found = false;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const void* blob = sqlite3_column_blob(stmt, 0);
        int sz = sqlite3_column_bytes(stmt, 0);
        if (blob && sz > 0) {
            data.assign(static_cast<const byte*>(blob),
                        static_cast<const byte*>(blob) + sz);
            found = true;
        }
    }

    sqlite3_finalize(stmt);
    return found;
}
