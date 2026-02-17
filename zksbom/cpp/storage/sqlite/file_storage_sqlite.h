// Implements the full BatchStorage interface, persisting all trie nodes,
// compressed tries, and store elements to SQLite.
// This enables exact state recovery including identical commitments.

#pragma once

#include <string>
#include <memory>
#include <vector>
#include <sqlite3.h>

#include "oZKS/storage/batch_storage.h"
#include "oZKS/compressed_trie.h"
#include "oZKS/ct_node_stored.h"

namespace ozks {
    namespace storage {
        class SQLiteBatchStorage : public BatchStorage {
        public:
            explicit SQLiteBatchStorage(const std::string& db_path);
            virtual ~SQLiteBatchStorage();

            // --- Storage interface ---

            bool load_ctnode(
                trie_id_type trie_id,
                const PartialLabel& node_id,
                std::shared_ptr<Storage> storage,
                CTNodeStored& node) override;

            void save_ctnode(trie_id_type trie_id, const CTNodeStored& node) override;

            bool load_compressed_trie(trie_id_type trie_id, CompressedTrie& trie) override;

            void save_compressed_trie(const CompressedTrie& trie) override;

            bool load_store_element(
                trie_id_type trie_id,
                const std::vector<std::byte>& key,
                store_value_type& value) override;

            void save_store_element(
                trie_id_type trie_id,
                const std::vector<std::byte>& key,
                const store_value_type& value) override;

            void flush(trie_id_type trie_id) override;

            // --- BatchStorage interface ---

            void flush(
                trie_id_type trie_id,
                const std::vector<CTNodeStored>& nodes,
                const std::vector<CompressedTrie>& tries,
                const std::vector<std::pair<std::vector<std::byte>, store_value_type>>&
                    store_elements) override;

            void add_ctnode(trie_id_type trie_id, const CTNodeStored& node) override;

            void add_compressed_trie(const CompressedTrie& trie) override;

            void add_store_element(
                trie_id_type trie_id,
                const std::vector<std::byte>& key,
                const store_value_type& value) override;

            std::size_t get_compressed_trie_epoch(trie_id_type trie_id) override;

            void load_updated_elements(
                std::size_t epoch,
                trie_id_type trie_id,
                std::shared_ptr<Storage> storage) override;

            void delete_ozks(trie_id_type trie_id) override;

            // --- OZKS instance serialization (for VRF key + metadata) ---

            bool save_ozks_data(trie_id_type trie_id, const std::vector<std::byte>& data);
            bool load_ozks_data(trie_id_type trie_id, std::vector<std::byte>& data);

            // --- Instance manifest (maps creation order to trie_id) ---

            void save_instance_manifest(int instance_index, trie_id_type trie_id, const std::string& name);
            std::vector<std::pair<int, std::pair<trie_id_type, std::string>>> load_instance_manifest();

        private:
            sqlite3* db_;
            std::string db_path_;

            void initialize_database();
            void exec_sql(const char* sql);

            // Serialize PartialLabel to fixed 36-byte blob
            std::vector<std::byte> serialize_label(const PartialLabel& label);
            PartialLabel deserialize_label(const std::byte* data, std::size_t size);
        };
    } // namespace storage
} // namespace ozks
