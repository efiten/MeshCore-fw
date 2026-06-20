#pragma once

#include <stdint.h>
#include <string.h>

// This unit is intentionally free of MeshCore/firmware dependencies so the
// matching logic can be unit-tested on the `native` env. When included from the
// firmware, PUB_KEY_SIZE is already defined by MeshCore.h.
#ifndef PUB_KEY_SIZE
#define PUB_KEY_SIZE 32
#endif

#ifndef FILTER_NODE_COUNT
#define FILTER_NODE_COUNT 16
#endif

struct BlockedNode {
  uint8_t key[PUB_KEY_SIZE];
  uint8_t key_len;   // significant bytes (1..PUB_KEY_SIZE); 0 == empty slot

  BlockedNode() : key_len(0) { memset(key, 0, sizeof(key)); }
};

namespace NodeBlock {

  // True if `entry` matches the leading bytes of `cand`. Node identities only
  // ever appear on the wire as a prefix of the public key (1-byte path/src
  // hashes, full key in adverts), so a match compares min(entry.key_len,
  // cand_len) bytes. Both lengths must be non-zero.
  inline bool keyMatches(const BlockedNode& entry, const uint8_t* cand, uint8_t cand_len) {
    if (entry.key_len == 0 || cand == nullptr || cand_len == 0) return false;
    uint8_t n = (entry.key_len < cand_len) ? entry.key_len : cand_len;
    return memcmp(entry.key, cand, n) == 0;
  }

  // True if any entry in the list matches `cand`.
  inline bool inList(const BlockedNode* list, int count, const uint8_t* cand, uint8_t cand_len) {
    if (list == nullptr) return false;
    for (int i = 0; i < count; i++) {
      if (keyMatches(list[i], cand, cand_len)) return true;
    }
    return false;
  }

  // True if any hop in a flood path matches a blocked node. `path` holds
  // `hop_count` hashes, each `hash_size` bytes wide.
  inline bool matchesPath(const BlockedNode* list, int count,
                          const uint8_t* path, uint8_t hop_count, uint8_t hash_size) {
    if (path == nullptr || hop_count == 0 || hash_size == 0) return false;
    for (uint8_t h = 0; h < hop_count; h++) {
      if (inList(list, count, &path[(uint16_t)h * hash_size], hash_size)) return true;
    }
    return false;
  }

  inline bool isEmpty(const BlockedNode* list, int count) {
    for (int i = 0; i < count; i++) {
      if (list[i].key_len != 0) return false;
    }
    return true;
  }

  // Store a key prefix in the first empty slot. Returns false if invalid or full.
  inline bool add(BlockedNode* list, int count, const uint8_t* key, uint8_t key_len) {
    if (key == nullptr || key_len == 0 || key_len > PUB_KEY_SIZE) return false;
    for (int i = 0; i < count; i++) {
      if (list[i].key_len == 0) {
        memset(list[i].key, 0, PUB_KEY_SIZE);
        memcpy(list[i].key, key, key_len);
        list[i].key_len = key_len;
        return true;
      }
    }
    return false;  // full
  }

  // Remove the entry that exactly equals (key, key_len). This is an exact-entry
  // operation, not a prefix match. Returns false if not found.
  inline bool remove(BlockedNode* list, int count, const uint8_t* key, uint8_t key_len) {
    if (key == nullptr || key_len == 0) return false;
    for (int i = 0; i < count; i++) {
      if (list[i].key_len == key_len && memcmp(list[i].key, key, key_len) == 0) {
        memset(list[i].key, 0, PUB_KEY_SIZE);
        list[i].key_len = 0;
        return true;
      }
    }
    return false;
  }
}
