#include <gtest/gtest.h>

// Header-only matching logic for the repeater packet filter's node blocklist.
#include "../../examples/simple_repeater/NodeBlocklist.h"

// Helper: build a 32-byte key whose bytes are a fixed pattern starting at `first`.
static void makeKey(uint8_t* out, uint8_t first) {
  for (int i = 0; i < PUB_KEY_SIZE; i++) out[i] = (uint8_t)(first + i);
}

// ---- keyMatches -------------------------------------------------------------

TEST(NodeBlockKeyMatches, EmptyEntryNeverMatches) {
  BlockedNode entry;  // key_len == 0
  uint8_t cand[PUB_KEY_SIZE];
  makeKey(cand, 0x10);
  EXPECT_FALSE(NodeBlock::keyMatches(entry, cand, PUB_KEY_SIZE));
}

TEST(NodeBlockKeyMatches, ExactFullKeyMatches) {
  BlockedNode entry;
  makeKey(entry.key, 0x10);
  entry.key_len = PUB_KEY_SIZE;

  uint8_t cand[PUB_KEY_SIZE];
  makeKey(cand, 0x10);
  EXPECT_TRUE(NodeBlock::keyMatches(entry, cand, PUB_KEY_SIZE));
}

TEST(NodeBlockKeyMatches, FullKeyDiffersInLastByteDoesNotMatch) {
  BlockedNode entry;
  makeKey(entry.key, 0x10);
  entry.key_len = PUB_KEY_SIZE;

  uint8_t cand[PUB_KEY_SIZE];
  makeKey(cand, 0x10);
  cand[PUB_KEY_SIZE - 1] ^= 0xFF;  // flip last byte
  EXPECT_FALSE(NodeBlock::keyMatches(entry, cand, PUB_KEY_SIZE));
}

TEST(NodeBlockKeyMatches, ShortStoredKeyMatchesLongerCandidatePrefix) {
  // Stored 1-byte prefix should match any candidate sharing that first byte.
  BlockedNode entry;
  entry.key[0] = 0x10;
  entry.key_len = 1;

  uint8_t cand[PUB_KEY_SIZE];
  makeKey(cand, 0x10);  // first byte 0x10
  EXPECT_TRUE(NodeBlock::keyMatches(entry, cand, PUB_KEY_SIZE));
}

TEST(NodeBlockKeyMatches, FullStoredKeyMatchesOneByteCandidateOnPrefix) {
  // A 1-byte src_hash candidate only has 1 byte; match on the shared prefix byte.
  BlockedNode entry;
  makeKey(entry.key, 0x10);
  entry.key_len = PUB_KEY_SIZE;

  uint8_t src_hash = 0x10;
  EXPECT_TRUE(NodeBlock::keyMatches(entry, &src_hash, 1));
}

TEST(NodeBlockKeyMatches, FullStoredKeyDoesNotMatchDifferentOneByteCandidate) {
  BlockedNode entry;
  makeKey(entry.key, 0x10);
  entry.key_len = PUB_KEY_SIZE;

  uint8_t src_hash = 0x99;
  EXPECT_FALSE(NodeBlock::keyMatches(entry, &src_hash, 1));
}

TEST(NodeBlockKeyMatches, ZeroLengthCandidateNeverMatches) {
  BlockedNode entry;
  makeKey(entry.key, 0x10);
  entry.key_len = PUB_KEY_SIZE;

  uint8_t cand[1] = {0x10};
  EXPECT_FALSE(NodeBlock::keyMatches(entry, cand, 0));
}

// ---- inList -----------------------------------------------------------------

TEST(NodeBlockInList, FindsMatchAmongEntriesAndSkipsEmpty) {
  BlockedNode list[FILTER_NODE_COUNT];
  // slot 0 empty, slot 1 has key prefix 0x42, rest empty
  list[1].key[0] = 0x42;
  list[1].key_len = 1;

  uint8_t cand_hit = 0x42;
  uint8_t cand_miss = 0x43;
  EXPECT_TRUE(NodeBlock::inList(list, FILTER_NODE_COUNT, &cand_hit, 1));
  EXPECT_FALSE(NodeBlock::inList(list, FILTER_NODE_COUNT, &cand_miss, 1));
}

TEST(NodeBlockInList, EmptyListMatchesNothing) {
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t cand = 0x10;
  EXPECT_FALSE(NodeBlock::inList(list, FILTER_NODE_COUNT, &cand, 1));
}

// ---- matchesPath ------------------------------------------------------------

TEST(NodeBlockMatchesPath, MatchesHopAnywhere) {
  BlockedNode list[FILTER_NODE_COUNT];
  list[0].key[0] = 0xAA;
  list[0].key_len = 1;

  // path of 1-byte hops
  uint8_t path_first[]  = {0xAA, 0x01, 0x02};
  uint8_t path_middle[] = {0x01, 0xAA, 0x02};
  uint8_t path_last[]   = {0x01, 0x02, 0xAA};
  uint8_t path_none[]   = {0x01, 0x02, 0x03};

  EXPECT_TRUE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_first, 3, 1));
  EXPECT_TRUE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_middle, 3, 1));
  EXPECT_TRUE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_last, 3, 1));
  EXPECT_FALSE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_none, 3, 1));
}

TEST(NodeBlockMatchesPath, ZeroHopsMatchesNothing) {
  BlockedNode list[FILTER_NODE_COUNT];
  list[0].key[0] = 0xAA;
  list[0].key_len = 1;
  uint8_t path[] = {0xAA};
  EXPECT_FALSE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path, 0, 1));
}

TEST(NodeBlockMatchesPath, TwoByteHashHopsCompareTwoBytes) {
  BlockedNode list[FILTER_NODE_COUNT];
  list[0].key[0] = 0xAA;
  list[0].key[1] = 0xBB;
  list[0].key_len = 2;

  // hops are 2 bytes wide: {0xAA,0x00} should NOT match (second byte differs),
  // {0xAA,0xBB} should match.
  uint8_t path_partial[] = {0xAA, 0x00, 0x11, 0x22};  // 2 hops
  uint8_t path_full[]    = {0x11, 0x22, 0xAA, 0xBB};  // 2 hops, match on hop 2
  EXPECT_FALSE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_partial, 2, 2));
  EXPECT_TRUE(NodeBlock::matchesPath(list, FILTER_NODE_COUNT, path_full, 2, 2));
}

// ---- add / remove / isEmpty -------------------------------------------------

TEST(NodeBlockAddRemove, AddFillsSlotsThenReportsFull) {
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t key[1];
  for (int i = 0; i < FILTER_NODE_COUNT; i++) {
    key[0] = (uint8_t)i;
    EXPECT_TRUE(NodeBlock::add(list, FILTER_NODE_COUNT, key, 1));
  }
  key[0] = 0xFF;
  EXPECT_FALSE(NodeBlock::add(list, FILTER_NODE_COUNT, key, 1));  // full
}

TEST(NodeBlockAddRemove, AddRejectsInvalidLength) {
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t key[PUB_KEY_SIZE + 1] = {0};
  EXPECT_FALSE(NodeBlock::add(list, FILTER_NODE_COUNT, key, 0));               // zero len
  EXPECT_FALSE(NodeBlock::add(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE + 1)); // too long
}

TEST(NodeBlockAddRemove, AddThenMatchThenRemoveThenNoMatch) {
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t key[PUB_KEY_SIZE];
  makeKey(key, 0x70);

  EXPECT_TRUE(NodeBlock::isEmpty(list, FILTER_NODE_COUNT));
  ASSERT_TRUE(NodeBlock::add(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE));
  EXPECT_FALSE(NodeBlock::isEmpty(list, FILTER_NODE_COUNT));

  uint8_t cand = 0x70;  // first byte
  EXPECT_TRUE(NodeBlock::inList(list, FILTER_NODE_COUNT, &cand, 1));

  ASSERT_TRUE(NodeBlock::remove(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE));
  EXPECT_FALSE(NodeBlock::inList(list, FILTER_NODE_COUNT, &cand, 1));
  EXPECT_TRUE(NodeBlock::isEmpty(list, FILTER_NODE_COUNT));
}

TEST(NodeBlockAddRemove, RemoveNonexistentReturnsFalse) {
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t key[PUB_KEY_SIZE];
  makeKey(key, 0x70);
  EXPECT_FALSE(NodeBlock::remove(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE));
}

TEST(NodeBlockAddRemove, RemoveRequiresExactStoredLength) {
  // Adding a full key and trying to remove with only a 1-byte prefix must fail:
  // remove is an exact-entry operation, not a prefix match.
  BlockedNode list[FILTER_NODE_COUNT];
  uint8_t key[PUB_KEY_SIZE];
  makeKey(key, 0x70);
  ASSERT_TRUE(NodeBlock::add(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE));

  uint8_t prefix = 0x70;
  EXPECT_FALSE(NodeBlock::remove(list, FILTER_NODE_COUNT, &prefix, 1));
  EXPECT_TRUE(NodeBlock::remove(list, FILTER_NODE_COUNT, key, PUB_KEY_SIZE));
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
