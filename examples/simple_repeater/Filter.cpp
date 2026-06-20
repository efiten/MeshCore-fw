#include "Filter.h"

bool Filter::allowPacketForward(const mesh::Packet* packet) {
  if (!_prefs.filter_enabled) return true;

  // do not filter direct
  if (packet->isRouteDirect()) return true;

  // blocked nodes (checked before priority so a blocked node cannot whitelist
  // itself via the ACL)
  if (isNodeBlocked(packet)) {
    _cnt.node++;
    return false;
  }

  // priority
  if (hasPriority(packet)) return true;

  // multi hash bytes
  if (packet->getPathHashSize() < _prefs.minimal_hash_bytes) {
    _cnt.hash++;
    return false;
  }

  uint8_t type = packet->getPayloadType();
  if (type < PAYLOAD_TYPE_COUNT) {
    // hops max
    if (packet->getPathHashCount() >= _prefs.payload_prefs[type].hops_max) {
      _cnt.hops[type]++;
      return false;
    }
    // rate limiter
    if (!_limiters[type].allow(_rtc->getCurrentTime())) {
      _cnt.rate[type]++;
      return false;
    }
  }

  // channels
  if (type == PAYLOAD_TYPE_GRP_TXT) {
    if (packet->payload_len <= PATH_HASH_SIZE + CIPHER_MAC_SIZE) return false;

    uint8_t channel_hash = packet->payload[0];

    // blocked
    for (int i=0; i<FILTER_CHANNEL_COUNT; i++) {
      ChannelDetails &ch = _prefs.filter_channels[i];
      if (ch.name[0] == '\0') continue;
      if (channel_hash == ch.channel.hash[0]) {
        _cnt.channel++;
        return false;
      }
    }

    // malformed
    if (_prefs.filter_malformed) {
      if (channel_hash == PUBLIC_CHANNEL_HASH) {
        uint8_t data[MAX_PACKET_PAYLOAD + 1];
        int len = mesh::Utils::MACThenDecrypt(PUBLIC_CHANNEL_SECRET, data, &packet->payload[PATH_HASH_SIZE], packet->payload_len - PATH_HASH_SIZE);
        if (!validMessageContent(data, len)) {
          _cnt.malformed++;
          return false;
        }
      }
    }
  }

  // allowed
  return true;
}

bool Filter::hasPriority(const mesh::Packet* packet) {
  uint8_t type = packet->getPayloadType();
  if (type != PAYLOAD_TYPE_REQ &&
      type != PAYLOAD_TYPE_RESPONSE &&
      type != PAYLOAD_TYPE_TXT_MSG &&
      type != PAYLOAD_TYPE_ANON_REQ &&
      type != PAYLOAD_TYPE_PATH) return false;

  if (packet->payload_len < 2) return false;

  uint8_t dst_hash = packet->payload[0];
  uint8_t src_hash = packet->payload[1];

  // check ACL contacts
  for (int i = 0; i < _acl->getNumClients(); i++) {
    ClientInfo* client = _acl->getClientByIdx(i);
    if (client->id.isHashMatch(&src_hash) || client->id.isHashMatch(&dst_hash)) return true;
  }
  return false;
}

bool Filter::isNodeBlocked(const mesh::Packet* packet) const {
  if (NodeBlock::isEmpty(_prefs.blocked_nodes, FILTER_NODE_COUNT)) return false;

  // transit: any repeater that already forwarded this flood packet appended its
  // own hash to the path
  uint8_t hop_count = packet->getPathHashCount();
  if (hop_count > 0) {
    if (NodeBlock::matchesPath(_prefs.blocked_nodes, FILTER_NODE_COUNT,
                               packet->path, hop_count, packet->getPathHashSize())) {
      return true;
    }
  }

  uint8_t type = packet->getPayloadType();

  // advert: the full public key is carried in payload[0..PUB_KEY_SIZE-1]
  if (type == PAYLOAD_TYPE_ADVERT) {
    if (packet->payload_len >= PUB_KEY_SIZE &&
        NodeBlock::inList(_prefs.blocked_nodes, FILTER_NODE_COUNT, packet->payload, PUB_KEY_SIZE)) {
      return true;
    }
  }

  // originator: src hash (payload[1]) for the identity-bearing payload types
  if (type == PAYLOAD_TYPE_REQ || type == PAYLOAD_TYPE_RESPONSE ||
      type == PAYLOAD_TYPE_TXT_MSG || type == PAYLOAD_TYPE_PATH) {
    if (packet->payload_len >= 2 &&
        NodeBlock::inList(_prefs.blocked_nodes, FILTER_NODE_COUNT, &packet->payload[1], 1)) {
      return true;
    }
  }

  return false;
}

bool Filter::addNode(const uint8_t* key, uint8_t key_len) {
  return NodeBlock::add(_prefs.blocked_nodes, FILTER_NODE_COUNT, key, key_len);
}

bool Filter::removeNode(const uint8_t* key, uint8_t key_len) {
  return NodeBlock::remove(_prefs.blocked_nodes, FILTER_NODE_COUNT, key, key_len);
}

void Filter::listNodeKeys(char* out_buf, size_t out_size) {
  if (out_buf == nullptr || out_size == 0) return;

  out_buf[0] = '\0';
  size_t pos = 0;
  char key_hex[2 * 6 + 1];   // show up to 6 leading bytes per entry

  for (int i = 0; i < FILTER_NODE_COUNT; i++) {
    const BlockedNode& n = _prefs.blocked_nodes[i];
    if (n.key_len == 0) continue;

    // append comma
    if (pos > 0 && pos + 1 < out_size) {
      out_buf[pos++] = ',';
      out_buf[pos] = '\0';
    }

    size_t rem = out_size - pos;
    if (rem == 0) break;

    uint8_t show = (n.key_len < 6) ? n.key_len : 6;
    mesh::Utils::toHex(key_hex, n.key, show);
    int written = snprintf(out_buf + pos, rem, "%s%s", key_hex, (n.key_len > show) ? ".." : "");
    if (written < 0) break;
    size_t adv = (static_cast<size_t>(written) < rem) ? static_cast<size_t>(written) : rem - 1;
    pos += adv;
    out_buf[pos] = '\0';
    if (adv == rem - 1) break;   // buffer full
  }

  // no blocked nodes
  if (!pos) strcpy(out_buf, "None");
}

void Filter::handleCommand(FILESYSTEM* fs, char* command, char* reply) {
  const char* parts[6];
  int n = mesh::Utils::parseTextParts(command, parts, 6, ' ');

  if (n <= 1) {
    uint32_t hops_total = 0;
    uint32_t rate_total = 0;
    for (uint8_t i = 0; i < PAYLOAD_TYPE_COUNT; ++i) {
      hops_total += _cnt.hops[i];
      rate_total += _cnt.rate[i];
    }
    sprintf(reply, "> Filter %s: Blocked [ Hops: %d | Rate: %d | Channel: %d | Hash: %d | Malformed: %d | Node: %d ]",
        _prefs.filter_enabled ? "on" : "off",
        hops_total, rate_total, _cnt.channel, _cnt.hash, _cnt.malformed, _cnt.node);
  }

  if (n == 2) {
    if (strcmp(parts[1], "help") == 0) {
      strcpy(reply, "> filter [ help | on | off | reset | types | count | hops <args> | rate <args> | channel <args> | block <args> | hash <min_bytes> | malformed <on | off> ]");
    } else if (strcmp(parts[1], "types") == 0) {
      strcpy(reply, "00=REQ\n01=RESPONSE\n02=TXT_MSG\n03=ACK\n04=ADVERT\n05=GRP_TXT\n06=GRP_DATA\n07=ANON_REQ\n08=PATH\n09=TRACE\n10=MULTIPART\n11=CONTROL");
    } else if (strcmp(parts[1], "on") == 0) {
      _prefs.filter_enabled = true;
      strcpy(reply, "> Filter: on");
      save(fs);
    } else if (strcmp(parts[1], "off") == 0) {
      _prefs.filter_enabled = false;
      strcpy(reply, "> Filter: off");
      save(fs);
    } else if (strcmp(parts[1], "reset") == 0) {
      resetPrefs();
      strcpy(reply, "> Filter: preferences reset");
      save(fs);
    } else if (strcmp(parts[1], "count") == 0) {
      formatResponse(reply, ResponseType::COUNT);
    } else if (strcmp(parts[1], "hops") == 0) {
      formatResponse(reply, ResponseType::HOPS);
    } else if (strcmp(parts[1], "rate") == 0) {
      formatResponse(reply, ResponseType::RATE);
    } else if (strcmp(parts[1], "channel") == 0) {
      strcpy(reply, "> filter channel [list | add | remove] <#name | Public>");
    } else if (strcmp(parts[1], "block") == 0) {
      strcpy(reply, "> filter block [list | add | remove] <hex_pubkey>");
    } else if (strcmp(parts[1], "hash") == 0) {
      sprintf(reply, "> Filter: minimal %d bytes path hash size", _prefs.minimal_hash_bytes);
    } else if (strcmp(parts[1], "malformed") == 0) {
      sprintf(reply, "> Filter: malformed text scan %s", _prefs.filter_malformed ? "on" : "off");
    } else {
      strcpy(reply, "> Filter: command error");
    }
  }

  if (n >= 3) {

    // hops
    if (strcmp(parts[1], "hops") == 0) {

      if (n == 4) {
        uint8_t type = atoi(parts[2]);
        uint8_t count = atoi(parts[3]);

        if (type < 0 || type >= PAYLOAD_TYPE_COUNT) {
          strcpy(reply, "> Filter: error <type> range is 0-10");
        } else if (count < 0 || count > 64) {
          strcpy(reply, "> Filter: error <max_hops> range is 0-64");
        } else {
          _prefs.payload_prefs[type].hops_max = count;
          save(fs);
          strcpy(reply, "> Filter: OK");
        }
      } else {
        strcpy(reply, "> Filter: syntax error 'filter hops <type> <max_hops>'");
      }

    // rate
    } else if (strcmp(parts[1], "rate") == 0) {

      if (n == 5) {
        uint8_t type = atoi(parts[2]);
        uint16_t limit = atoi(parts[3]);
        uint32_t secs = atoi(parts[4]);

        if (type < 0 || type >= PAYLOAD_TYPE_COUNT) {
          strcpy(reply, "> Filter: error type range is 0-10");
        } else {
          _prefs.payload_prefs[type].rate_limit = limit;
          _prefs.payload_prefs[type].rate_secs = secs;
          _limiters[type].init(limit, secs);
          save(fs);
          strcpy(reply, "> Filter: OK");
        }
      } else {
        strcpy(reply, "> Filter: syntax error 'filter rate <type> <limit> <secs>'");
      }

    // channel
    } else if (strcmp(parts[1], "channel") == 0) {

      if (strcmp(parts[2], "list") == 0) {
        listChannelNames(reply, 160);
      } else if (n >= 4 && strcmp(parts[2], "add") == 0) {
        if (addChannel(parts[3])) {
          sprintf(reply, "> Filter: channel %s added", parts[3]);
          save(fs);
        } else {
          strcpy(reply, "Failed");
        }
      } else if (n >= 4 && strcmp(parts[2], "remove") == 0) {
        if (removeChannel(parts[3])) {
          sprintf(reply, "> Filter: channel %s removed", parts[3]);
          save(fs);
        } else {
          strcpy(reply, "Failed");
        }
      } else {
        strcpy(reply, "> Filter: syntax error 'filter channel [list | add | remove] <#name | Public>'");
      }

    // block (by node public key / prefix)
    } else if (strcmp(parts[1], "block") == 0) {

      if (strcmp(parts[2], "list") == 0) {
        listNodeKeys(reply, 160);
      } else if (n >= 4 && (strcmp(parts[2], "add") == 0 || strcmp(parts[2], "remove") == 0)) {
        const char* hex = parts[3];
        int hex_len = strlen(hex);
        int key_len = hex_len / 2;
        uint8_t key[PUB_KEY_SIZE];

        if (key_len < 1 || key_len > PUB_KEY_SIZE || !mesh::Utils::fromHex(key, key_len, hex)) {
          strcpy(reply, "> Filter: error bad hex pubkey (1-32 bytes)");
        } else if (strcmp(parts[2], "add") == 0) {
          if (addNode(key, key_len)) {
            sprintf(reply, "> Filter: node %s blocked (2/3-byte hops precise; 1-byte over-blocks)", hex);
            save(fs);
          } else {
            strcpy(reply, "> Filter: error blocklist full");
          }
        } else {  // remove
          if (removeNode(key, key_len)) {
            sprintf(reply, "> Filter: node %s unblocked", hex);
            save(fs);
          } else {
            strcpy(reply, "> Filter: error node not found");
          }
        }
      } else {
        strcpy(reply, "> Filter: syntax error 'filter block [list | add | remove] <hex_pubkey>'");
      }

    // hash
    } else if (strcmp(parts[1], "hash") == 0) {
      uint8_t count = atoi(parts[2]);
      if (count < 1 || count > 3) {
          strcpy(reply, "> Filter: error hash bytes range is 1-3");
      } else {
        _prefs.minimal_hash_bytes = count;
        save(fs);
        strcpy(reply, "> Filter: OK");
      }

    // malformed
    } else if (strcmp(parts[1], "malformed") == 0) {
      if (strcmp(parts[2], "on") == 0) {
        _prefs.filter_malformed = true;
        strcpy(reply, "> Filter: malformed scan on");
        save(fs);
      } else if (strcmp(parts[2], "off") == 0) {
        _prefs.filter_malformed = false;
        strcpy(reply, "> Filter: malformed scan off");
        save(fs);
      }
    } else {
      strcpy(reply, "> Filter: command error");
    }
  }
}

void Filter::formatResponse(char *reply, ResponseType rtype) {
  uint8_t buflen = 160;
  uint8_t n = 0;
  uint8_t pos = 0;

  if (rtype == ResponseType::HOPS) {
    pos = snprintf(reply, buflen, "[TYPE: MAX_HOPS]\n");
  } else if (rtype == ResponseType::RATE) {
    pos = snprintf(reply, buflen, "[TYPE: LIMIT,SECS]\n");
  } else if (rtype == ResponseType::COUNT) {
    pos = snprintf(reply, buflen, "[TYPE: HOPS,RATE]\n");
  }

  for (uint8_t i = 0; i < PAYLOAD_TYPE_COUNT; ++i) {
    if (rtype == ResponseType::HOPS) {
      n = snprintf(reply + pos, (pos < buflen) ? (buflen - pos) : 0,
                    "%02d: %d",
                    i,
                    _prefs.payload_prefs[i].hops_max);
    } else if (rtype == ResponseType::RATE){
      n = snprintf(reply + pos, (pos < buflen) ? (buflen - pos) : 0,
                    "%02d: %d,%d",
                    i,
                    _prefs.payload_prefs[i].rate_limit,
                    _prefs.payload_prefs[i].rate_secs);
    } else if (rtype == ResponseType::COUNT){
      n = snprintf(reply + pos, (pos < buflen) ? (buflen - pos) : 0,
                  "%02d: %d,%d",
                  i,
                  _cnt.hops[i],
                  _cnt.rate[i]);
    }
    if (n < 0) return;
    if (n >= (buflen - pos)) {
        pos = buflen - 1;
        reply[pos] = '\0';
        return;
    }
    pos += (size_t)n;

    if (i + 1 < PAYLOAD_TYPE_COUNT) {
        if (pos + 1 >= buflen) {
            reply[buflen - 1] = '\0';
            return;
        }
        reply[pos++] = '\n';
        reply[pos] = '\0';
    }
  }
}

bool Filter::addChannel(const char* name) {
  if (name == nullptr || name[0] == '\0') return false;

  for (int i=0; i<FILTER_CHANNEL_COUNT; i++) {
    ChannelDetails &ch = _prefs.filter_channels[i];
    if (ch.name[0] == '\0') {
      strncpy(ch.name, name, sizeof(ch.name)-1);
      getChannelHash(name, &ch.channel);
      return true;
    }
  }
  return false;
}

bool Filter::removeChannel(const char* name) {
  if (name == nullptr || name[0] == '\0') return false;

  for (int i=0; i<FILTER_CHANNEL_COUNT; i++) {
    ChannelDetails &ch = _prefs.filter_channels[i];
    if (strcmp(ch.name, name) == 0) {
      ch.name[0] = '\0';
      return true;
    }
  }
  return false;
}

bool Filter::getChannelHash(const char* name, mesh::GroupChannel* gc) {
  if (name == nullptr || name[0] == '\0' || gc == nullptr) return false;

  // get channel secret
  memset(gc->secret, 0, PUB_KEY_SIZE);
  if (strcmp(name, "Public") == 0) {
    memcpy(gc->secret, PUBLIC_CHANNEL_SECRET, PUB_KEY_SIZE);
  } else {
    mesh::Utils::sha256(gc->secret, 16, (const uint8_t*)name, strlen(name));
  }

  // get channel hash
  mesh::Utils::sha256(gc->hash, sizeof(gc->hash), gc->secret, 16);
  return true;
}

void Filter::listChannelNames(char *out_buf, size_t out_size) {
    if (out_buf == nullptr || out_size == 0) return;

    out_buf[0] = '\0';
    size_t pos = 0;
    char channel_hex[4];

    for (int i=0; i<FILTER_CHANNEL_COUNT; i++) {
        const char *name = _prefs.filter_channels[i].name;
        if (name == nullptr || name[0] == '\0') continue;

        // append comma
        if (pos > 0 && pos + 1 < out_size) {
            out_buf[pos++] = ',';
            out_buf[pos] = '\0';
        }

        // remaining
        size_t rem = out_size - pos;
        if (rem == 0) break;

        // append name
        mesh::Utils::toHex(channel_hex, _prefs.filter_channels[i].channel.hash, 1);
        int written = snprintf(out_buf + pos, rem, "%s (%s)", name, channel_hex);
        if (written < 0) break;
        // if truncated, snprintf returns number that would have been written
        size_t adv = (static_cast<size_t>(written) < rem) ? static_cast<size_t>(written) : rem - 1;
        pos += adv;
        out_buf[pos] = '\0';
        if (adv == rem - 1) break; // buffer full
    }

    // no channels
    if (!pos) strcpy(out_buf, "None");
}

bool Filter::validMessageContent(const uint8_t* data, uint8_t len) {
  if (data == nullptr || len <= 5) return false;

  // check timestamp
  uint32_t now = _rtc->getCurrentTime();
  uint32_t timestamp;
  memcpy(&timestamp, &data[0], 4);
  if (!timestamp || timestamp < now - INVALID_TIMESTAMP_WINDOW || timestamp > now + INVALID_TIMESTAMP_WINDOW) return false;

  // check message type
  uint8_t txt_type = data[4] >> 2;
  if (txt_type != TXT_TYPE_PLAIN) return true;

  // calculate text length
  uint8_t txt_len = 5;
  while (txt_len < len && data[txt_len] != 0) txt_len++;
  txt_len -= 5;
  if (!txt_len) return false;

  // valid UTF8
  if (!isValidUTF8(&data[5], txt_len)) return false;

  // valid
  return true;
}

bool Filter::isValidUTF8(const uint8_t* data, uint8_t len) {
  if (data == nullptr || len == 0) return false;

  uint8_t i = 0;
  while (i < len) {
    uint8_t c = data[i++];
    if (c == 0) break;
    if (c < 0x80) continue;

    uint32_t codepoint;
    uint8_t needed;
    if ((c & 0xE0) == 0xC0) {
      codepoint = c & 0x1F;
      needed = 1;
      if (codepoint == 0) return false;
    } else if ((c & 0xF0) == 0xE0) {
      codepoint = c & 0x0F;
      needed = 2;
    } else if ((c & 0xF8) == 0xF0) {
      codepoint = c & 0x07;
      needed = 3;
    } else {
      return false;
    }

    if (i + needed > len) return false;
    for (uint8_t j = 0; j < needed; j++) {
      uint8_t cc = data[i++];
      if ((cc & 0xC0) != 0x80) return false;
      codepoint = (codepoint << 6) | (cc & 0x3F);
    }

    if (needed == 1 && codepoint < 0x80) return false;
    if (needed == 2 && codepoint < 0x0800) return false;
    if (needed == 3 && codepoint < 0x10000) return false;
    if (codepoint > 0x10FFFF) return false;
    if (codepoint >= 0xD800 && codepoint <= 0xDFFF) return false;
    if (codepoint >= 0xFDD0 && codepoint <= 0xFDEF) return false;
    if ((codepoint & 0xFFFE) == 0xFFFE) return false;
  }
  return true;
}

bool Filter::load(FILESYSTEM* fs) {
  if (fs == nullptr || !fs->exists(FILTER_PREFS_FILE)) return true;

#if defined(RP2040_PLATFORM)
  File file = fs->open(FILTER_PREFS_FILE, "r");
#else
  File file = fs->open(FILTER_PREFS_FILE);
#endif

  if (!file) return false;

  file.read(reinterpret_cast<uint8_t*>(&_prefs), sizeof(_prefs));

  _prefs.filter_enabled = constrain(_prefs.filter_enabled, 0, 1);

  for (uint8_t i = 0; i < PAYLOAD_TYPE_COUNT; ++i) {
    _prefs.payload_prefs[i].hops_max = constrain(_prefs.payload_prefs[i].hops_max, 0, 64);
    _limiters[i].init(_prefs.payload_prefs[i].rate_limit, _prefs.payload_prefs[i].rate_secs);
  }
  _prefs.minimal_hash_bytes = constrain(_prefs.minimal_hash_bytes, 1, 3);
  _prefs.filter_malformed = constrain(_prefs.filter_malformed, 0, 1);
  for (uint8_t i = 0; i < FILTER_NODE_COUNT; ++i) {
    _prefs.blocked_nodes[i].key_len = constrain(_prefs.blocked_nodes[i].key_len, 0, PUB_KEY_SIZE);
  }

  file.close();
  return true;
}

bool Filter::save(FILESYSTEM* fs) const {
  if (fs == nullptr) return false;

#if defined(NRF52_PLATFORM) || defined(STM32_PLATFORM)
  fs->remove(FILTER_PREFS_FILE);
  File file = fs->open(FILTER_PREFS_FILE, FILE_O_WRITE);
#elif defined(RP2040_PLATFORM)
  File file = fs->open(FILTER_PREFS_FILE, "w");
#else
  File file = fs->open(FILTER_PREFS_FILE, "w", true);
#endif

  if (!file) return false;

  file.write(reinterpret_cast<const uint8_t*>(&_prefs), sizeof(_prefs));
  file.close();
  return true;
}