#ifndef BITCOINFUZZ_CUSTOMMUTATOR_WITNESS_SPEND_H
#define BITCOINFUZZ_CUSTOMMUTATOR_WITNESS_SPEND_H

/**
 * Structure-aware custom mutator for the verify_witness_spend target.
 *
 * Parses the FuzzedDataProvider input layout and inner SegWit/legacy
 * transaction, mutates fields in place (consensus flags, transaction
 * version/locktime/sequence, multi-input prevouts, witness stack items,
 * Taproot annex, sighash type, and committed Tapscript / P2WSH scripts),
 * then recomputes script commitments (TapLeaf/TapBranch/TapTweak, SHA-256,
 * HASH160) and real BIP-341 Schnorr / BIP-143 ECDSA signatures most of the
 * time (~7/8) while leaving ~1/8 un-repaired to cover rejection paths.
 */

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <limits>
#include <random>
#include <vector>

#include <bitcoinfuzz/basemodule.h>
#include <custommutator/utils/crypto/ripemd160.h>
#include <custommutator/utils/crypto/sha256.h>

#define template c_template
extern "C" {
#if __has_include(<external/secp256k1/include/secp256k1.h>)
#include <external/secp256k1/include/secp256k1.h>
#include <external/secp256k1/include/secp256k1_extrakeys.h>
#include <external/secp256k1/include/secp256k1_schnorrsig.h>
#elif __has_include(<secp256k1.h>)
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig.h>
#endif
}
#undef template

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

namespace witness_spend_mutator {

using Bytes = std::vector<uint8_t>;
using Hash32 = std::array<uint8_t, 32>;

// Deterministic signing secret key (scalar = 1 -> generator point G).
constexpr uint8_t PRIVKEY_ONE[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

// x-only coordinate of generator point G.
constexpr uint8_t INTERNAL_PUBKEY_G[32] = {
    0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
    0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
    0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};

// 33-byte compressed SEC1 encoding of generator point G.
constexpr uint8_t COMPRESSED_PUBKEY_G[33] = {
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0,
    0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d,
    0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};

// BIP-342 OP_SUCCESS opcodes.
constexpr uint8_t OP_SUCCESS_OPCODES[] = {
    0x7e, 0x7f, 0x80, 0x83, 0x84, 0x85, 0x86, 0x8b, 0x8c, 0x8d, 0x8e,
    0x95, 0x96, 0x97, 0x98, 0x99, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
    0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};

constexpr uint32_t INDIVIDUAL_FLAGS[] = {
    bitcoinfuzz::WITNESS_SPEND_FLAG_P2SH,
    bitcoinfuzz::WITNESS_SPEND_FLAG_DERSIG,
    bitcoinfuzz::WITNESS_SPEND_FLAG_NULLDUMMY,
    bitcoinfuzz::WITNESS_SPEND_FLAG_CLTV,
    bitcoinfuzz::WITNESS_SPEND_FLAG_CSV,
    bitcoinfuzz::WITNESS_SPEND_FLAG_WITNESS,
    bitcoinfuzz::WITNESS_SPEND_FLAG_TAPROOT};

constexpr uint8_t VALID_TAPROOT_HASHTYPES[] = {0x00, 0x01, 0x02, 0x03,
                                               0x81, 0x82, 0x83};
constexpr uint8_t VALID_SEGWIT_V0_HASHTYPES[] = {0x01, 0x02, 0x03,
                                                 0x81, 0x82, 0x83};

constexpr size_t MAX_TX_IO = 8;
constexpr size_t MAX_WITNESS_ITEMS = 32;
constexpr size_t MAX_SCRIPT_BYTES = 2048;

struct TxIn {
  Hash32 prevout_hash{};
  uint32_t prevout_n{0};
  Bytes script_sig;
  uint32_t sequence{0xffffffff};
  std::vector<Bytes> witness;
};

struct TxOut {
  int64_t value{1000};
  Bytes script_pubkey;
};

struct ParsedTx {
  int32_t version{2};
  std::vector<TxIn> vin;
  std::vector<TxOut> vout;
  uint32_t locktime{0};
};

struct ParsedWitnessSpend {
  uint32_t flags{bitcoinfuzz::WITNESS_SPEND_FLAGS_MASK};
  uint32_t input_index{0};
  int64_t spent_amount{1000000};
  Bytes spent_script_pubkey;
  bool has_multi_prevouts{false};
  std::vector<int64_t> all_spent_amounts;
  std::vector<Bytes> all_spent_spks;
  ParsedTx tx;
};

inline secp256k1_context *GetSecpCtx() {
  static secp256k1_context *ctx =
      secp256k1_context_create(SECP256K1_CONTEXT_NONE);
  return ctx;
}

inline void PushLE32(Bytes &out, uint32_t v) {
  out.push_back(static_cast<uint8_t>(v & 0xff));
  out.push_back(static_cast<uint8_t>((v >> 8) & 0xff));
  out.push_back(static_cast<uint8_t>((v >> 16) & 0xff));
  out.push_back(static_cast<uint8_t>((v >> 24) & 0xff));
}

inline void PushLE64(Bytes &out, uint64_t v) {
  for (int i = 0; i < 8; ++i) {
    out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xff));
  }
}

inline bool ReadLE32(const Bytes &in, size_t &pos, uint32_t &out) {
  if (in.size() - pos < 4)
    return false;
  out = static_cast<uint32_t>(in[pos]) |
        (static_cast<uint32_t>(in[pos + 1]) << 8) |
        (static_cast<uint32_t>(in[pos + 2]) << 16) |
        (static_cast<uint32_t>(in[pos + 3]) << 24);
  pos += 4;
  return true;
}

inline bool ReadLE64(const Bytes &in, size_t &pos, uint64_t &out) {
  if (in.size() - pos < 8)
    return false;
  out = 0;
  for (int i = 0; i < 8; ++i) {
    out |= static_cast<uint64_t>(in[pos + i]) << (8 * i);
  }
  pos += 8;
  return true;
}

inline void WriteCompactSize(Bytes &out, uint64_t n) {
  if (n < 253) {
    out.push_back(static_cast<uint8_t>(n));
  } else if (n <= 0xffff) {
    out.push_back(253);
    out.push_back(static_cast<uint8_t>(n & 0xff));
    out.push_back(static_cast<uint8_t>((n >> 8) & 0xff));
  } else if (n <= 0xffffffffULL) {
    out.push_back(254);
    PushLE32(out, static_cast<uint32_t>(n));
  } else {
    out.push_back(255);
    PushLE64(out, n);
  }
}

inline bool ReadCompactSize(const Bytes &in, size_t &pos, uint64_t &out) {
  if (pos >= in.size())
    return false;
  const uint8_t first = in[pos++];
  if (first < 253) {
    out = first;
    return true;
  }
  if (first == 253) {
    if (in.size() - pos < 2)
      return false;
    uint16_t v = static_cast<uint16_t>(in[pos]) |
                 (static_cast<uint16_t>(in[pos + 1]) << 8);
    pos += 2;
    if (v < 253)
      return false;
    out = v;
    return true;
  }
  if (first == 254) {
    uint32_t v = 0;
    if (!ReadLE32(in, pos, v) || v < 0x10000U)
      return false;
    out = v;
    return true;
  }
  uint64_t v = 0;
  if (!ReadLE64(in, pos, v) || v < 0x100000000ULL)
    return false;
  out = v;
  return true;
}

inline void WriteVectorItem(Bytes &out, const Bytes &item) {
  WriteCompactSize(out, item.size());
  out.insert(out.end(), item.begin(), item.end());
}

inline Hash32 Sha256(const uint8_t *data, size_t len) {
  Hash32 out{};
  CSHA256().Write(data, len).Finalize(out.data());
  return out;
}

inline Hash32 DoubleSha256(const uint8_t *data, size_t len) {
  Hash32 first = Sha256(data, len);
  return Sha256(first.data(), first.size());
}

inline std::array<uint8_t, 20> Hash160(const uint8_t *data, size_t len) {
  Hash32 sha = Sha256(data, len);
  std::array<uint8_t, 20> out{};
  CRIPEMD160().Write(sha.data(), sha.size()).Finalize(out.data());
  return out;
}

inline Hash32 TaggedHash(const char *tag, size_t tag_len, const uint8_t *data,
                         size_t data_len) {
  Hash32 tag_hash = Sha256(reinterpret_cast<const uint8_t *>(tag), tag_len);
  Hash32 out{};
  CSHA256 hasher;
  hasher.Write(tag_hash.data(), 32);
  hasher.Write(tag_hash.data(), 32);
  if (data_len > 0) {
    hasher.Write(data, data_len);
  }
  hasher.Finalize(out.data());
  return out;
}

inline bool ParseTx(const Bytes &raw, ParsedTx &tx) {
  tx = ParsedTx{};
  size_t pos = 0;
  uint32_t ver = 0;
  if (!ReadLE32(raw, pos, ver))
    return false;
  tx.version = static_cast<int32_t>(ver);

  bool has_witness = false;
  if (raw.size() - pos >= 2 && raw[pos] == 0x00 && raw[pos + 1] == 0x01) {
    has_witness = true;
    pos += 2;
  }

  uint64_t vin_count = 0;
  if (!ReadCompactSize(raw, pos, vin_count) || vin_count == 0 ||
      vin_count > MAX_TX_IO) {
    return false;
  }
  tx.vin.resize(static_cast<size_t>(vin_count));
  for (size_t i = 0; i < tx.vin.size(); ++i) {
    if (raw.size() - pos < 36)
      return false;
    std::memcpy(tx.vin[i].prevout_hash.data(), raw.data() + pos, 32);
    pos += 32;
    if (!ReadLE32(raw, pos, tx.vin[i].prevout_n))
      return false;
    uint64_t sig_len = 0;
    if (!ReadCompactSize(raw, pos, sig_len) || sig_len > MAX_SCRIPT_BYTES ||
        sig_len > raw.size() - pos) {
      return false;
    }
    tx.vin[i].script_sig.assign(raw.begin() + static_cast<ptrdiff_t>(pos),
                                raw.begin() +
                                    static_cast<ptrdiff_t>(pos + sig_len));
    pos += static_cast<size_t>(sig_len);
    if (!ReadLE32(raw, pos, tx.vin[i].sequence))
      return false;
  }

  uint64_t vout_count = 0;
  if (!ReadCompactSize(raw, pos, vout_count) || vout_count > MAX_TX_IO)
    return false;
  tx.vout.resize(static_cast<size_t>(vout_count));
  for (size_t i = 0; i < tx.vout.size(); ++i) {
    uint64_t val = 0;
    if (!ReadLE64(raw, pos, val))
      return false;
    tx.vout[i].value = static_cast<int64_t>(val);
    uint64_t spk_len = 0;
    if (!ReadCompactSize(raw, pos, spk_len) || spk_len > MAX_SCRIPT_BYTES ||
        spk_len > raw.size() - pos) {
      return false;
    }
    tx.vout[i].script_pubkey.assign(raw.begin() + static_cast<ptrdiff_t>(pos),
                                    raw.begin() +
                                        static_cast<ptrdiff_t>(pos + spk_len));
    pos += static_cast<size_t>(spk_len);
  }

  if (has_witness) {
    for (size_t i = 0; i < tx.vin.size(); ++i) {
      uint64_t item_count = 0;
      if (!ReadCompactSize(raw, pos, item_count) ||
          item_count > MAX_WITNESS_ITEMS) {
        return false;
      }
      tx.vin[i].witness.resize(static_cast<size_t>(item_count));
      for (size_t j = 0; j < tx.vin[i].witness.size(); ++j) {
        uint64_t item_len = 0;
        if (!ReadCompactSize(raw, pos, item_len) ||
            item_len > MAX_SCRIPT_BYTES || item_len > raw.size() - pos) {
          return false;
        }
        tx.vin[i].witness[j].assign(raw.begin() + static_cast<ptrdiff_t>(pos),
                                    raw.begin() +
                                        static_cast<ptrdiff_t>(pos + item_len));
        pos += static_cast<size_t>(item_len);
      }
    }
  }

  if (!ReadLE32(raw, pos, tx.locktime))
    return false;
  return pos == raw.size();
}

inline Bytes SerializeTx(const ParsedTx &tx) {
  Bytes out;
  PushLE32(out, static_cast<uint32_t>(tx.version));

  const bool has_witness =
      std::any_of(tx.vin.begin(), tx.vin.end(),
                  [](const TxIn &in) { return !in.witness.empty(); });
  if (has_witness) {
    out.push_back(0x00);
    out.push_back(0x01);
  }

  WriteCompactSize(out, tx.vin.size());
  for (const TxIn &in : tx.vin) {
    out.insert(out.end(), in.prevout_hash.begin(), in.prevout_hash.end());
    PushLE32(out, in.prevout_n);
    WriteVectorItem(out, in.script_sig);
    PushLE32(out, in.sequence);
  }

  WriteCompactSize(out, tx.vout.size());
  for (const TxOut &o : tx.vout) {
    PushLE64(out, static_cast<uint64_t>(o.value));
    WriteVectorItem(out, o.script_pubkey);
  }

  if (has_witness) {
    for (const TxIn &in : tx.vin) {
      WriteCompactSize(out, in.witness.size());
      for (const Bytes &item : in.witness) {
        WriteVectorItem(out, item);
      }
    }
  }

  PushLE32(out, tx.locktime);
  return out;
}

// Mirrors Driver::VerifyWitnessSpendTarget byte consumption via
// FuzzedDataProvider so parsing never drifts from driver.cpp.
inline bool ParseWitnessSpend(const uint8_t *data, size_t size,
                              ParsedWitnessSpend &out) {
  out = ParsedWitnessSpend{};
  if (size < 18)
    return false;

  FuzzedDataProvider provider(data, size);
  out.flags = provider.ConsumeIntegral<uint32_t>();
  out.input_index = provider.ConsumeIntegral<uint32_t>();
  out.spent_amount = provider.ConsumeIntegralInRange<int64_t>(
      0, std::numeric_limits<int64_t>::max());
  out.spent_script_pubkey = provider.ConsumeBytes<uint8_t>(
      provider.ConsumeIntegralInRange<size_t>(0, 128));

  out.has_multi_prevouts = provider.ConsumeBool();
  if (out.has_multi_prevouts) {
    const size_t num_prevouts = provider.ConsumeIntegralInRange<size_t>(1, 8);
    out.all_spent_amounts.reserve(num_prevouts);
    out.all_spent_spks.reserve(num_prevouts);
    for (size_t i = 0; i < num_prevouts; ++i) {
      out.all_spent_amounts.push_back(provider.ConsumeIntegralInRange<int64_t>(
          0, std::numeric_limits<int64_t>::max()));
      const size_t spk_len = provider.ConsumeIntegralInRange<size_t>(0, 64);
      out.all_spent_spks.push_back(provider.ConsumeBytes<uint8_t>(spk_len));
    }
  }

  const Bytes tx_bytes = provider.ConsumeRemainingBytes<uint8_t>();
  if (tx_bytes.empty())
    return false;
  return ParseTx(tx_bytes, out.tx);
}

// Exact inverse of FuzzedDataProvider consumption in
// Driver::VerifyWitnessSpendTarget.
inline Bytes SerializeWitnessSpend(const ParsedWitnessSpend &in) {
  Bytes out;

  // Front bytes (consumed in order by ConsumeBytes).
  const size_t default_spk_len =
      std::min<size_t>(in.spent_script_pubkey.size(), 128);
  out.insert(out.end(), in.spent_script_pubkey.begin(),
             in.spent_script_pubkey.begin() +
                 static_cast<ptrdiff_t>(default_spk_len));

  const bool emit_multi =
      in.has_multi_prevouts && !in.all_spent_amounts.empty() &&
      in.all_spent_amounts.size() == in.all_spent_spks.size();
  const size_t num_prevouts =
      emit_multi ? std::min<size_t>(in.all_spent_amounts.size(), 8) : 0;

  if (emit_multi) {
    for (size_t i = 0; i < num_prevouts; ++i) {
      const size_t spk_len = std::min<size_t>(in.all_spent_spks[i].size(), 64);
      out.insert(out.end(), in.all_spent_spks[i].begin(),
                 in.all_spent_spks[i].begin() +
                     static_cast<ptrdiff_t>(spk_len));
    }
  }

  // Middle bytes (consumed by ConsumeRemainingBytes).
  const Bytes tx_bytes = SerializeTx(in.tx);
  out.insert(out.end(), tx_bytes.begin(), tx_bytes.end());

  // Tail bytes (consumed from the end in reverse order).
  auto push_nonneg_i64 = [&](int64_t val) {
    const uint64_t raw = val < 0 ? 0ULL : static_cast<uint64_t>(val);
    PushLE64(out, raw);
  };

  if (emit_multi) {
    for (size_t i = num_prevouts; i-- > 0;) {
      const size_t spk_len = std::min<size_t>(in.all_spent_spks[i].size(), 64);
      out.push_back(static_cast<uint8_t>(spk_len));
      push_nonneg_i64(in.all_spent_amounts[i]);
    }
    out.push_back(static_cast<uint8_t>(num_prevouts - 1));
  }

  out.push_back(emit_multi ? 0x01 : 0x00);
  out.push_back(static_cast<uint8_t>(default_spk_len));
  push_nonneg_i64(in.spent_amount);
  PushLE32(out, in.input_index);
  PushLE32(out, in.flags);

  return out;
}

inline size_t EffectiveInputIdx(const ParsedWitnessSpend &s) {
  return s.tx.vin.empty() ? 0 : (s.input_index % s.tx.vin.size());
}

inline bool UsesMultiPrevouts(const ParsedWitnessSpend &s) {
  const size_t n = s.tx.vin.size();
  return s.has_multi_prevouts && s.all_spent_spks.size() == n &&
         s.all_spent_amounts.size() == n;
}

inline int64_t PrevoutAmount(const ParsedWitnessSpend &s, size_t i) {
  return UsesMultiPrevouts(s) ? s.all_spent_amounts[i] : s.spent_amount;
}

inline const Bytes &PrevoutSpk(const ParsedWitnessSpend &s, size_t i) {
  return UsesMultiPrevouts(s) ? s.all_spent_spks[i] : s.spent_script_pubkey;
}

inline void SetTargetSpk(ParsedWitnessSpend &s, size_t idx, const Bytes &spk) {
  if (UsesMultiPrevouts(s)) {
    s.all_spent_spks[idx] = spk;
  } else {
    s.spent_script_pubkey = spk;
  }
}

inline bool IsValidTaprootHashType(uint8_t ht) {
  return ht == 0x00 || ht == 0x01 || ht == 0x02 || ht == 0x03 || ht == 0x81 ||
         ht == 0x82 || ht == 0x83;
}

inline bool IsValidSegwitV0HashType(uint8_t ht) {
  return ht == 0x01 || ht == 0x02 || ht == 0x03 || ht == 0x81 || ht == 0x82 ||
         ht == 0x83;
}

// Computes exact BIP-341 / BIP-342 Taproot sighash digest.
inline bool ComputeTaprootSighash(const ParsedWitnessSpend &s, size_t idx,
                                  uint8_t hash_type, const Bytes *annex,
                                  const Hash32 *tapleaf_hash,
                                  uint32_t codesep_pos, Hash32 &out_digest) {
  if (!IsValidTaprootHashType(hash_type) || idx >= s.tx.vin.size())
    return false;
  const uint8_t output_type =
      (hash_type == 0x00) ? 0x01 : static_cast<uint8_t>(hash_type & 0x03);
  const uint8_t input_type = static_cast<uint8_t>(hash_type & 0x80);
  if (output_type == 0x03 && idx >= s.tx.vout.size())
    return false;

  Bytes sigmsg;
  sigmsg.push_back(0x00); // epoch = 0
  sigmsg.push_back(hash_type);
  PushLE32(sigmsg, static_cast<uint32_t>(s.tx.version));
  PushLE32(sigmsg, s.tx.locktime);

  if (input_type != 0x80) {
    Bytes prevouts, amounts, spks, seqs;
    for (size_t i = 0; i < s.tx.vin.size(); ++i) {
      prevouts.insert(prevouts.end(), s.tx.vin[i].prevout_hash.begin(),
                      s.tx.vin[i].prevout_hash.end());
      PushLE32(prevouts, s.tx.vin[i].prevout_n);
      PushLE64(amounts, static_cast<uint64_t>(PrevoutAmount(s, i)));
      WriteVectorItem(spks, PrevoutSpk(s, i));
      PushLE32(seqs, s.tx.vin[i].sequence);
    }
    const Hash32 h_prev = Sha256(prevouts.data(), prevouts.size());
    const Hash32 h_amt = Sha256(amounts.data(), amounts.size());
    const Hash32 h_spk = Sha256(spks.data(), spks.size());
    const Hash32 h_seq = Sha256(seqs.data(), seqs.size());
    sigmsg.insert(sigmsg.end(), h_prev.begin(), h_prev.end());
    sigmsg.insert(sigmsg.end(), h_amt.begin(), h_amt.end());
    sigmsg.insert(sigmsg.end(), h_spk.begin(), h_spk.end());
    sigmsg.insert(sigmsg.end(), h_seq.begin(), h_seq.end());
  }

  if (output_type != 0x02 && output_type != 0x03) {
    Bytes outs;
    for (const TxOut &o : s.tx.vout) {
      PushLE64(outs, static_cast<uint64_t>(o.value));
      WriteVectorItem(outs, o.script_pubkey);
    }
    const Hash32 h_out = Sha256(outs.data(), outs.size());
    sigmsg.insert(sigmsg.end(), h_out.begin(), h_out.end());
  }

  const uint8_t ext_flag = tapleaf_hash ? 1 : 0;
  const uint8_t spend_type =
      static_cast<uint8_t>((ext_flag * 2) + (annex ? 1 : 0));
  sigmsg.push_back(spend_type);

  if (input_type == 0x80) {
    sigmsg.insert(sigmsg.end(), s.tx.vin[idx].prevout_hash.begin(),
                  s.tx.vin[idx].prevout_hash.end());
    PushLE32(sigmsg, s.tx.vin[idx].prevout_n);
    PushLE64(sigmsg, static_cast<uint64_t>(PrevoutAmount(s, idx)));
    WriteVectorItem(sigmsg, PrevoutSpk(s, idx));
    PushLE32(sigmsg, s.tx.vin[idx].sequence);
  } else {
    PushLE32(sigmsg, static_cast<uint32_t>(idx));
  }

  if (annex) {
    Bytes annex_ser;
    WriteVectorItem(annex_ser, *annex);
    const Hash32 h_annex = Sha256(annex_ser.data(), annex_ser.size());
    sigmsg.insert(sigmsg.end(), h_annex.begin(), h_annex.end());
  }

  if (output_type == 0x03) {
    Bytes single_out;
    PushLE64(single_out, static_cast<uint64_t>(s.tx.vout[idx].value));
    WriteVectorItem(single_out, s.tx.vout[idx].script_pubkey);
    const Hash32 h_single = Sha256(single_out.data(), single_out.size());
    sigmsg.insert(sigmsg.end(), h_single.begin(), h_single.end());
  }

  if (tapleaf_hash) {
    sigmsg.insert(sigmsg.end(), tapleaf_hash->begin(), tapleaf_hash->end());
    sigmsg.push_back(0x00); // key_version
    PushLE32(sigmsg, codesep_pos);
  }

  out_digest = TaggedHash("TapSighash", 10, sigmsg.data(), sigmsg.size());
  return true;
}

// Computes exact BIP-143 SegWit v0 sighash digest.
inline bool ComputeSegwitV0Sighash(const ParsedWitnessSpend &s, size_t idx,
                                   const Bytes &script_code, uint8_t hash_type,
                                   Hash32 &out_digest) {
  if (idx >= s.tx.vin.size())
    return false;
  const uint8_t base_type = static_cast<uint8_t>(hash_type & 0x1f);
  const bool anyonecanpay = (hash_type & 0x80) != 0;

  Hash32 hash_prevouts{};
  if (!anyonecanpay) {
    Bytes prevouts;
    for (const TxIn &in : s.tx.vin) {
      prevouts.insert(prevouts.end(), in.prevout_hash.begin(),
                      in.prevout_hash.end());
      PushLE32(prevouts, in.prevout_n);
    }
    hash_prevouts = DoubleSha256(prevouts.data(), prevouts.size());
  }

  Hash32 hash_sequence{};
  if (!anyonecanpay && base_type != 0x02 && base_type != 0x03) {
    Bytes seqs;
    for (const TxIn &in : s.tx.vin) {
      PushLE32(seqs, in.sequence);
    }
    hash_sequence = DoubleSha256(seqs.data(), seqs.size());
  }

  Hash32 hash_outputs{};
  if (base_type != 0x02 && base_type != 0x03) {
    Bytes outs;
    for (const TxOut &o : s.tx.vout) {
      PushLE64(outs, static_cast<uint64_t>(o.value));
      WriteVectorItem(outs, o.script_pubkey);
    }
    hash_outputs = DoubleSha256(outs.data(), outs.size());
  } else if (base_type == 0x03 && idx < s.tx.vout.size()) {
    Bytes single_out;
    PushLE64(single_out, static_cast<uint64_t>(s.tx.vout[idx].value));
    WriteVectorItem(single_out, s.tx.vout[idx].script_pubkey);
    hash_outputs = DoubleSha256(single_out.data(), single_out.size());
  }

  Bytes preimage;
  PushLE32(preimage, static_cast<uint32_t>(s.tx.version));
  preimage.insert(preimage.end(), hash_prevouts.begin(), hash_prevouts.end());
  preimage.insert(preimage.end(), hash_sequence.begin(), hash_sequence.end());
  preimage.insert(preimage.end(), s.tx.vin[idx].prevout_hash.begin(),
                  s.tx.vin[idx].prevout_hash.end());
  PushLE32(preimage, s.tx.vin[idx].prevout_n);
  WriteVectorItem(preimage, script_code);
  PushLE64(preimage, static_cast<uint64_t>(PrevoutAmount(s, idx)));
  PushLE32(preimage, s.tx.vin[idx].sequence);
  preimage.insert(preimage.end(), hash_outputs.begin(), hash_outputs.end());
  PushLE32(preimage, s.tx.locktime);
  PushLE32(preimage, static_cast<uint32_t>(hash_type));

  out_digest = DoubleSha256(preimage.data(), preimage.size());
  return true;
}

inline bool SignSchnorr(const secp256k1_keypair &kp, const Hash32 &digest,
                        uint8_t hash_type, Bytes &out_sig) {
  secp256k1_context *ctx = GetSecpCtx();
  if (!ctx)
    return false;
  uint8_t sig64[64];
  uint8_t aux[32] = {};
  if (!secp256k1_schnorrsig_sign32(ctx, sig64, digest.data(), &kp, aux))
    return false;
  out_sig.assign(sig64, sig64 + 64);
  if (hash_type != 0x00) {
    out_sig.push_back(hash_type);
  }
  return true;
}

inline bool SignEcdsaDer(const Hash32 &digest, uint8_t hash_type,
                         Bytes &out_sig) {
  secp256k1_context *ctx = GetSecpCtx();
  if (!ctx)
    return false;
  secp256k1_ecdsa_signature sig;
  if (!secp256k1_ecdsa_sign(ctx, &sig, digest.data(), PRIVKEY_ONE, nullptr,
                            nullptr)) {
    return false;
  }
  uint8_t der[74];
  size_t der_len = sizeof(der);
  if (!secp256k1_ecdsa_signature_serialize_der(ctx, der, &der_len, &sig))
    return false;
  out_sig.assign(der, der + der_len);
  out_sig.push_back(hash_type);
  return true;
}

inline Hash32 ComputeTapLeafHash(uint8_t leaf_version, const Bytes &script) {
  Bytes leaf_data;
  leaf_data.push_back(leaf_version);
  WriteVectorItem(leaf_data, script);
  return TaggedHash("TapLeaf", 7, leaf_data.data(), leaf_data.size());
}

inline Hash32 ComputeTapBranchHash(const Hash32 &a, const Hash32 &b) {
  uint8_t buf[64];
  if (std::memcmp(a.data(), b.data(), 32) <= 0) {
    std::memcpy(buf, a.data(), 32);
    std::memcpy(buf + 32, b.data(), 32);
  } else {
    std::memcpy(buf, b.data(), 32);
    std::memcpy(buf + 32, a.data(), 32);
  }
  return TaggedHash("TapBranch", 9, buf, 64);
}

// Advances one script instruction; returns false on truncated pushdata.
inline bool StepScriptOpcode(const Bytes &script, size_t &pos,
                             uint8_t &opcode) {
  if (pos >= script.size())
    return false;
  opcode = script[pos++];
  size_t push_len = 0;
  if (opcode >= 0x01 && opcode <= 0x4b) {
    push_len = opcode;
  } else if (opcode == 0x4c) {
    if (pos >= script.size())
      return false;
    push_len = script[pos++];
  } else if (opcode == 0x4d) {
    if (script.size() - pos < 2)
      return false;
    push_len = static_cast<size_t>(script[pos]) |
               (static_cast<size_t>(script[pos + 1]) << 8);
    pos += 2;
  } else if (opcode == 0x4e) {
    if (script.size() - pos < 4)
      return false;
    push_len = static_cast<size_t>(script[pos]) |
               (static_cast<size_t>(script[pos + 1]) << 8) |
               (static_cast<size_t>(script[pos + 2]) << 16) |
               (static_cast<size_t>(script[pos + 3]) << 24);
    pos += 4;
  }
  if (push_len > script.size() - pos)
    return false;
  pos += push_len;
  return true;
}

// Finds codesep_pos for every Tapscript checksig/checksigadd opcode.
inline std::vector<uint32_t> ScanTapscriptChecksigPos(const Bytes &script) {
  std::vector<uint32_t> positions;
  size_t pos = 0;
  uint32_t opcode_idx = 0;
  uint32_t last_codesep = 0xffffffffU;
  while (pos < script.size()) {
    uint8_t op = 0;
    if (!StepScriptOpcode(script, pos, op))
      break;
    if (op == 0xab) { // OP_CODESEPARATOR
      last_codesep = opcode_idx;
    } else if (op == 0xac || op == 0xad || op == 0xba) {
      positions.push_back(last_codesep);
    }
    ++opcode_idx;
  }
  return positions;
}

// Finds byte offset after OP_CODESEPARATOR for every v0 checksig/multisig op.
inline std::vector<std::pair<size_t, bool>>
ScanV0ChecksigOps(const Bytes &script) {
  std::vector<std::pair<size_t, bool>> ops; // (scriptCode_offset, is_multisig)
  size_t pos = 0;
  size_t last_codesep_after = 0;
  while (pos < script.size()) {
    uint8_t op = 0;
    if (!StepScriptOpcode(script, pos, op))
      break;
    if (op == 0xab) { // OP_CODESEPARATOR
      last_codesep_after = pos;
    } else if (op == 0xac || op == 0xad) {
      ops.emplace_back(last_codesep_after, false);
    } else if (op == 0xae || op == 0xaf) {
      ops.emplace_back(last_codesep_after, true);
    }
  }
  return ops;
}

inline bool HasAnnex(const std::vector<Bytes> &witness) {
  return witness.size() >= 2 && !witness.back().empty() &&
         witness.back()[0] == 0x50;
}

// Recomputes script commitments (Taproot tweak / P2WSH SHA256 / P2SH HASH160)
// and fresh cryptographic signatures (BIP-341 Schnorr / BIP-143 ECDSA) for the
// target input after structure-aware mutations.
inline void RecommitAndResign(ParsedWitnessSpend &s, std::mt19937 &rng) {
  secp256k1_context *ctx = GetSecpCtx();
  if (!ctx || s.tx.vin.empty())
    return;

  const size_t idx = EffectiveInputIdx(s);
  TxIn &txin = s.tx.vin[idx];
  Bytes target_spk = PrevoutSpk(s, idx);

  // 1. Taproot spend: OP_1 <32-byte x-only output key>
  if (target_spk.size() == 34 && target_spk[0] == 0x51 &&
      target_spk[1] == 0x20 && !txin.witness.empty()) {
    const bool annex_present = HasAnnex(txin.witness);
    const Bytes *annex = annex_present ? &txin.witness.back() : nullptr;
    const size_t stack_len = txin.witness.size() - (annex_present ? 1 : 0);

    if (stack_len == 1) {
      // Taproot key-path spend.
      secp256k1_keypair kp;
      if (!secp256k1_keypair_create(ctx, &kp, PRIVKEY_ONE))
        return;
      const Hash32 tweak = TaggedHash("TapTweak", 8, INTERNAL_PUBKEY_G, 32);
      if (!secp256k1_keypair_xonly_tweak_add(ctx, &kp, tweak.data()))
        return;
      secp256k1_xonly_pubkey out_xonly;
      if (!secp256k1_keypair_xonly_pub(ctx, &out_xonly, nullptr, &kp))
        return;
      uint8_t out_pk[32];
      secp256k1_xonly_pubkey_serialize(ctx, out_pk, &out_xonly);

      target_spk = {0x51, 0x20};
      target_spk.insert(target_spk.end(), out_pk, out_pk + 32);
      SetTargetSpk(s, idx, target_spk);

      uint8_t hash_type = 0x00;
      if (txin.witness[0].size() == 65 &&
          IsValidTaprootHashType(txin.witness[0][64])) {
        hash_type = txin.witness[0][64];
      }
      if ((hash_type & 0x03) == 0x03 && idx >= s.tx.vout.size()) {
        hash_type = 0x00;
      }

      Hash32 digest{};
      Bytes sig;
      if (ComputeTaprootSighash(s, idx, hash_type, annex, nullptr, 0xffffffffU,
                                digest) &&
          SignSchnorr(kp, digest, hash_type, sig)) {
        txin.witness[0] = std::move(sig);
      }
      txin.script_sig.clear();
      return;
    }

    if (stack_len >= 2) {
      // Taproot script-path spend.
      const Bytes &script = txin.witness[stack_len - 2];
      Bytes &cb = txin.witness[stack_len - 1];

      uint8_t leaf_version = 0xc0;
      if (!cb.empty()) {
        leaf_version = static_cast<uint8_t>(cb[0] & 0xfe);
      }

      // Preserve any existing 32-byte Merkle branch siblings in control block.
      std::vector<Hash32> siblings;
      if (cb.size() >= 33 && ((cb.size() - 33) % 32 == 0)) {
        const size_t n_branches = std::min<size_t>((cb.size() - 33) / 32, 4);
        for (size_t b = 0; b < n_branches; ++b) {
          Hash32 node{};
          std::memcpy(node.data(), cb.data() + 33 + b * 32, 32);
          siblings.push_back(node);
        }
      }

      const Hash32 tapleaf_hash = ComputeTapLeafHash(leaf_version, script);
      Hash32 root = tapleaf_hash;
      for (const Hash32 &sib : siblings) {
        root = ComputeTapBranchHash(root, sib);
      }

      uint8_t tweak_in[64];
      std::memcpy(tweak_in, INTERNAL_PUBKEY_G, 32);
      std::memcpy(tweak_in + 32, root.data(), 32);
      const Hash32 taptweak = TaggedHash("TapTweak", 8, tweak_in, 64);

      secp256k1_xonly_pubkey internal_pk;
      secp256k1_pubkey out_pk;
      if (!secp256k1_xonly_pubkey_parse(ctx, &internal_pk, INTERNAL_PUBKEY_G) ||
          !secp256k1_xonly_pubkey_tweak_add(ctx, &out_pk, &internal_pk,
                                            taptweak.data())) {
        return;
      }

      secp256k1_xonly_pubkey out_xonly;
      int parity = 0;
      secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xonly, &parity, &out_pk);
      uint8_t out_pk_bytes[32];
      secp256k1_xonly_pubkey_serialize(ctx, out_pk_bytes, &out_xonly);

      target_spk = {0x51, 0x20};
      target_spk.insert(target_spk.end(), out_pk_bytes, out_pk_bytes + 32);
      SetTargetSpk(s, idx, target_spk);

      cb.clear();
      cb.push_back(static_cast<uint8_t>(leaf_version | (parity & 1)));
      cb.insert(cb.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
      for (const Hash32 &sib : siblings) {
        cb.insert(cb.end(), sib.begin(), sib.end());
      }
      txin.script_sig.clear();

      // Re-sign Tapscript OP_CHECKSIG / OP_CHECKSIGVERIFY / OP_CHECKSIGADD.
      if (leaf_version == 0xc0 && stack_len > 2) {
        const std::vector<uint32_t> cs_positions =
            ScanTapscriptChecksigPos(script);
        if (!cs_positions.empty()) {
          secp256k1_keypair leaf_kp;
          if (!secp256k1_keypair_create(ctx, &leaf_kp, PRIVKEY_ONE))
            return;

          // Match signature stack slots from top down as checksigs execute
          // left-to-right.
          size_t next_op = 0;
          for (size_t wi = stack_len - 2;
               wi-- > 0 && next_op < cs_positions.size();) {
            Bytes &slot = txin.witness[wi];
            if (slot.size() == 64 || slot.size() == 65) {
              uint8_t ht = 0x00;
              if (slot.size() == 65 && IsValidTaprootHashType(slot[64])) {
                ht = slot[64];
              }
              if ((ht & 0x03) == 0x03 && idx >= s.tx.vout.size()) {
                ht = 0x00;
              }
              Hash32 digest{};
              Bytes sig;
              if (ComputeTaprootSighash(s, idx, ht, annex, &tapleaf_hash,
                                        cs_positions[next_op], digest) &&
                  SignSchnorr(leaf_kp, digest, ht, sig)) {
                slot = std::move(sig);
              }
              ++next_op;
            }
          }
        }
      }
      return;
    }
  }

  // 2. Detect P2SH-wrapped SegWit v0 (P2SH-P2WPKH or P2SH-P2WSH).
  bool is_p2sh_wrapped = false;
  Bytes effective_prog = target_spk;
  if (target_spk.size() == 23 && target_spk[0] == 0xa9 &&
      target_spk[1] == 0x14 && target_spk[22] == 0x87) {
    if (txin.script_sig.size() == 23 && txin.script_sig[0] == 0x16 &&
        txin.script_sig[1] == 0x00 && txin.script_sig[2] == 0x14) {
      is_p2sh_wrapped = true;
      effective_prog.assign(txin.script_sig.begin() + 1, txin.script_sig.end());
    } else if (txin.script_sig.size() == 35 && txin.script_sig[0] == 0x22 &&
               txin.script_sig[1] == 0x00 && txin.script_sig[2] == 0x20) {
      is_p2sh_wrapped = true;
      effective_prog.assign(txin.script_sig.begin() + 1, txin.script_sig.end());
    }
  }

  // 3. SegWit v0 P2WPKH (native or P2SH-wrapped).
  if (effective_prog.size() == 22 && effective_prog[0] == 0x00 &&
      effective_prog[1] == 0x14) {
    const auto pkh = Hash160(COMPRESSED_PUBKEY_G, 33);
    Bytes prog = {0x00, 0x14};
    prog.insert(prog.end(), pkh.begin(), pkh.end());

    if (is_p2sh_wrapped) {
      txin.script_sig = {0x16};
      txin.script_sig.insert(txin.script_sig.end(), prog.begin(), prog.end());
      const auto sh = Hash160(prog.data(), prog.size());
      target_spk = {0xa9, 0x14};
      target_spk.insert(target_spk.end(), sh.begin(), sh.end());
      target_spk.push_back(0x87);
    } else {
      txin.script_sig.clear();
      target_spk = prog;
    }
    SetTargetSpk(s, idx, target_spk);

    uint8_t hash_type = 0x01;
    if (!txin.witness.empty() && !txin.witness[0].empty() &&
        IsValidSegwitV0HashType(txin.witness[0].back())) {
      hash_type = txin.witness[0].back();
    }

    Bytes script_code = {0x76, 0xa9, 0x14};
    script_code.insert(script_code.end(), pkh.begin(), pkh.end());
    script_code.push_back(0x88);
    script_code.push_back(0xac);

    Hash32 digest{};
    Bytes der_sig;
    if (ComputeSegwitV0Sighash(s, idx, script_code, hash_type, digest) &&
        SignEcdsaDer(digest, hash_type, der_sig)) {
      txin.witness.clear();
      txin.witness.push_back(std::move(der_sig));
      txin.witness.emplace_back(COMPRESSED_PUBKEY_G, COMPRESSED_PUBKEY_G + 33);
    }
    return;
  }

  // 4. SegWit v0 P2WSH (native or P2SH-wrapped).
  if (effective_prog.size() == 34 && effective_prog[0] == 0x00 &&
      effective_prog[1] == 0x20 && !txin.witness.empty()) {
    const Bytes &wscript = txin.witness.back();
    const Hash32 wsh = Sha256(wscript.data(), wscript.size());
    Bytes prog = {0x00, 0x20};
    prog.insert(prog.end(), wsh.begin(), wsh.end());

    if (is_p2sh_wrapped) {
      txin.script_sig = {0x22};
      txin.script_sig.insert(txin.script_sig.end(), prog.begin(), prog.end());
      const auto sh = Hash160(prog.data(), prog.size());
      target_spk = {0xa9, 0x14};
      target_spk.insert(target_spk.end(), sh.begin(), sh.end());
      target_spk.push_back(0x87);
    } else {
      txin.script_sig.clear();
      target_spk = prog;
    }
    SetTargetSpk(s, idx, target_spk);

    const auto cs_ops = ScanV0ChecksigOps(wscript);
    if (!cs_ops.empty() && txin.witness.size() >= 2) {
      size_t op_i = 0;
      for (size_t wi = txin.witness.size() - 1;
           wi-- > 0 && op_i < cs_ops.size();) {
        Bytes &slot = txin.witness[wi];
        // Skip empty NULLDUMMY element for OP_CHECKMULTISIG.
        if (slot.empty() && cs_ops[op_i].second)
          continue;
        if (slot.size() >= 8 && slot.size() <= 74 && slot[0] == 0x30) {
          uint8_t ht =
              IsValidSegwitV0HashType(slot.back()) ? slot.back() : 0x01;
          const size_t off = cs_ops[op_i].first;
          Bytes sub_script(wscript.begin() + static_cast<ptrdiff_t>(off),
                           wscript.end());
          Hash32 digest{};
          Bytes der_sig;
          if (ComputeSegwitV0Sighash(s, idx, sub_script, ht, digest) &&
              SignEcdsaDer(digest, ht, der_sig)) {
            slot = std::move(der_sig);
          }
          if (!cs_ops[op_i].second) {
            ++op_i;
          }
        }
      }
    }
    (void)rng;
  }
}

inline Bytes MakeTapscriptChecksig() {
  Bytes script;
  script.push_back(0x20); // push 32-byte x-only pubkey G
  script.insert(script.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
  script.push_back(0xac); // OP_CHECKSIG
  return script;
}

inline Bytes MakeTapscriptChecksigAdd() {
  Bytes script;
  script.push_back(0x20);
  script.insert(script.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
  script.push_back(0xac); // OP_CHECKSIG
  script.push_back(0x20);
  script.insert(script.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
  script.push_back(0xba); // OP_CHECKSIGADD
  script.push_back(0x52); // OP_2
  script.push_back(0x87); // OP_EQUAL
  return script;
}

inline Bytes MakeV0ChecksigScript() {
  Bytes script;
  script.push_back(0x21); // push 33-byte compressed pubkey G
  script.insert(script.end(), COMPRESSED_PUBKEY_G, COMPRESSED_PUBKEY_G + 33);
  script.push_back(0xac); // OP_CHECKSIG
  return script;
}

inline Bytes MakeV0MultisigScript() {
  Bytes script;
  script.push_back(0x51); // OP_1
  script.push_back(0x21);
  script.insert(script.end(), COMPRESSED_PUBKEY_G, COMPRESSED_PUBKEY_G + 33);
  script.push_back(0x51); // OP_1
  script.push_back(0xae); // OP_CHECKMULTISIG
  return script;
}

// Seeds a valid signed witness spend of one of 7 archetypes when the incoming
// corpus buffer does not parse as a WitnessSpendInput + transaction.
inline ParsedWitnessSpend BuildSeedSpend(std::mt19937 &rng) {
  ParsedWitnessSpend s;
  s.flags = bitcoinfuzz::WITNESS_SPEND_FLAGS_MASK;
  s.input_index = 0;
  s.spent_amount = 1000000;
  s.has_multi_prevouts = false;

  s.tx.version = 2;
  s.tx.locktime = 0;
  TxIn in;
  in.sequence = 0xfffffffeU;
  s.tx.vin.push_back(in);

  TxOut out;
  out.value = 1000;
  out.script_pubkey = {0x51}; // OP_TRUE
  s.tx.vout.push_back(out);

  const int archetype = static_cast<int>(rng() % 7);
  switch (archetype) {
  case 0: {
    // Taproot BIP-341 key-path spend (validly signed by RecommitAndResign).
    s.spent_script_pubkey = {0x51, 0x20};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), INTERNAL_PUBKEY_G,
                                 INTERNAL_PUBKEY_G + 32);
    s.tx.vin[0].witness = {Bytes(64, 0x00)};
    break;
  }
  case 1: {
    // Taproot BIP-342 script-path with OP_CHECKSIG (+ optional CODESEPARATOR).
    s.spent_script_pubkey = {0x51, 0x20};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), INTERNAL_PUBKEY_G,
                                 INTERNAL_PUBKEY_G + 32);
    Bytes script = MakeTapscriptChecksig();
    if (rng() % 3 == 0) {
      script.insert(script.begin(), 0xab); // OP_CODESEPARATOR
    }
    Bytes cb = {0xc0};
    cb.insert(cb.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
    s.tx.vin[0].witness = {Bytes(64, 0x00), std::move(script), std::move(cb)};
    break;
  }
  case 2: {
    // Taproot BIP-342 script-path with OP_CHECKSIGADD 2-of-2.
    s.spent_script_pubkey = {0x51, 0x20};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), INTERNAL_PUBKEY_G,
                                 INTERNAL_PUBKEY_G + 32);
    Bytes cb = {0xc0};
    cb.insert(cb.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
    s.tx.vin[0].witness = {Bytes(64, 0x00), Bytes(64, 0x00),
                           MakeTapscriptChecksigAdd(), std::move(cb)};
    break;
  }
  case 3: {
    // Taproot BIP-342 script-path with OP_SUCCESS or arithmetic/timelock.
    s.spent_script_pubkey = {0x51, 0x20};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), INTERNAL_PUBKEY_G,
                                 INTERNAL_PUBKEY_G + 32);
    Bytes script;
    std::vector<Bytes> items;
    if (rng() % 2 == 0) {
      script.push_back(OP_SUCCESS_OPCODES[rng() % sizeof(OP_SUCCESS_OPCODES)]);
      script.push_back(0x6a); // OP_RETURN after OP_SUCCESS must still pass
    } else {
      // OP_1 OP_CLTV OP_DROP OP_1 OP_CSV OP_DROP OP_ADD OP_EQUAL
      s.tx.locktime = 10;
      s.tx.vin[0].sequence = 10;
      script = {0x51, 0xb1, 0x75, 0x51, 0xb2, 0x75, 0x93, 0x87};
      items = {{0x03}, {0x01}, {0x02}};
    }
    Bytes cb = {0xc0};
    cb.insert(cb.end(), INTERNAL_PUBKEY_G, INTERNAL_PUBKEY_G + 32);
    items.push_back(std::move(script));
    items.push_back(std::move(cb));
    s.tx.vin[0].witness = std::move(items);
    break;
  }
  case 4: {
    // SegWit v0 P2WPKH (validly signed via BIP-143).
    const auto pkh = Hash160(COMPRESSED_PUBKEY_G, 33);
    s.spent_script_pubkey = {0x00, 0x14};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), pkh.begin(),
                                 pkh.end());
    s.tx.vin[0].witness = {
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01},
        Bytes(COMPRESSED_PUBKEY_G, COMPRESSED_PUBKEY_G + 33)};
    break;
  }
  case 5: {
    // SegWit v0 P2WSH (OP_CHECKSIG or 1-of-1 OP_CHECKMULTISIG).
    Bytes wscript =
        (rng() % 2 == 0) ? MakeV0ChecksigScript() : MakeV0MultisigScript();
    const Hash32 wsh = Sha256(wscript.data(), wscript.size());
    s.spent_script_pubkey = {0x00, 0x20};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), wsh.begin(),
                                 wsh.end());
    Bytes dummy_der = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01};
    if (wscript.back() == 0xae) {
      s.tx.vin[0].witness = {{}, dummy_der, std::move(wscript)};
    } else {
      s.tx.vin[0].witness = {dummy_der, std::move(wscript)};
    }
    break;
  }
  default: {
    // P2SH-wrapped P2WPKH.
    const auto pkh = Hash160(COMPRESSED_PUBKEY_G, 33);
    Bytes redeem = {0x00, 0x14};
    redeem.insert(redeem.end(), pkh.begin(), pkh.end());
    s.tx.vin[0].script_sig = {0x16};
    s.tx.vin[0].script_sig.insert(s.tx.vin[0].script_sig.end(), redeem.begin(),
                                  redeem.end());
    const auto sh = Hash160(redeem.data(), redeem.size());
    s.spent_script_pubkey = {0xa9, 0x14};
    s.spent_script_pubkey.insert(s.spent_script_pubkey.end(), sh.begin(),
                                 sh.end());
    s.spent_script_pubkey.push_back(0x87);
    s.tx.vin[0].witness = {
        {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01},
        Bytes(COMPRESSED_PUBKEY_G, COMPRESSED_PUBKEY_G + 33)};
    break;
  }
  }

  RecommitAndResign(s, rng);
  return s;
}

inline void MutateBytesWithLibFuzzer(Bytes &buf, size_t max_growth,
                                     size_t hard_cap) {
  const size_t old_size = buf.size();
  const size_t cap = std::min(old_size + max_growth, hard_cap);
  if (cap == 0)
    return;
  buf.resize(cap);
  const size_t new_size = LLVMFuzzerMutate(buf.data(), old_size, cap);
  buf.resize(std::min(new_size, hard_cap));
}

inline void MutateCommittedScript(Bytes &script, bool is_tapscript,
                                  std::mt19937 &rng) {
  static constexpr uint8_t INTERESTING_OPS[] = {
      0x00, 0x51, 0x52, 0x63, 0x64, 0x67, 0x68, 0x69, 0x75, 0x76,
      0x7c, 0x87, 0x88, 0x93, 0x94, 0xab, 0xac, 0xad, 0xb1, 0xb2};

  switch (rng() % 5) {
  case 0:
    // Mutate existing committed script bytes via libFuzzer.
    MutateBytesWithLibFuzzer(script, 16, 256);
    break;
  case 1: {
    // Insert an interesting consensus/control-flow opcode.
    const size_t pos = script.empty() ? 0 : (rng() % (script.size() + 1));
    uint8_t op = INTERESTING_OPS[rng() % sizeof(INTERESTING_OPS)];
    if (is_tapscript && rng() % 4 == 0) {
      op = OP_SUCCESS_OPCODES[rng() % sizeof(OP_SUCCESS_OPCODES)];
    } else if (is_tapscript && rng() % 4 == 0) {
      op = 0xba; // OP_CHECKSIGADD
    }
    script.insert(script.begin() + static_cast<ptrdiff_t>(pos), op);
    break;
  }
  case 2:
    // Prepend or append OP_CODESEPARATOR to exercise sighash codeSepPos.
    if (rng() % 2 == 0) {
      script.insert(script.begin(), 0xab);
    } else {
      script.push_back(0xab);
    }
    break;
  case 3:
    // Replace with a signature-checking or timelock script template.
    if (is_tapscript) {
      script = (rng() % 2 == 0) ? MakeTapscriptChecksig()
                                : MakeTapscriptChecksigAdd();
    } else {
      script =
          (rng() % 2 == 0) ? MakeV0ChecksigScript() : MakeV0MultisigScript();
    }
    break;
  default:
    // Trim a byte from the script if non-empty.
    if (!script.empty()) {
      script.erase(script.begin() +
                   static_cast<ptrdiff_t>(rng() % script.size()));
    }
    break;
  }
}

// Applies one structure-aware mutation to a parsed WitnessSpendInput.
inline void MutateSpendOnce(ParsedWitnessSpend &s, std::mt19937 &rng) {
  if (s.tx.vin.empty())
    return;
  const size_t idx = EffectiveInputIdx(s);
  TxIn &txin = s.tx.vin[idx];
  const Bytes target_spk = PrevoutSpk(s, idx);
  const bool is_taproot =
      target_spk.size() == 34 && target_spk[0] == 0x51 && target_spk[1] == 0x20;
  const bool is_p2wsh =
      target_spk.size() == 34 && target_spk[0] == 0x00 && target_spk[1] == 0x20;

  switch (rng() % 9) {
  case 0: {
    // Mutate verification flags.
    if (rng() % 4 == 0) {
      s.flags = bitcoinfuzz::WITNESS_SPEND_FLAGS_MASK;
    } else {
      const uint32_t bit =
          INDIVIDUAL_FLAGS[rng() % std::size(INDIVIDUAL_FLAGS)];
      s.flags ^= bit;
    }
    break;
  }
  case 1: {
    // Mutate committed script (Tapscript leaf or P2WSH witnessScript).
    if (is_taproot && !txin.witness.empty()) {
      const size_t stack_len =
          txin.witness.size() - (HasAnnex(txin.witness) ? 1 : 0);
      if (stack_len >= 2) {
        MutateCommittedScript(txin.witness[stack_len - 2],
                              /*is_tapscript=*/true, rng);
        break;
      }
    }
    if (is_p2wsh && !txin.witness.empty()) {
      MutateCommittedScript(txin.witness.back(), /*is_tapscript=*/false, rng);
      break;
    }
    // Otherwise mutate a witness item if present.
    if (!txin.witness.empty()) {
      MutateBytesWithLibFuzzer(txin.witness[rng() % txin.witness.size()], 16,
                               256);
    }
    break;
  }
  case 2: {
    // Mutate transaction version, locktime, or input sequence (CLTV/CSV edges).
    static constexpr int32_t VERSIONS[] = {0, 1, 2, 3, -1};
    static constexpr uint32_t LOCKTIMES[] = {
        0, 1, 100, 499999999U, 500000000U, 500000100U, 0xffffffffU};
    static constexpr uint32_t SEQUENCES[] = {
        0U, 1U, 10U, 0x0040000aU, 0x80000000U, 0xfffffffeU, 0xffffffffU};
    switch (rng() % 3) {
    case 0:
      s.tx.version = VERSIONS[rng() % std::size(VERSIONS)];
      break;
    case 1:
      s.tx.locktime = (rng() % 2 == 0) ? LOCKTIMES[rng() % std::size(LOCKTIMES)]
                                       : static_cast<uint32_t>(rng());
      break;
    default:
      txin.sequence = (rng() % 2 == 0) ? SEQUENCES[rng() % std::size(SEQUENCES)]
                                       : static_cast<uint32_t>(rng());
      break;
    }
    break;
  }
  case 3: {
    // Mutate sighash type on an existing signature slot.
    if (is_taproot && !txin.witness.empty()) {
      const size_t stack_len =
          txin.witness.size() - (HasAnnex(txin.witness) ? 1 : 0);
      for (size_t wi = 0; wi < stack_len; ++wi) {
        Bytes &slot = txin.witness[wi];
        if (slot.size() == 64 || slot.size() == 65) {
          const uint8_t ht =
              VALID_TAPROOT_HASHTYPES[rng() %
                                      std::size(VALID_TAPROOT_HASHTYPES)];
          slot.resize(64);
          if (ht != 0x00) {
            slot.push_back(ht);
          }
          break;
        }
      }
    } else if (!txin.witness.empty() && txin.witness[0].size() >= 8 &&
               txin.witness[0][0] == 0x30) {
      txin.witness[0].back() =
          VALID_SEGWIT_V0_HASHTYPES[rng() %
                                    std::size(VALID_SEGWIT_V0_HASHTYPES)];
    }
    break;
  }
  case 4: {
    // Toggle or mutate Taproot annex or control block Merkle siblings/leaf ver.
    if (!is_taproot || txin.witness.empty())
      break;
    const bool has_annex = HasAnnex(txin.witness);
    if (rng() % 2 == 0) {
      if (has_annex) {
        txin.witness.pop_back();
      } else {
        Bytes annex = {0x50};
        const size_t extra = rng() % 16;
        for (size_t i = 0; i < extra; ++i) {
          annex.push_back(static_cast<uint8_t>(rng() & 0xff));
        }
        txin.witness.push_back(std::move(annex));
      }
    } else {
      const size_t stack_len = txin.witness.size() - (has_annex ? 1 : 0);
      if (stack_len >= 2) {
        Bytes &cb = txin.witness[stack_len - 1];
        if (cb.size() >= 33 && ((cb.size() - 33) % 32 == 0)) {
          if (rng() % 3 == 0) {
            // Mutate leaf version (0xc0 or unknown upgradable even version).
            const uint8_t lv =
                (rng() % 2 == 0) ? 0xc0 : static_cast<uint8_t>(rng() & 0xfe);
            cb[0] = static_cast<uint8_t>(lv | (cb[0] & 1));
          } else if (cb.size() < 33 + 3 * 32 && rng() % 2 == 0) {
            // Add a 32-byte Merkle branch sibling.
            for (int i = 0; i < 32; ++i) {
              cb.push_back(static_cast<uint8_t>(rng() & 0xff));
            }
          } else if (cb.size() > 33) {
            // Drop the last Merkle branch sibling.
            cb.resize(cb.size() - 32);
          }
        }
      }
    }
    break;
  }
  case 5: {
    // Mutate spent amount or transaction outputs.
    static constexpr int64_t AMOUNTS[] = {
        0, 1, 546, 1000000, 2100000000000000LL, 2100000000000001LL};
    if (rng() % 2 == 0) {
      const int64_t amt = AMOUNTS[rng() % std::size(AMOUNTS)];
      if (UsesMultiPrevouts(s)) {
        s.all_spent_amounts[idx] = amt;
      } else {
        s.spent_amount = amt;
      }
    } else if (s.tx.vout.size() < 4 && rng() % 2 == 0) {
      TxOut extra;
      extra.value = AMOUNTS[rng() % 5];
      extra.script_pubkey = {0x51};
      s.tx.vout.push_back(std::move(extra));
    } else if (!s.tx.vout.empty()) {
      if (s.tx.vout.size() > 1 && rng() % 3 == 0) {
        s.tx.vout.pop_back();
      } else {
        TxOut &o = s.tx.vout[rng() % s.tx.vout.size()];
        o.value = AMOUNTS[rng() % 5];
        MutateBytesWithLibFuzzer(o.script_pubkey, 8, 64);
      }
    }
    break;
  }
  case 6: {
    // Add/remove inputs and toggle multi-input prevouts to test BIP-341/143
    // multi-input sighashes.
    if (s.tx.vin.size() < 4 && rng() % 2 == 0) {
      TxIn extra;
      extra.prevout_hash[0] = static_cast<uint8_t>(s.tx.vin.size());
      extra.prevout_n = static_cast<uint32_t>(s.tx.vin.size());
      extra.sequence = 0xfffffffeU;
      s.tx.vin.push_back(std::move(extra));
    } else if (s.tx.vin.size() > 1 && rng() % 2 == 0) {
      s.tx.vin.pop_back();
    }
    const size_t n = s.tx.vin.size();
    s.has_multi_prevouts = (n > 1) || (rng() % 2 == 0);
    if (s.has_multi_prevouts) {
      s.all_spent_amounts.resize(n, s.spent_amount);
      s.all_spent_spks.resize(n, target_spk);
      s.input_index = static_cast<uint32_t>(rng() % n);
    } else {
      s.all_spent_amounts.clear();
      s.all_spent_spks.clear();
    }
    break;
  }
  case 7: {
    // Mutate witness stack structure (push/pop/modify non-script items).
    if (txin.witness.size() < 8 && rng() % 2 == 0) {
      Bytes item;
      const size_t len = rng() % 4;
      for (size_t i = 0; i < len; ++i) {
        item.push_back(static_cast<uint8_t>(rng() & 0xff));
      }
      txin.witness.insert(txin.witness.begin(), std::move(item));
    } else if (txin.witness.size() > 1) {
      txin.witness.erase(txin.witness.begin());
    }
    break;
  }
  default: {
    // Occasionally switch spend archetype while keeping existing tx context.
    if (rng() % 3 == 0) {
      ParsedWitnessSpend fresh = BuildSeedSpend(rng);
      fresh.flags = s.flags;
      fresh.tx.version = s.tx.version;
      fresh.tx.locktime = s.tx.locktime;
      s = std::move(fresh);
    } else {
      // Mutate prevout outpoint hash/index.
      txin.prevout_hash[rng() % 32] ^= static_cast<uint8_t>(1U << (rng() % 8));
      txin.prevout_n ^= static_cast<uint32_t>(rng() & 0xf);
    }
    break;
  }
  }
}

} // namespace witness_spend_mutator

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *fuzz_data, size_t size,
                                          size_t max_size, unsigned int seed) {
  using namespace witness_spend_mutator;
  std::mt19937 rng(seed);

  ParsedWitnessSpend spend;
  if (!ParseWitnessSpend(fuzz_data, size, spend)) {
    spend = BuildSeedSpend(rng);
  } else {
    const size_t rounds = 1 + (rng() % 3);
    for (size_t i = 0; i < rounds; ++i) {
      MutateSpendOnce(spend, rng);
    }
    // ~7/8 of the time, recompute commitments and signatures so mutations
    // reach deep script/sighash verification logic; ~1/8 leave broken to
    // cover invalid-signature and commitment-mismatch rejection paths.
    if (rng() % 8 != 0) {
      RecommitAndResign(spend, rng);
    } else if (rng() % 2 == 0) {
      // Also exercise raw byte-level perturbations on serialized inputs.
      const size_t mutated = LLVMFuzzerMutate(fuzz_data, size, max_size);
      return mutated;
    }
  }

  const Bytes out = SerializeWitnessSpend(spend);
  if (out.size() > max_size) {
    return LLVMFuzzerMutate(fuzz_data, size, max_size);
  }
  std::memcpy(fuzz_data, out.data(), out.size());
  return out.size();
}

#endif // BITCOINFUZZ_CUSTOMMUTATOR_WITNESS_SPEND_H
