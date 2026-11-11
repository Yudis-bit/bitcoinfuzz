// Tests for the verify_witness_spend structure-aware custom mutator:
// FuzzedDataProvider wire round-trip, BIP-341 key-path and Tapscript Schnorr
// signing, BIP-143 SegWit v0 ECDSA signing, and in-place mutation preservation.
#include "../mutators/witness_spend.h"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                   size_t max_size) {
  if (size > 0 && data != nullptr) {
    data[0] ^= 0x01;
  }
  (void)max_size;
  return size;
}

namespace {
using namespace witness_spend_mutator;

void TestFdpRoundTrip() {
  ParsedWitnessSpend orig;
  orig.flags = bitcoinfuzz::WITNESS_SPEND_FLAG_P2SH |
               bitcoinfuzz::WITNESS_SPEND_FLAG_WITNESS |
               bitcoinfuzz::WITNESS_SPEND_FLAG_TAPROOT;
  orig.input_index = 1;
  orig.spent_amount = 2100000000000000LL;
  orig.spent_script_pubkey = {0x51, 0x20, 0xaa, 0xbb};
  orig.has_multi_prevouts = true;
  orig.all_spent_amounts = {1000000, 2500000};
  orig.all_spent_spks = {{0x00, 0x14, 0x11, 0x22}, {0x51, 0x20, 0x33, 0x44}};

  orig.tx.version = 2;
  orig.tx.locktime = 500000123U;
  TxIn in0, in1;
  in0.prevout_hash[0] = 0xde;
  in0.prevout_n = 7;
  in0.sequence = 0xfffffffeU;
  in0.witness = {{0x01, 0x02}};
  in1.prevout_hash[31] = 0xad;
  in1.prevout_n = 3;
  in1.script_sig = {0x51};
  in1.sequence = 10;
  in1.witness = {{0x03, 0x04, 0x05}, {0x06}};
  orig.tx.vin = {in0, in1};
  orig.tx.vout = {{999, {0x51}}, {1234, {0x00, 0x14}}};

  const Bytes raw = SerializeWitnessSpend(orig);
  ParsedWitnessSpend decoded;
  assert(ParseWitnessSpend(raw.data(), raw.size(), decoded));
  assert(decoded.flags == orig.flags);
  assert(decoded.input_index == orig.input_index);
  assert(decoded.spent_amount == orig.spent_amount);
  assert(decoded.spent_script_pubkey == orig.spent_script_pubkey);
  assert(decoded.has_multi_prevouts == orig.has_multi_prevouts);
  assert(decoded.all_spent_amounts == orig.all_spent_amounts);
  assert(decoded.all_spent_spks == orig.all_spent_spks);
  assert(decoded.tx.version == orig.tx.version);
  assert(decoded.tx.locktime == orig.tx.locktime);
  assert(decoded.tx.vin.size() == 2);
  assert(decoded.tx.vin[1].prevout_n == 3);
  assert(decoded.tx.vin[1].witness == orig.tx.vin[1].witness);
  assert(decoded.tx.vout.size() == 2);
  assert(decoded.tx.vout[1].value == 1234);
}

bool VerifySpendSignatureAndCommitment(const ParsedWitnessSpend &s) {
  secp256k1_context *ctx = GetSecpCtx();
  if (!ctx || s.tx.vin.empty())
    return false;
  const size_t idx = EffectiveInputIdx(s);
  const TxIn &txin = s.tx.vin[idx];
  const Bytes &spk = PrevoutSpk(s, idx);

  // Taproot key-path or script-path
  if (spk.size() == 34 && spk[0] == 0x51 && spk[1] == 0x20 &&
      !txin.witness.empty()) {
    const bool annex_present = HasAnnex(txin.witness);
    const Bytes *annex = annex_present ? &txin.witness.back() : nullptr;
    const size_t stack_len = txin.witness.size() - (annex_present ? 1 : 0);

    if (stack_len == 1) {
      const Bytes &sig = txin.witness[0];
      if (sig.size() != 64 && sig.size() != 65)
        return false;
      const uint8_t ht = (sig.size() == 65) ? sig[64] : 0x00;
      Hash32 digest{};
      if (!ComputeTaprootSighash(s, idx, ht, annex, nullptr, 0xffffffffU,
                                 digest)) {
        return false;
      }
      secp256k1_xonly_pubkey pk;
      return secp256k1_xonly_pubkey_parse(ctx, &pk, spk.data() + 2) &&
             secp256k1_schnorrsig_verify(ctx, sig.data(), digest.data(), 32,
                                         &pk);
    }

    if (stack_len >= 2) {
      const Bytes &script = txin.witness[stack_len - 2];
      const Bytes &cb = txin.witness[stack_len - 1];
      if (cb.size() < 33 || ((cb.size() - 33) % 32 != 0))
        return false;
      const uint8_t leaf_ver = static_cast<uint8_t>(cb[0] & 0xfe);
      Hash32 root = ComputeTapLeafHash(leaf_ver, script);
      for (size_t off = 33; off < cb.size(); off += 32) {
        Hash32 sib{};
        std::memcpy(sib.data(), cb.data() + off, 32);
        root = ComputeTapBranchHash(root, sib);
      }
      uint8_t tweak_in[64];
      std::memcpy(tweak_in, cb.data() + 1, 32);
      std::memcpy(tweak_in + 32, root.data(), 32);
      const Hash32 tweak = TaggedHash("TapTweak", 8, tweak_in, 64);

      secp256k1_xonly_pubkey internal_pk;
      secp256k1_pubkey out_pk;
      if (!secp256k1_xonly_pubkey_parse(ctx, &internal_pk, cb.data() + 1) ||
          !secp256k1_xonly_pubkey_tweak_add(ctx, &out_pk, &internal_pk,
                                            tweak.data())) {
        return false;
      }
      secp256k1_xonly_pubkey out_xonly;
      int parity = 0;
      secp256k1_xonly_pubkey_from_pubkey(ctx, &out_xonly, &parity, &out_pk);
      uint8_t out_bytes[32];
      secp256k1_xonly_pubkey_serialize(ctx, out_bytes, &out_xonly);
      return (parity & 1) == (cb[0] & 1) &&
             std::memcmp(out_bytes, spk.data() + 2, 32) == 0;
    }
  }

  // SegWit v0 P2WPKH
  if (spk.size() == 22 && spk[0] == 0x00 && spk[1] == 0x14 &&
      txin.witness.size() == 2 && txin.witness[0].size() >= 9 &&
      txin.witness[1].size() == 33) {
    const auto pkh = Hash160(txin.witness[1].data(), 33);
    if (std::memcmp(pkh.data(), spk.data() + 2, 20) != 0)
      return false;
    const uint8_t ht = txin.witness[0].back();
    Bytes sc = {0x76, 0xa9, 0x14};
    sc.insert(sc.end(), pkh.begin(), pkh.end());
    sc.push_back(0x88);
    sc.push_back(0xac);
    Hash32 digest{};
    if (!ComputeSegwitV0Sighash(s, idx, sc, ht, digest))
      return false;
    secp256k1_ecdsa_signature sig;
    secp256k1_pubkey pk;
    return secp256k1_ecdsa_signature_parse_der(
               ctx, &sig, txin.witness[0].data(), txin.witness[0].size() - 1) &&
           secp256k1_ec_pubkey_parse(ctx, &pk, txin.witness[1].data(), 33) &&
           secp256k1_ecdsa_verify(ctx, &sig, digest.data(), &pk);
  }

  // SegWit v0 P2WSH
  if (spk.size() == 34 && spk[0] == 0x00 && spk[1] == 0x20 &&
      !txin.witness.empty()) {
    const Hash32 wsh =
        Sha256(txin.witness.back().data(), txin.witness.back().size());
    return std::memcmp(wsh.data(), spk.data() + 2, 32) == 0;
  }

  // P2SH-P2WPKH
  if (spk.size() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 &&
      txin.script_sig.size() == 23 && txin.script_sig[0] == 0x16) {
    const auto sh = Hash160(txin.script_sig.data() + 1, 22);
    return std::memcmp(sh.data(), spk.data() + 2, 20) == 0;
  }

  return false;
}

void TestMutatorPreservesStructureAndResigns() {
  std::mt19937 seed_rng(42);
  Bytes seed_buf = SerializeWitnessSpend(BuildSeedSpend(seed_rng));

  size_t total = 0;
  size_t parsed_ok = 0;
  size_t valid_committed = 0;
  size_t changed_fields = 0;

  for (unsigned seed = 0; seed < 512; ++seed) {
    std::vector<uint8_t> buf(4096);
    std::memcpy(buf.data(), seed_buf.data(), seed_buf.size());
    const size_t n =
        LLVMFuzzerCustomMutator(buf.data(), seed_buf.size(), buf.size(), seed);
    ++total;
    ParsedWitnessSpend out;
    if (ParseWitnessSpend(buf.data(), n, out)) {
      ++parsed_ok;
      if (VerifySpendSignatureAndCommitment(out)) {
        ++valid_committed;
      }
      if (n != seed_buf.size() ||
          std::memcmp(buf.data(), seed_buf.data(), n) != 0) {
        ++changed_fields;
      }
    }
  }

  std::printf(
      "witness_spend mutator: %zu/%zu parsed, %zu/%zu valid committed/signed, "
      "%zu/%zu mutated\n",
      parsed_ok, total, valid_committed, total, changed_fields, total);
  assert(parsed_ok * 4 > total * 3);
  assert(valid_committed * 4 > total * 3);
  assert(changed_fields * 10 > total * 9);
}

} // namespace

int main() {
  TestFdpRoundTrip();
  TestMutatorPreservesStructureAndResigns();
  std::printf("witness_spend mutator tests passed\n");
  return 0;
}
