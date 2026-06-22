// Shared parameter selection, database geometry, encoding, and proto wire
// helpers for the Qor hintless-SimplePIR worker (server side) and client.
//
// Both the worker and the client derive the *same* hintless-SimplePIR
// Parameters from a small public descriptor: a fixed cryptographic preset
// (selected by `parameterId`) plus per-epoch database dimensions that are
// recomputed deterministically from the record count and record size. Because
// the geometry is a pure function of the public manifest, dimensions never have
// to be transmitted or trusted: client and worker independently arrive at the
// identical matrix shape.
//
// The only per-epoch secret-free blob that must cross the wire is the server's
// HintlessPirServerPublicParams (a handful of PRNG seeds, ~100 bytes). There is
// no client-downloaded hint: that is the entire point of the hintless scheme.

#ifndef QOR_PIR_COMMON_H_
#define QOR_PIR_COMMON_H_

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "hintless_simplepir/parameters.h"
#include "linpir/parameters.h"
#include "shell_encryption/serialization.pb.h"

namespace qor_pir {

// The single pinned cryptographic parameter preset. Only the database geometry
// (db_rows, db_cols, db_record_bit_size) varies per epoch; every lattice
// parameter below is fixed and security-reviewed. Bumping any value here is a
// breaking parameter change and must come with a new kParameterId.
inline constexpr char kParameterId[] = "hintless-simplepir-rlwe64-v1";

// Database geometry for one epoch, derived from the public manifest.
struct DbGeometry {
  int64_t db_rows = 0;
  int64_t db_cols = 0;
  int db_record_bit_size = 0;  // record_bytes * 8
  int64_t capacity = 0;        // db_rows * db_cols (>= record_count)
};

// Deterministically choose the database matrix shape.
//
// With lwe_plaintext_bit_size == 8 a record of B bytes occupies B "shards", so
// the response (download) is proportional to db_rows * B while the query
// (upload) is proportional to db_cols. Minimising db_rows*B + record_count/db_rows
// gives the balance point db_rows ~= sqrt(record_count / B). Because this is a
// pure function of (record_count, record_size) the client reproduces it exactly.
inline DbGeometry ChooseGeometry(int64_t record_count, int record_size_bytes) {
  DbGeometry g;
  if (record_size_bytes <= 0) return g;  // caller validates; 0 => invalid
  int64_t n = std::max<int64_t>(record_count, 1);
  g.db_record_bit_size = record_size_bytes * 8;

  double ideal = std::sqrt(static_cast<double>(n) /
                           static_cast<double>(record_size_bytes));
  int64_t rows = static_cast<int64_t>(std::llround(ideal));
  rows = std::clamp<int64_t>(rows, 1, n);
  int64_t cols = (n + rows - 1) / rows;  // ceil(n / rows)
  // The hintless-SimplePIR LWE query encodes one coefficient per column, and
  // the RLWE packing requires that count to be even. Round db_cols up to the
  // next even value, then take the minimum number of rows that still spans the
  // record count so the zero-padded capacity stays tight.
  auto round_up_even = [](int64_t v) { return v + (v & 1); };
  cols = std::max<int64_t>(round_up_even(cols), 2);
  rows = (n + cols - 1) / cols;

  g.db_rows = rows;
  g.db_cols = cols;
  g.capacity = rows * cols;
  return g;
}

// Build the full hintless-SimplePIR Parameters for an epoch. `parameter_id`
// selects the fixed preset; the geometry comes from ChooseGeometry().
inline absl::StatusOr<hintless_pir::hintless_simplepir::Parameters>
BuildParameters(absl::string_view parameter_id, const DbGeometry& geometry) {
  using Parameters = hintless_pir::hintless_simplepir::Parameters;
  using RlweInteger = Parameters::RlweInteger;
  if (parameter_id != kParameterId) {
    return absl::InvalidArgumentError("unknown_parameter_id");
  }
  if (geometry.db_rows <= 0 || geometry.db_cols <= 0 ||
      geometry.db_record_bit_size <= 0) {
    return absl::InvalidArgumentError("invalid_geometry");
  }
  return Parameters{
      .db_rows = geometry.db_rows,
      .db_cols = geometry.db_cols,
      .db_record_bit_size = geometry.db_record_bit_size,
      .lwe_secret_dim = 1400,
      .lwe_modulus_bit_size = 32,
      .lwe_plaintext_bit_size = 8,
      .lwe_error_variance = 8,
      .linpir_params =
          hintless_pir::linpir::RlweParameters<RlweInteger>{
              .log_n = 12,
              .qs = {35184371884033ULL, 35184371703809ULL},  // 90 bits
              .ts = {2056193, 1990657},                      // 42 bits
              .gadget_log_bs = {16, 16},
              .error_variance = 8,
              .prng_type = rlwe::PRNG_TYPE_HKDF,
              .rows_per_block = 1024,
          },
      .prng_type = rlwe::PRNG_TYPE_HKDF,
  };
}

// ---------------------------------------------------------------------------
// Base64 (URL-safe, no padding) used for every opaque blob on the wire. Decode
// is tolerant of standard and URL-safe alphabets, with or without padding, so
// it interoperates with the Node server (which uploads records as standard
// base64) and the client/worker (which exchange URL-safe, no-pad blobs).
// ---------------------------------------------------------------------------

inline std::string Base64UrlEncode(absl::string_view in) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve(((in.size() + 2) / 3) * 4);
  size_t i = 0;
  for (; i + 3 <= in.size(); i += 3) {
    uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                 (static_cast<uint8_t>(in[i + 1]) << 8) |
                 static_cast<uint8_t>(in[i + 2]);
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    out.push_back(kAlphabet[(n >> 6) & 63]);
    out.push_back(kAlphabet[n & 63]);
  }
  if (i + 1 == in.size()) {
    uint32_t n = static_cast<uint8_t>(in[i]) << 16;
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
  } else if (i + 2 == in.size()) {
    uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                 (static_cast<uint8_t>(in[i + 1]) << 8);
    out.push_back(kAlphabet[(n >> 18) & 63]);
    out.push_back(kAlphabet[(n >> 12) & 63]);
    out.push_back(kAlphabet[(n >> 6) & 63]);
  }
  return out;
}

inline absl::StatusOr<std::string> Base64Decode(absl::string_view in) {
  auto val = [](char c) -> int {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;
    if (c == '/' || c == '_') return 63;
    return -1;
  };
  std::string out;
  out.reserve((in.size() / 4) * 3 + 3);
  uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
    int v = val(c);
    if (v < 0) return absl::InvalidArgumentError("invalid_base64");
    buf = (buf << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xff));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Proto <-> opaque base64 string helpers. The opaque query/response blobs that
// the Node server forwards verbatim are simply base64url(proto bytes); there is
// no extra JSON envelope, so the large response carries no double-base64 tax.
// ---------------------------------------------------------------------------

template <typename Proto>
inline std::string ProtoToBase64(const Proto& proto) {
  std::string bytes;
  const bool ok = proto.SerializeToString(&bytes);
  (void)ok;  // proto2 with only optional fields cannot fail serialization
  return Base64UrlEncode(bytes);
}

template <typename Proto>
inline absl::StatusOr<Proto> ProtoFromBase64(absl::string_view b64) {
  auto bytes = Base64Decode(b64);
  if (!bytes.ok()) return bytes.status();
  Proto proto;
  if (!proto.ParseFromString(*bytes)) {
    return absl::InvalidArgumentError("invalid_proto");
  }
  return proto;
}

}  // namespace qor_pir

#endif  // QOR_PIR_COMMON_H_
