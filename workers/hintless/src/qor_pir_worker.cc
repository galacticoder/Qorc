// Qor hintless-SimplePIR worker (server side).
//
// A separately reviewed, in-process-free HTTP service that the Node server
// talks to over localhost. It never sees plaintext indices: it builds a
// hintless-SimplePIR Server per (kind, epoch), preprocesses it, hands the
// client a tiny hint-free public-params blob, and answers opaque proto queries.
//
// Endpoints:
//   GET  /health           -> liveness + pinned identity
//   POST /v1/databases     -> upload fixed-size records, build+preprocess epoch
//   POST /v1/public-params -> fetch the hint-free server public params for epoch
//   POST /v1/query         -> answer one opaque HintlessPirRequest
//
// There is deliberately no setup/hint download endpoint: the hintless scheme
// outsources the hint to the server's LinPIR work, so the client downloads
// nothing but the per-epoch PRNG seeds.

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/serialization.pb.h"
#include "hintless_simplepir/server.h"
#include "json.hpp"
#include "httplib.h"
#include "qor/qor_pir_common.h"

namespace {

using ::hintless_pir::HintlessPirRequest;
using ::hintless_pir::hintless_simplepir::Server;
using json = nlohmann::json;

constexpr char kSourceCommit[] = "49434e086ec56d19546ca6e97353671b690ba19b";

std::string EnvStr(const char* name, const std::string& fallback) {
  const char* v = std::getenv(name);
  if (v == nullptr) return fallback;
  std::string s(v);
  return s.empty() ? fallback : s;
}

int64_t EnvInt(const char* name, int64_t fallback, int64_t lo, int64_t hi) {
  const char* v = std::getenv(name);
  if (v == nullptr) return fallback;
  char* end = nullptr;
  long long parsed = std::strtoll(v, &end, 10);
  if (end == v) return fallback;
  if (parsed < lo) return lo;
  if (parsed > hi) return hi;
  return static_cast<int64_t>(parsed);
}

// One built + preprocessed epoch. Immutable after construction except that
// HandleRequest is serialised through g_compute_mu.
struct Db {
  std::string kind;
  std::string epoch_id;
  std::string parameter_id;
  std::string database_digest;
  int64_t record_count = 0;
  int record_size = 0;
  int64_t db_rows = 0;
  int64_t db_cols = 0;
  std::unique_ptr<Server> server;
  std::string public_params_b64;
};

std::mutex g_map_mu;
std::map<std::string, std::shared_ptr<Db>> g_dbs;  // key = kind\0epoch
// Insertion-ordered keys (oldest first) bounding g_dbs. The discovery epoch id includes the
// DB digest, so it rolls on every publish/refresh (~30s); without a bound g_dbs would grow
// unbounded. Keep the most recent N epochs loaded — far more than any in-flight lookup spans —
// so a lookup completes even as the epoch churns, while memory stays bounded. Must be mutated
// only under g_map_mu.
std::deque<std::string> g_db_order;
// Serialises all heavy lattice work (build/preprocess/answer). Lookups are
// not high-QPS and Tor dominates latency, so a single compute lock keeps the
// memory model trivially correct.
std::mutex g_compute_mu;

std::string MapKey(const std::string& kind, const std::string& epoch) {
  return kind + std::string(1, '\0') + epoch;
}

std::shared_ptr<Db> GetDb(const std::string& kind, const std::string& epoch) {
  std::lock_guard<std::mutex> lock(g_map_mu);
  auto it = g_dbs.find(MapKey(kind, epoch));
  return it == g_dbs.end() ? nullptr : it->second;
}

void SetHeaders(httplib::Response& res) {
  res.set_header("x-content-type-options", "nosniff");
  res.set_header("cache-control", "no-store");
}

void WriteJson(httplib::Response& res, int status, const json& body) {
  res.status = status;
  res.set_content(body.dump(), "application/json");
}

void WriteError(httplib::Response& res, int status, const std::string& code) {
  WriteJson(res, status, json{{"ok", false}, {"error", code}});
}

bool Authorized(const httplib::Request& req) {
  std::string token = EnvStr("QOR_PIR_AUTH_TOKEN", "");
  if (token.empty()) return true;
  auto it = req.headers.find("authorization");
  return it != req.headers.end() && it->second == ("Bearer " + token);
}

std::string ConfiguredParameterId() {
  return EnvStr("QOR_PIR_PARAMETER_ID", qor_pir::kParameterId);
}

// ---- POST /v1/databases ----------------------------------------------------
void HandleUpload(const httplib::Request& req, httplib::Response& res) {
  if (!Authorized(req)) return WriteError(res, 401, "unauthorized");
  json body;
  try {
    body = json::parse(req.body);
  } catch (...) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_json"}});
  }

  const auto& m = body["manifest"];
  if (!m.is_object() || !body["records"].is_array()) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_manifest"}});
  }
  std::string kind = m.value("kind", "");
  std::string epoch_id = m.value("epochId", "");
  std::string parameter_id = m.value("parameterId", "");
  std::string database_digest = m.value("databaseDigest", "");
  int64_t record_count = m.value("recordCount", 0);
  int record_size = m.value("recordSize", 0);

  if (kind.empty() || epoch_id.empty()) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_manifest"}});
  }
  if (parameter_id != ConfiguredParameterId()) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "parameter_mismatch"}});
  }
  if (record_count <= 0 || record_size <= 0) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_record_layout"}});
  }
  const auto& records = body["records"];
  if (static_cast<int64_t>(records.size()) != record_count) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "record_count_mismatch"}});
  }
  int64_t max_bytes = EnvInt("QOR_PIR_MAX_DATABASE_BYTES", int64_t{2} << 30, 4096,
                             int64_t{1} << 40);
  if (record_count * static_cast<int64_t>(record_size) > max_bytes) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "database_too_large"}});
  }

  // Idempotent reuse: identical (kind,epoch,digest) already built.
  if (auto existing = GetDb(kind, epoch_id);
      existing && existing->database_digest == database_digest) {
    return WriteJson(res, 200,
                     json{{"accepted", true},
                          {"epochId", epoch_id},
                          {"databaseDigest", database_digest},
                          {"parameterId", parameter_id},
                          {"recordCount", existing->record_count},
                          {"recordSize", existing->record_size},
                          {"dbRows", existing->db_rows},
                          {"dbCols", existing->db_cols},
                          {"publicParams", existing->public_params_b64}});
  }

  qor_pir::DbGeometry geo = qor_pir::ChooseGeometry(record_count, record_size);
  auto params_or = qor_pir::BuildParameters(parameter_id, geo);
  if (!params_or.ok()) {
    return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_geometry"}});
  }

  auto db = std::make_shared<Db>();
  db->kind = kind;
  db->epoch_id = epoch_id;
  db->parameter_id = parameter_id;
  db->database_digest = database_digest;
  db->record_count = record_count;
  db->record_size = record_size;
  db->db_rows = geo.db_rows;
  db->db_cols = geo.db_cols;

  {
    std::lock_guard<std::mutex> compute(g_compute_mu);
    auto server_or = Server::Create(*params_or);
    if (!server_or.ok()) {
      return WriteJson(res, 500, json{{"accepted", false}, {"error", "server_create_failed"}});
    }
    db->server = std::move(server_or).value();
    for (int64_t i = 0; i < record_count; ++i) {
      auto raw = qor_pir::Base64Decode(records[i].get<std::string>());
      if (!raw.ok()) {
        return WriteJson(res, 400, json{{"accepted", false}, {"error", "invalid_record_encoding"}});
      }
      if (static_cast<int>(raw->size()) != record_size) {
        return WriteJson(res, 400, json{{"accepted", false}, {"error", "record_size_mismatch"}});
      }
      if (auto st = db->server->GetDatabase()->Append(*raw); !st.ok()) {
        return WriteJson(res, 400, json{{"accepted", false}, {"error", "append_failed"}});
      }
    }
    if (auto st = db->server->Preprocess(); !st.ok()) {
      return WriteJson(res, 500, json{{"accepted", false}, {"error", "preprocess_failed"}});
    }
    db->public_params_b64 = qor_pir::ProtoToBase64(db->server->GetPublicParams());
  }

  {
    std::lock_guard<std::mutex> lock(g_map_mu);
    const std::string key = MapKey(kind, epoch_id);
    g_dbs[key] = db;
    // Bump to most-recent and evict the oldest beyond the cap.
    g_db_order.erase(std::remove(g_db_order.begin(), g_db_order.end(), key), g_db_order.end());
    g_db_order.push_back(key);
    const size_t max_loaded = static_cast<size_t>(
        EnvInt("QOR_PIR_MAX_LOADED_EPOCHS", 32, 2, 4096));
    while (g_db_order.size() > max_loaded) {
      g_dbs.erase(g_db_order.front());
      g_db_order.pop_front();
    }
  }

  WriteJson(res, 200,
            json{{"accepted", true},
                 {"epochId", epoch_id},
                 {"databaseDigest", database_digest},
                 {"parameterId", parameter_id},
                 {"recordCount", record_count},
                 {"recordSize", record_size},
                 {"dbRows", geo.db_rows},
                 {"dbCols", geo.db_cols},
                 {"publicParams", db->public_params_b64}});
}

// ---- POST /v1/public-params ------------------------------------------------
void HandlePublicParams(const httplib::Request& req, httplib::Response& res) {
  if (!Authorized(req)) return WriteError(res, 401, "unauthorized");
  json body;
  try {
    body = json::parse(req.body);
  } catch (...) {
    return WriteError(res, 400, "invalid_json");
  }
  std::string kind = body.value("kind", "");
  std::string epoch_id = body.value("epochId", "");
  auto db = GetDb(kind, epoch_id);
  if (!db) return WriteError(res, 404, "pir_epoch_not_loaded");

  WriteJson(res, 200,
            json{{"success", true},
                 {"kind", db->kind},
                 {"epochId", db->epoch_id},
                 {"parameterId", db->parameter_id},
                 {"recordCount", db->record_count},
                 {"recordSize", db->record_size},
                 {"dbRows", db->db_rows},
                 {"dbCols", db->db_cols},
                 {"publicParams", db->public_params_b64}});
}

// ---- POST /v1/query --------------------------------------------------------
void HandleQuery(const httplib::Request& req, httplib::Response& res) {
  if (!Authorized(req)) return WriteError(res, 401, "unauthorized");
  json body;
  try {
    body = json::parse(req.body);
  } catch (...) {
    return WriteError(res, 400, "invalid_json");
  }
  std::string kind = body.value("kind", "");
  std::string epoch_id = body.value("epochId", "");
  std::string query_b64 = body.value("query", "");
  int64_t max_response_chars = body.value("maxResponseChars", int64_t{0});
  if (kind.empty() || epoch_id.empty() || query_b64.empty()) {
    return WriteError(res, 400, "invalid_query_request");
  }

  auto db = GetDb(kind, epoch_id);
  if (!db) return WriteError(res, 404, "pir_epoch_not_loaded");

  auto request_or = qor_pir::ProtoFromBase64<HintlessPirRequest>(query_b64);
  if (!request_or.ok()) return WriteError(res, 400, "invalid_pir_query");

  std::string response_b64;
  {
    std::lock_guard<std::mutex> compute(g_compute_mu);
    auto response_or = db->server->HandleRequest(*request_or);
    if (!response_or.ok()) return WriteError(res, 400, "pir_answer_failed");
    response_b64 = qor_pir::ProtoToBase64(*response_or);
  }

  if (max_response_chars > 0 &&
      static_cast<int64_t>(response_b64.size()) > max_response_chars) {
    return WriteJson(res, 413,
                     json{{"ok", false}, {"error", "pir_response_too_large"}});
  }
  WriteJson(res, 200, json{{"response", response_b64}});
}

}  // namespace

int main() {
  httplib::Server server;
  server.set_payload_max_length(
      static_cast<size_t>(EnvInt("QOR_PIR_MAX_REQUEST_BYTES", int64_t{1} << 30,
                                 1024, int64_t{1} << 40)));

  server.Get("/health", [](const httplib::Request&, httplib::Response& res) {
    SetHeaders(res);
    WriteJson(res, 200,
              json{{"ok", true},
                   {"service", "qor-hintless-simplepir-worker"},
                   {"scheme", "hintless-simplepir"},
                   {"parameterId", ConfiguredParameterId()},
                   {"sourceCommit", kSourceCommit}});
  });
  server.Post("/v1/databases", [](const httplib::Request& req, httplib::Response& res) {
    SetHeaders(res);
    HandleUpload(req, res);
  });
  server.Post("/v1/public-params", [](const httplib::Request& req, httplib::Response& res) {
    SetHeaders(res);
    HandlePublicParams(req, res);
  });
  server.Post("/v1/query", [](const httplib::Request& req, httplib::Response& res) {
    SetHeaders(res);
    HandleQuery(req, res);
  });

  std::string bind = EnvStr("QOR_PIR_BIND", "0.0.0.0:8787");
  std::string host = bind;
  int port = 8787;
  auto colon = bind.rfind(':');
  if (colon != std::string::npos) {
    host = bind.substr(0, colon);
    port = static_cast<int>(std::strtol(bind.c_str() + colon + 1, nullptr, 10));
  }
  if (host.empty()) host = "0.0.0.0";
  fprintf(stderr, "qor-hintless-simplepir-worker listening on %s:%d parameter=%s\n",
          host.c_str(), port, ConfiguredParameterId().c_str());
  if (!server.listen(host, port)) {
    fprintf(stderr, "qor-hintless-simplepir-worker failed to bind %s:%d\n",
            host.c_str(), port);
    return 1;
  }
  return 0;
}
