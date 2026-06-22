// Qor hintless-SimplePIR client helper (runs on the user's device).
//
// PIR query generation and recovery stay on the client: the server only ever
// sees the opaque proto request. This binary is the separately reviewed PIR
// math boundary the Tauri app shells out to. It supports:
//
//   serve                persistent daemon, length-prefixed JSON framing
//   (no arg)             single-shot: one JSON request on stdin -> stdout
//
// Operations (record-major; one query retrieves one full record):
//   query-record   {parameterId, recordCount, recordSize, publicParams, index}
//                  -> {request, handle}   (Client secret kept under `handle`)
//   recover-record {handle, response}
//                  -> {record}            (recovers using the stored secret)
//   ping           -> {success}
//
// Because GenerateRequest stashes the LWE/LinPIR secret inside the Client and
// RecoverRecord consumes it, the same Client must serve both halves of a query.
// The daemon therefore keeps each in-flight Client alive in a small bounded map
// keyed by an unguessable handle, evicting on recover or LRU overflow.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "hintless_simplepir/client.h"
#include "hintless_simplepir/parameters.h"
#include "hintless_simplepir/serialization.pb.h"
#include "json.hpp"
#include "qor/qor_pir_common.h"

namespace {

using ::hintless_pir::HintlessPirResponse;
using ::hintless_pir::HintlessPirServerPublicParams;
using ::hintless_pir::hintless_simplepir::Client;
using ::hintless_pir::hintless_simplepir::Parameters;
using json = nlohmann::json;

constexpr uint32_t kMaxFrameBytes = 256u << 20;  // matches the Rust daemon
constexpr size_t kMaxLiveHandles = 64;

// In-flight client secrets, keyed by handle, with LRU eviction.
std::map<std::string, std::unique_ptr<Client>> g_clients;
std::deque<std::string> g_handle_order;

std::string NewHandle() {
  std::random_device rd;
  uint64_t hi = (static_cast<uint64_t>(rd()) << 32) ^ rd();
  uint64_t lo = (static_cast<uint64_t>(rd()) << 32) ^ rd();
  char buf[33];
  std::snprintf(buf, sizeof(buf), "%016llx%016llx",
                static_cast<unsigned long long>(hi),
                static_cast<unsigned long long>(lo));
  return std::string(buf);
}

void StoreClient(const std::string& handle, std::unique_ptr<Client> client) {
  g_clients[handle] = std::move(client);
  g_handle_order.push_back(handle);
  while (g_handle_order.size() > kMaxLiveHandles) {
    const std::string& oldest = g_handle_order.front();
    g_clients.erase(oldest);
    g_handle_order.pop_front();
  }
}

std::unique_ptr<Client> TakeClient(const std::string& handle) {
  auto it = g_clients.find(handle);
  if (it == g_clients.end()) return nullptr;
  std::unique_ptr<Client> client = std::move(it->second);
  g_clients.erase(it);
  for (auto d = g_handle_order.begin(); d != g_handle_order.end(); ++d) {
    if (*d == handle) {
      g_handle_order.erase(d);
      break;
    }
  }
  return client;
}

json Fail(const std::string& code) {
  return json{{"success", false}, {"error", code}};
}

// Rebuild the epoch's Parameters from the public manifest fields the same way
// the worker did, then create a Client from the parsed public params.
absl::StatusOr<std::unique_ptr<Client>> MakeClient(const json& req) {
  std::string parameter_id = req.value("parameterId", "");
  int64_t record_count = req.value("recordCount", int64_t{0});
  int record_size = req.value("recordSize", 0);
  std::string pp_b64 = req.value("publicParams", "");
  if (record_count <= 0 || record_size <= 0 || pp_b64.empty()) {
    return absl::InvalidArgumentError("invalid_setup");
  }
  qor_pir::DbGeometry geo = qor_pir::ChooseGeometry(record_count, record_size);
  auto params_or = qor_pir::BuildParameters(parameter_id, geo);
  if (!params_or.ok()) return params_or.status();
  auto pp_or = qor_pir::ProtoFromBase64<HintlessPirServerPublicParams>(pp_b64);
  if (!pp_or.ok()) return pp_or.status();
  return Client::Create(*params_or, *pp_or);
}

json HandleQueryRecord(const json& req) {
  auto client_or = MakeClient(req);
  if (!client_or.ok()) return Fail(std::string(client_or.status().message()));
  auto client = std::move(client_or).value();

  int64_t index = req.value("index", int64_t{-1});
  if (index < 0) return Fail("invalid_index");
  auto request_or = client->GenerateRequest(index);
  if (!request_or.ok()) return Fail(std::string(request_or.status().message()));

  std::string handle = NewHandle();
  std::string request_b64 = qor_pir::ProtoToBase64(*request_or);
  StoreClient(handle, std::move(client));
  return json{{"success", true}, {"request", request_b64}, {"handle", handle}};
}

json HandleRecoverRecord(const json& req) {
  std::string handle = req.value("handle", "");
  std::string response_b64 = req.value("response", "");
  if (handle.empty() || response_b64.empty()) return Fail("invalid_recover");
  auto client = TakeClient(handle);
  if (!client) return Fail("unknown_handle");

  auto response_or =
      qor_pir::ProtoFromBase64<HintlessPirResponse>(response_b64);
  if (!response_or.ok()) return Fail("invalid_response");
  auto record_or = client->RecoverRecord(*response_or);
  if (!record_or.ok()) return Fail(std::string(record_or.status().message()));
  return json{{"success", true},
              {"record", qor_pir::Base64UrlEncode(*record_or)}};
}

json Dispatch(const json& req) {
  std::string op = req.value("operation", "");
  if (op == "query-record") return HandleQueryRecord(req);
  if (op == "recover-record") return HandleRecoverRecord(req);
  if (op == "ping") return json{{"success", true}};
  return Fail("unsupported_operation");
}

// ---- length-prefixed framed stdio (daemon) --------------------------------
bool ReadExact(void* buf, size_t n) {
  size_t got = std::fread(buf, 1, n, stdin);
  return got == n;
}

bool ReadFrame(std::string& out) {
  unsigned char len_buf[4];
  if (!ReadExact(len_buf, 4)) return false;
  uint32_t n = (static_cast<uint32_t>(len_buf[0]) << 24) |
               (static_cast<uint32_t>(len_buf[1]) << 16) |
               (static_cast<uint32_t>(len_buf[2]) << 8) |
               static_cast<uint32_t>(len_buf[3]);
  if (n == 0 || n > kMaxFrameBytes) return false;
  out.resize(n);
  return ReadExact(out.data(), n);
}

bool WriteFrame(const std::string& payload) {
  if (payload.size() > kMaxFrameBytes) return false;
  uint32_t n = static_cast<uint32_t>(payload.size());
  unsigned char len_buf[4] = {
      static_cast<unsigned char>((n >> 24) & 0xff),
      static_cast<unsigned char>((n >> 16) & 0xff),
      static_cast<unsigned char>((n >> 8) & 0xff),
      static_cast<unsigned char>(n & 0xff)};
  if (std::fwrite(len_buf, 1, 4, stdout) != 4) return false;
  if (!payload.empty() &&
      std::fwrite(payload.data(), 1, payload.size(), stdout) != payload.size()) {
    return false;
  }
  return std::fflush(stdout) == 0;
}

int Serve() {
  std::string frame;
  while (ReadFrame(frame)) {
    json req;
    json resp;
    bool parsed = true;
    try {
      req = json::parse(frame);
    } catch (...) {
      parsed = false;
    }
    if (!parsed) {
      resp = Fail("invalid_json");
    } else {
      try {
        resp = Dispatch(req);
      } catch (...) {
        resp = Fail("client_exception");
      }
      // Echo the monotonic id so the parent can detect a misframed reply.
      if (req.contains("id")) resp["id"] = req["id"];
    }
    if (!WriteFrame(resp.dump())) return 1;
  }
  return 0;
}

int SingleShot() {
  std::string input;
  char buf[65536];
  size_t got;
  while ((got = std::fread(buf, 1, sizeof(buf), stdin)) > 0) {
    input.append(buf, got);
  }
  json req;
  try {
    req = json::parse(input);
  } catch (...) {
    std::fputs(Fail("invalid_json").dump().c_str(), stdout);
    return 1;
  }
  json resp;
  try {
    resp = Dispatch(req);
  } catch (...) {
    resp = Fail("client_exception");
  }
  std::fputs(resp.dump().c_str(), stdout);
  std::fputc('\n', stdout);
  return resp.value("success", false) ? 0 : 1;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc > 1 && std::strcmp(argv[1], "serve") == 0) {
    return Serve();
  }
  return SingleShot();
}
