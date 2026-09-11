// ScotMesh node pages, telemetry API and remote administration.
//
// Everything a remote (e.g. solar) microReticulum node needs to be looked
// after over the mesh from its own NomadNet page: public home page with
// battery, routes/neighbours pages, a small JSON telemetry API that works for
// unidentified clients, and admin pages (name & announce, home layout,
// rmap.world position, radio trial, role, power, admins, password
// registration, change log, health, lights & Bluetooth, logs, maintenance,
// restart and firmware-update windows).
//
// Every reply fits in ONE LoRa link packet (Link MDU 431 B minus ~22 B of
// response framing). Budgets: home / routes / neighbours / API <= 400 B,
// admin pages <= 300 B. Pages are written into one bounded buffer with a
// printf-style builder (compact code, no heap churn); nothing copies a table,
// and below a free-RAM floor the node answers "busy" instead of building.
//
// Included once, from RNode_Firmware.ino, after Utilities.h.

#pragma once

#include <string>
#include <vector>
#include <cstring>
#include <cstdarg>
#include <cmath>

#include <SHA256.h>
#include <microReticulum/Transport.h>
#include <microReticulum/Identity.h>
#include <microReticulum/Destination.h>
#include <microReticulum/Cryptography/HKDF.h>
#include <microReticulum/Cryptography/Hashes.h>
#include <microReticulum/Cryptography/Random.h>
#include <microReticulum/Utilities/OS.h>
#include <microReticulum/Utilities/Memory.h>
#ifdef HAS_PROVISIONING
#include <microReticulum/Provisioning/Provisioning.h>
#endif

#ifndef SCOTMESH_FW_TAG
  #define SCOTMESH_FW_TAG "v1.86-scotmesh-dev"
#endif
#ifndef BOARD_SHORT_NAME
  #ifdef BLE_MODEL
    #define BOARD_SHORT_NAME BLE_MODEL
  #else
    #define BOARD_SHORT_NAME "RNode"
  #endif
#endif

#define SM_HOME_BUDGET   400
#define SM_HARD_LIMIT    409      // 431 B link MDU minus response framing
#define SM_RAM_FLOOR     8192     // below this, answer "busy" instead of building
#define SM_DFU_MAGIC     0x5D     // GPREGRET2 value asking the next boot for a BLE update window
#define SM_DFU_WINDOW_MS (20UL * 60UL * 1000UL)
#define SM_TRIAL_MS      (5UL * 60UL * 1000UL)
// Forgetting paired phones needs bond storage: nRF52 (Bluefruit) and ESP32 BLE; not ESP32 classic Bluetooth
#if MCU_VARIANT == MCU_NRF52 || (MCU_VARIANT == MCU_ESP32 && HAS_BLE == true)
  #define SM_CAN_UNPAIR 1
#else
  #define SM_CAN_UNPAIR 0
#endif

bool startRadio();
void stopRadio();
extern RNS::Destination nomadnet_destination;
extern char nomadnet_name[64];
extern RNS::Interface lora_interface;

// ---------------------------------------------------------------------------
// Persisted settings (own small file; provisioning keeps name/role/admins)
// ---------------------------------------------------------------------------
enum : uint8_t { SMH_BAT = 1, SMH_UP = 2, SMH_RADIO = 4, SMH_PATHS = 8, SMH_AIR = 16, SMH_OP = 32, SMH_ROUTES = 64 };
struct SmConfig {
  uint32_t magic = 0x31434D53;           // "SMC1"
  uint8_t  home = SMH_BAT | SMH_UP | SMH_PATHS | SMH_OP | SMH_ROUTES;
  uint8_t  api = 1;
  uint8_t  leds = 0;                     // 0 on, 1 off, 2 first 10 min after start
  uint8_t  pw_on = 0, pw_approval = 0, pw_set = 0;
  uint8_t  pw_salt[16] = {0};
  uint8_t  pw_hash[32] = {0};
  char     op[23] = "";
  uint8_t  map_on = 0, map_coarse = 0;
  double   lat = 0, lon = 0;
  float    height = 0;
  uint8_t  pwr_below = 25, pwr_act = 1, pwr_lock = 1;   // act: 0 nothing, 1 lower TX power, 2 radio off until charged
  uint8_t  sched = 0;                    // 0 off, 1 every day, 2 every week
  uint32_t reboots = 0;
  uint8_t  stamp_for[16] = {0};          // info hash the cached discovery stamp belongs to
  uint8_t  stamp[32] = {0};
  uint8_t  ann = 3;                      // announce every: 0 30 min, 1 1 h, 2 3 h, 3 6 h, 4 12 h
  uint8_t  reserved[15] = {0};
};
static SmConfig sm;
static const char* SM_CFG_PATH = "/scotmesh.cfg";
static const char* SM_LOG_PATH = "/scotmesh.chg";
static void sm_save() { RNS::Utilities::OS::write_file(SM_CFG_PATH, RNS::Bytes((const uint8_t*)&sm, sizeof(sm))); }
static void sm_load() {
  RNS::Bytes b;
  if (RNS::Utilities::OS::file_exists(SM_CFG_PATH) && RNS::Utilities::OS::read_file(SM_CFG_PATH, b) == sizeof(sm)) {
    SmConfig c; memcpy(&c, b.data(), sizeof(c)); if (c.magic == 0x31434D53) sm = c;
  }
}

// ---------------------------------------------------------------------------
// Runtime state (RAM, all capped)
// ---------------------------------------------------------------------------
static const char* sm_reset_reason = "power-on";
static uint64_t sm_up_ms = 0; static uint32_t sm_last_millis = 0;
static uint32_t sm_blink_until = 0, sm_dfu_action = 0, sm_dfu_action_at = 0;
struct SmRadio { uint32_t f, bw; int sf, cr, txp; };
static bool sm_trial = false; static SmRadio sm_trial_prev; static uint32_t sm_trial_until = 0;
static bool sm_power_limited = false, sm_power_sleep = false; static int sm_saved_txp = -1;
static char sm_log_ring[5][48]; static uint8_t sm_log_next = 0, sm_log_count = 0;
struct SmToken { char key[5]; char what[20]; uint32_t until; };
static SmToken sm_tokens[6]; static uint8_t sm_token_next = 0;
struct SmPending { RNS::Bytes id; uint32_t at; };
static std::vector<SmPending> sm_pending;            // max 5
struct SmFail { RNS::Bytes id; uint8_t n; uint32_t lock_until; };
static std::vector<SmFail> sm_fails;                 // max 8
static uint32_t sm_global_fails[10] = {0}; static uint8_t sm_gf_next = 0; static uint32_t sm_reg_paused_until = 0;
static char sm_last_attempt[16] = "";
static const uint16_t SM_ANN_MIN[] = {30, 60, 180, 360, 720};
static uint32_t sm_ann_ms() { return (uint32_t)SM_ANN_MIN[sm.ann > 4 ? 3 : sm.ann] * 60000UL; }

static uint64_t sm_uptime_ms() { uint32_t m = millis(); sm_up_ms += (uint32_t)(m - sm_last_millis); sm_last_millis = m; return sm_up_ms; }
static const char* sm_up() {
  static char b[16]; uint32_t s = (uint32_t)(sm_uptime_ms() / 1000);
  if (s >= 86400) snprintf(b, sizeof b, "%lud %luh", (unsigned long)(s / 86400), (unsigned long)(s % 86400 / 3600));
  else snprintf(b, sizeof b, "%luh %lum", (unsigned long)(s / 3600), (unsigned long)(s % 3600 / 60));
  return b;
}
static const char* sm_age(double secs, char* b) {   // b: 8 bytes
  if (secs < 0) secs = 0;
  if (secs < 3600) snprintf(b, 8, "%dm", (int)(secs / 60 + 0.5)); else if (secs < 86400) snprintf(b, 8, "%dh", (int)(secs / 3600 + 0.5)); else snprintf(b, 8, "%dd", (int)(secs / 86400 + 0.5));
  return b;
}
static const char* sm_mhz(uint32_t f) {
  static char b[16]; snprintf(b, sizeof b, "%.3f", f / 1e6);
  for (int i = strlen(b) - 1; i > 0 && (b[i] == '0' || b[i] == '.'); i--) { bool dot = b[i] == '.'; b[i] = 0; if (dot) break; }
  return b;
}

// Log tail for the Logs page (fed from on_log)
void sm_log_line(const char* msg) {
  strncpy(sm_log_ring[sm_log_next], msg, sizeof(sm_log_ring[0]) - 1); sm_log_ring[sm_log_next][sizeof(sm_log_ring[0]) - 1] = 0;
  for (char* p = sm_log_ring[sm_log_next]; *p; p++) if (*p == '`' || *p == '\n' || *p == '\r') *p = ' ';
  sm_log_next = (sm_log_next + 1) % 5; if (sm_log_count < 5) sm_log_count++;
}

// ---------------------------------------------------------------------------
// Change log: fixed ring of 32 x 40 B in flash (time, identity, what)
// ---------------------------------------------------------------------------
struct SmChange { uint32_t t; uint8_t id[16]; char what[20]; };
static size_t sm_changes_read(RNS::Bytes& b) {
  if (!RNS::Utilities::OS::file_exists(SM_LOG_PATH) || RNS::Utilities::OS::read_file(SM_LOG_PATH, b) == 0) return 0;
  return b.size() / sizeof(SmChange);
}
static void sm_change(const RNS::Bytes& who, const char* what) {
  RNS::Bytes old; size_t n = sm_changes_read(old); if (n > 31) n = 31;
  SmChange c; c.t = (uint32_t)RNS::Utilities::OS::time(); memset(c.id, 0, 16); if (who.size() >= 16) memcpy(c.id, who.data(), 16);
  strncpy(c.what, what, sizeof(c.what) - 1); c.what[sizeof(c.what) - 1] = 0;
  RNS::Bytes out((const uint8_t*)&c, sizeof(c)); if (n) out.append(old.data(), n * sizeof(SmChange));
  RNS::Utilities::OS::write_file(SM_LOG_PATH, out);
}

// ---------------------------------------------------------------------------
// Page builder: one bounded buffer, printf-style. Micron helpers write into it.
// ---------------------------------------------------------------------------
static char sm_pb[720]; static size_t sm_pn = 0;
static void pb_reset() { sm_pn = 0; sm_pb[0] = 0; }
static void P(const char* fmt, ...) {
  if (sm_pn >= sizeof(sm_pb) - 1) return;
  va_list a; va_start(a, fmt); int n = vsnprintf(sm_pb + sm_pn, sizeof(sm_pb) - sm_pn, fmt, a); va_end(a);
  if (n > 0) { sm_pn += n; if (sm_pn > sizeof(sm_pb) - 1) sm_pn = sizeof(sm_pb) - 1; }
}
static void pb_cut(size_t at) { sm_pn = at; sm_pb[at] = 0; }
#define DIM(s) "`F888" s "`f"
#define MIDDOT "\xC2\xB7"
static void Ph(const char* title) { P("#!c=0\n>%s\n", title); }
static void Pmsg(char kind, const char* s) { if (s && *s) P("`F%s%s`f\n", kind == 'o' ? "2c5" : kind == 'b' ? "f66" : "da3", s); }
static void PL(const char* label, char pg, const char* fields = nullptr) {    // link to /page/<pg>.mu ('I' = index)
  char u[8]; if (pg == 'I') strcpy(u, "index"); else { u[0] = pg; u[1] = 0; }
  P(fields && *fields ? "`[%s`:/page/%s.mu`%s]" : "`[%s`:/page/%s.mu]", label, u, fields);
}
static void PLf(const char* label, char pg, const char* fmt, ...) { char f[64]; va_list a; va_start(a, fmt); vsnprintf(f, sizeof f, fmt, a); va_end(a); PL(label, pg, f); }
static void PC(const char* name, bool on) { P("`<?|%s|1%s`>", name, on ? "|*" : ""); }
static void PR(const char* name, const char* v, bool on) { P("`<^|%s|%s%s`>", name, v, on ? "|*" : ""); }
static void PF(int w, const char* name, const char* val) { P("`<%d|%s`%s>", w, name, val); }
static void PBACK() { P("`[< Admin`:/page/a.mu]"); }

// ---------------------------------------------------------------------------
// Request data: msgpack map. NomadNet sends field_* / var_*, API clients raw keys.
// Parsed into a small fixed table; values are cleaned of micron backticks.
// ---------------------------------------------------------------------------
struct SmKV { char k[16]; char v[64]; };
static SmKV sm_kv[16]; static uint8_t sm_nkv = 0;
static bool mp_read(const uint8_t* p, size_t n, size_t& i, char* out, size_t cap) {
  if (i >= n) return false; uint8_t t = p[i++]; size_t len = 0; long iv = 0; bool num = false;
  if (t <= 0x7f) { iv = t; num = true; }
  else if (t >= 0xe0) { iv = (int8_t)t; num = true; }
  else if ((t & 0xe0) == 0xa0) len = t & 0x1f;
  else switch (t) {
    case 0xc0: case 0xc2: out[0] = 0; return true;
    case 0xc3: strcpy(out, "1"); return true;
    case 0xc4: case 0xd9: if (i >= n) return false; len = p[i++]; break;
    case 0xc5: case 0xda: if (i + 2 > n) return false; len = (p[i] << 8) | p[i + 1]; i += 2; break;
    case 0xcc: if (i >= n) return false; iv = p[i++]; num = true; break;
    case 0xcd: if (i + 2 > n) return false; iv = (p[i] << 8) | p[i + 1]; i += 2; num = true; break;
    case 0xce: if (i + 4 > n) return false; iv = (long)(((uint32_t)p[i] << 24) | ((uint32_t)p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3]); i += 4; num = true; break;
    case 0xd0: if (i >= n) return false; iv = (int8_t)p[i++]; num = true; break;
    case 0xcb: { if (i + 8 > n) return false; uint64_t u = 0; for (int k = 0; k < 8; k++) u = (u << 8) | p[i + k]; i += 8; double d; memcpy(&d, &u, 8); snprintf(out, cap, "%g", d); return true; }
    default: return false;
  }
  if (num) { snprintf(out, cap, "%ld", iv); return true; }
  if (i + len > n) return false;
  size_t c = len < cap - 1 ? len : cap - 1; memcpy(out, p + i, c); out[c] = 0; i += len; return true;
}
static void sm_parse(const RNS::Bytes& data) {
  sm_nkv = 0; const uint8_t* p = data.data(); size_t n = data.size(), i = 0, cnt;
  if (n == 0) return;
  uint8_t t = p[i++];
  if ((t & 0xf0) == 0x80) cnt = t & 0x0f; else if (t == 0xde && n >= 3) { cnt = (p[1] << 8) | p[2]; i = 3; } else return;
  for (size_t k = 0; k < cnt && sm_nkv < 16; k++) {
    SmKV& e = sm_kv[sm_nkv];
    if (!mp_read(p, n, i, e.k, sizeof e.k) || !mp_read(p, n, i, e.v, sizeof e.v)) break;
    for (char* c = e.v; *c; c++) if (*c == '`' || *c == '\n') *c = ' ';
    sm_nkv++;
  }
}
static const char* Q(const char* key) { for (uint8_t i = 0; i < sm_nkv; i++) if (!strcmp(sm_kv[i].k, key)) return sm_kv[i].v; return ""; }
static bool Qhas(const char* key) { for (uint8_t i = 0; i < sm_nkv; i++) if (!strcmp(sm_kv[i].k, key)) return true; return false; }
static const char* Fv(const char* n) { char k[16]; snprintf(k, sizeof k, "field_%s", n); return Q(k); }
static const char* Vv(const char* n) { char k[16]; snprintf(k, sizeof k, "var_%s", n); return Q(k); }
static bool Fis(const char* n, const char* v) { return !strcmp(Fv(n), v); }
static bool Vis(const char* n, const char* v) { return !strcmp(Vv(n), v); }

// ---------------------------------------------------------------------------
// Identity / access
// ---------------------------------------------------------------------------
static bool sm_is_admin(const RNS::Bytes& id) { return id.size() == 16 && RNS::Transport::remote_management_allowed().count(id) > 0; }
static bool sm_token_use(const char* k, const char* what) {
  for (auto& t : sm_tokens) if (strlen(k) == 4 && !strncmp(t.key, k, 4) && !strcmp(what, t.what)) { bool ok = (int32_t)(t.until - millis()) > 0; t.key[0] = 0; return ok; }
  return false;
}
static const char* sm_token(const char* what) {
  SmToken& t = sm_tokens[sm_token_next]; sm_token_next = (sm_token_next + 1) % 6;
  RNS::Bytes r = RNS::Cryptography::random(2); snprintf(t.key, sizeof t.key, "%02x%02x", r.data()[0], r.data()[1]);
  strncpy(t.what, what, sizeof t.what - 1); t.what[sizeof t.what - 1] = 0; t.until = millis() + 120000UL;
  return t.key;
}
static void sm_admins_persist(const std::set<RNS::Bytes>& ids) {
  RNS::Transport::remote_management_allowed(ids);
#ifdef HAS_PROVISIONING
  auto list = RNS::Provisioning::Provisioner::instance().field(1, 8).as_bytes_list();
  list.clear(); for (auto& x : ids) list.push_back(x);
  RNS::Provisioning::Provisioner::instance().field(1, 8, RNS::Provisioning::Value(list));
  RNS::Provisioning::Provisioner::instance().commit(1);
#endif
}
static bool sm_admin_add(const RNS::Bytes& id) {
  std::set<RNS::Bytes> ids = RNS::Transport::remote_management_allowed();
  if (ids.size() >= 8) return false;
  ids.insert(id); sm_admins_persist(ids); return true;
}
static void sm_pbkdf2(const char* pw, const uint8_t* salt, uint8_t out[32]) {
  SHA256 h; uint8_t u[32], t[32]; const uint8_t one[4] = {0, 0, 0, 1}; size_t pl = strlen(pw);
  h.resetHMAC(pw, pl); h.update(salt, 16); h.update(one, 4); h.finalizeHMAC(pw, pl, u, 32); memcpy(t, u, 32);
  for (int it = 1; it < 2000; it++) {
    h.resetHMAC(pw, pl); h.update(u, 32); h.finalizeHMAC(pw, pl, u, 32);
    for (int k = 0; k < 32; k++) t[k] ^= u[k];
    if ((it & 255) == 0) yield();
  }
  memcpy(out, t, 32);
}
static bool sm_transport_on() {
#ifdef HAS_PROVISIONING
  return RNS::Provisioning::Provisioner::instance().field(1, 1).as_bool();
#else
  return true;
#endif
}

// ---------------------------------------------------------------------------
// Radio
// ---------------------------------------------------------------------------
static SmRadio sm_radio_now() { return SmRadio{lora_freq, lora_bw, lora_sf, lora_cr, lora_txp}; }
static void sm_radio_apply(const SmRadio& r) {
  lora_freq = r.f; lora_bw = r.bw; lora_sf = r.sf; lora_cr = r.cr; lora_txp = r.txp;
  setFrequency(); setBandwidth(); setSpreadingFactor(); setCodingRate(); setTXPower();
}

// ---------------------------------------------------------------------------
// rmap.world: Reticulum interface-discovery announce with an LXMF stamp
// (cost 16; the 20 x HKDF-256 workblock is exactly 80 SHA-256 blocks, so the
// hash state after it is computed once and each try is a single block).
// Worked in slices from the loop; the stamp is cached in flash.
// ---------------------------------------------------------------------------
static RNS::Destination sm_disc({RNS::Type::NONE});
static bool sm_disc_busy = false; static SHA256 sm_disc_mid; static uint32_t sm_disc_ctr = 0;
static std::string sm_disc_packed; static uint8_t sm_disc_hash[32];
static uint32_t sm_disc_last = 0, sm_disc_due = 0, sm_nn_due = 0;
static void mp_str(std::string& o, const char* s) { size_t l = strlen(s); if (l < 32) o += (char)(0xa0 | l); else { o += (char)0xd9; o += (char)l; } o.append(s, l); }
static void mp_uint(std::string& o, uint32_t v) { if (v < 128) o += (char)v; else if (v < 256) { o += (char)0xcc; o += (char)v; } else if (v < 65536) { o += (char)0xcd; o += (char)(v >> 8); o += (char)v; } else { o += (char)0xce; for (int s = 24; s >= 0; s -= 8) o += (char)(v >> s); } }
static void mp_f64(std::string& o, double d) { uint64_t b; memcpy(&b, &d, 8); o += (char)0xcb; for (int s = 56; s >= 0; s -= 8) o += (char)(b >> s); }
static void sm_disc_prepare() {
  double lat = sm.lat, lon = sm.lon;
  if (sm.map_coarse) { lat = std::round(lat * 100) / 100; lon = std::round(lon * 100) / 100; }
  char name[32]; strncpy(name, nomadnet_name, 31); name[31] = 0;
  RNS::Bytes tid = RNS::Transport::identity().hash();
  std::string o; o += (char)(0x80 | 13);
  mp_uint(o, 0x00); mp_str(o, "RNodeInterface");
  mp_uint(o, 0x01); o += (char)(sm_transport_on() ? 0xc3 : 0xc2);
  mp_uint(o, 0xFE); o += (char)0xc4; o += (char)tid.size(); o.append((const char*)tid.data(), tid.size());
  mp_uint(o, 0xFD); mp_str(o, "microReticulum");
  mp_uint(o, 0xFC); mp_str(o, SCOTMESH_FW_TAG);
  mp_uint(o, 0xFF); mp_str(o, name);
  mp_uint(o, 0x03); mp_f64(o, lat);
  mp_uint(o, 0x04); mp_f64(o, lon);
  mp_uint(o, 0x05); mp_f64(o, (double)sm.height);
  mp_uint(o, 0x09); mp_uint(o, lora_freq);
  mp_uint(o, 0x0A); mp_uint(o, lora_bw);
  mp_uint(o, 0x0B); mp_uint(o, lora_sf);
  mp_uint(o, 0x0C); mp_uint(o, lora_cr);
  sm_disc_packed = o;
  RNS::Bytes ih = RNS::Cryptography::sha256(RNS::Bytes((const uint8_t*)o.data(), o.size()));
  memcpy(sm_disc_hash, ih.data(), 32);
}
static void sm_disc_send() {
  RNS::Bytes app; app.append((uint8_t)0x00);
  app.append((const uint8_t*)sm_disc_packed.data(), sm_disc_packed.size()); app.append(sm.stamp, 32);
  sm_disc.announce(app); sm_disc_last = millis();
  NOTICEF("[discovery] announced %s to rmap.world (%u B app_data)", sm_disc.hash().toHex().c_str(), (unsigned)app.size());
}
static void sm_disc_start() {
  if (!sm.map_on || !sm_disc) return;
  sm_disc_prepare();
  if (memcmp(sm.stamp_for, sm_disc_hash, 16) == 0) { sm_disc_send(); return; }     // cached stamp still valid
  RNS::Bytes ih(sm_disc_hash, 32);
  sm_disc_mid.reset();
  for (uint8_t n = 0; n < 20; n++) {
    RNS::Bytes salt_in = ih; salt_in.append(n);                                     // msgpack(n) == n for n < 128
    RNS::Bytes blk = RNS::Cryptography::hkdf(256, ih, RNS::Cryptography::sha256(salt_in));
    sm_disc_mid.update(blk.data(), blk.size());
  }
  sm_disc_ctr = 0; sm_disc_busy = true;
  NOTICE("[discovery] generating stamp (cost 16)");
}
static void sm_disc_work() {                       // ~500 single-block tries per loop pass
  if (!sm_disc_busy) return;
  uint8_t st[32], res[32]; RNS::Bytes seed = RNS::Cryptography::random(24);
  memcpy(st, seed.data(), 24);
  for (int k = 0; k < 500; k++) {
    uint32_t c = sm_disc_ctr++; memcpy(st + 24, &c, 4); memcpy(st + 28, &sm_disc_ctr, 4);
    SHA256 h = sm_disc_mid; h.update(st, 32); h.finalize(res, 32);
    if (res[0] == 0 && res[1] == 0) {
      memcpy(sm.stamp, st, 32); memcpy(sm.stamp_for, sm_disc_hash, 16); sm_save();
      sm_disc_busy = false; NOTICEF("[discovery] stamp found after %lu tries", (unsigned long)sm_disc_ctr);
      sm_disc_send(); return;
    }
  }
}

// ---------------------------------------------------------------------------
// Position parser: what Google Maps gives you, decimal or DMS, with or
// without N/S/E/W, commas or brackets. False unless it finds two coordinates.
// ---------------------------------------------------------------------------
static bool sm_parse_pos(const char* in, double& lat, double& lon) {
  double g[3][3] = {{0}}; int gc[3] = {0, 0, 0}, grp = 0; char dirs[2] = {0, 0}; int nd = 0;
  for (const char* p = in; *p;) {
    if ((*p >= '0' && *p <= '9') || ((*p == '-' || *p == '+') && p[1] >= '0' && p[1] <= '9')) {
      char* end; double v = strtod(p, &end); p = end;
      if (gc[grp] < 3) g[grp][gc[grp]++] = v;
      continue;
    }
    char u = toupper((unsigned char)*p++);
    if ((u == 'N' || u == 'S' || u == 'E' || u == 'W') && nd < 2) { dirs[nd++] = u; grp = nd; }
  }
  auto dms = [&](int k) { double v = fabs(g[k][0]) + g[k][1] / 60 + g[k][2] / 3600; return g[k][0] < 0 ? -v : v; };
  if (nd == 2) {
    double a = dms(0), b = dms(1);
    if (dirs[0] == 'S' || dirs[0] == 'W') a = -fabs(a);
    if (dirs[1] == 'S' || dirs[1] == 'W') b = -fabs(b);
    bool aLat = dirs[0] == 'N' || dirs[0] == 'S', bLat = dirs[1] == 'N' || dirs[1] == 'S';
    if (aLat == bLat) return false;
    lat = aLat ? a : b; lon = aLat ? b : a;
  } else if (nd == 0 && gc[0] == 2) { lat = g[0][0]; lon = g[0][1]; }
  else return false;
  if (!(lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180)) return false;
  lat = std::round(lat * 1e5) / 1e5; lon = std::round(lon * 1e5) / 1e5;
  return true;
}

// ---------------------------------------------------------------------------
// Path table walk (never copies the table)
// ---------------------------------------------------------------------------
typedef bool (*SmPathFn)(const RNS::Bytes& dest, uint8_t hops, double heard, const RNS::Bytes& via, void* ctx);
static void sm_walk_paths(SmPathFn fn, void* ctx) {
  auto& t = const_cast<std::remove_const_t<std::remove_reference_t<decltype(RNS::Transport::new_path_table())>>&>(RNS::Transport::new_path_table());
  for (auto it = t.begin(); it != t.end(); ++it) { auto& e = *it; if (!fn(e.key, e.value._hops, e.value._timestamp, e.value._received_from, ctx)) break; }
}

// ---------------------------------------------------------------------------
// Neighbours: the transport nodes we hear directly = next hop of each
// announce, kept in a small RAM table from the announce handler, so pages
// and the API never walk the (flash-backed) path table for them.
// ---------------------------------------------------------------------------
struct SmNbr { RNS::Bytes id; double heard; char name[17]; };
static std::vector<SmNbr> sm_nbrs;                    // max 16, newest first
class SmAnnounceWatch : public RNS::AnnounceHandler {
public:
  SmAnnounceWatch() : RNS::AnnounceHandler(nullptr) {}
  void received_announce(const RNS::Bytes& dest, const RNS::Identity& id, const RNS::Bytes& app_data) override {
    RNS::Bytes nh = RNS::Transport::next_hop(dest);
    if (!nh || nh.size() != 16) return;
    bool direct = nh == dest || RNS::Transport::hops_to(dest) <= 1;
    SmNbr n; n.id = nh; n.heard = RNS::Utilities::OS::time(); n.name[0] = 0;
    for (size_t i = 0; i < sm_nbrs.size(); i++) if (sm_nbrs[i].id == nh) { memcpy(n.name, sm_nbrs[i].name, sizeof n.name); sm_nbrs.erase(sm_nbrs.begin() + i); break; }
    if (direct && !n.name[0] && app_data && app_data.size()) {
      size_t l = app_data.size() < 16 ? app_data.size() : 16; bool ok = true;
      for (size_t k = 0; k < l; k++) { uint8_t c = app_data.data()[k]; if (c < 0x20 || c == '`') ok = false; }
      if (ok) { memcpy(n.name, app_data.data(), l); n.name[l] = 0; }
    }
    sm_nbrs.insert(sm_nbrs.begin(), n); if (sm_nbrs.size() > 16) sm_nbrs.pop_back();
  }
};

// ---------------------------------------------------------------------------
// Battery
// ---------------------------------------------------------------------------
static bool sm_charging() { return battery_state == BATTERY_STATE_CHARGING || battery_state == BATTERY_STATE_CHARGED; }
static int sm_pct() { int p = (int)(battery_percent + 0.5); return p < 0 ? 0 : p > 100 ? 100 : p; }
static void P_battery() {
  int p = sm_pct(), f = (p + 5) / 10;
  P("`F%s", p < 25 ? "f55" : p < 50 ? "da3" : "2c5");
  for (int i = 0; i < 10; i++) P(i < f ? "\xE2\x96\x88" : "\xE2\x96\x91");
  P("`f %d%% %.2fV %s", p, battery_voltage, sm_charging() ? "`F2c5\xE2\x96\xB2`f" : "`Fda3\xE2\x96\xBC`f");
}

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------
static const char* SM_FLAG = "\xF0\x9F\x8F\xB4\xF3\xA0\x81\xA7\xF3\xA0\x81\xA2\xF3\xA0\x81\xB3\xF3\xA0\x81\xA3\xF3\xA0\x81\xB4\xF3\xA0\x81\xBF";
static void P_verified(const RNS::Bytes& rid) { if (rid.size()) P("\xF0\x9F\x9B\xA1\xEF\xB8\x8F Verified identity: %s\n", rid.toHex().c_str()); else P(DIM("Not identified") "\n"); }
static void pg_denied(const RNS::Bytes& rid) {
  Ph("Admins only");
  if (rid.size()) { P("Not on this node's admin list:\n" DIM("%s") "\n", rid.toHex().c_str()); if (sm.pw_on) { PL("Register with a password", 'l'); P("\n"); } }
  else P("Identify first, then reload.\n");
  PL("Home", 'I');
}

static void pg_home(const RNS::Bytes& rid) {
  bool preview = Vis("v", "1"), admin = sm_is_admin(rid) && !preview;
  static const uint8_t order[] = {SMH_AIR, SMH_RADIO, SMH_PATHS, SMH_UP};   // dropped in this order if over budget
  uint8_t dropped = 0;
  for (int pass = 0; pass <= 4; pass++) {
    auto show = [&](uint8_t bit) { return ((sm.home & bit) || admin) && !(dropped & bit); };
    auto star = [&](uint8_t bit) { if (admin && !(sm.home & bit)) P("*"); };
    pb_reset(); P("#!c=0\n");
    if (preview) { P("`Bda3`F000 Visitor view `b`f "); PL("back", 'h'); P("\n"); }
    P(">%s\n", nomadnet_name);
    if (show(SMH_BAT) || show(SMH_UP) || show(SMH_PATHS) || show(SMH_RADIO) || show(SMH_AIR) || (show(SMH_OP) && sm.op[0])) P(">>Status\n");
    if (show(SMH_BAT)) { star(SMH_BAT); P_battery(); P("\n"); }
    if (show(SMH_UP) || show(SMH_PATHS)) {
      star(show(SMH_UP) ? SMH_UP : SMH_PATHS); P(DIM("Up") " ");
      if (show(SMH_UP)) P("%s", sm_up());
      if (show(SMH_PATHS)) {
        char l[20]; snprintf(l, sizeof l, "%u routes", (unsigned)RNS::Transport::new_path_table().size());
        if (show(SMH_UP)) P(", ");
        if ((sm.home & SMH_ROUTES) || admin) PL(l, 'r'); else P("%s", l);
      }
      P("\n");
    }
    if (show(SMH_RADIO) || show(SMH_AIR)) {
      star(show(SMH_RADIO) ? SMH_RADIO : SMH_AIR); P(DIM("Radio") " ");
      if (show(SMH_RADIO)) P("%s SF%d %luk", sm_mhz(lora_freq), lora_sf, (unsigned long)(lora_bw / 1000));
      if (show(SMH_AIR)) P("%s%.1f%% air", show(SMH_RADIO) ? ", " : "", airtime * 100);
      P("\n");
    }
    if (show(SMH_OP) && sm.op[0]) { star(SMH_OP); P(DIM("Op") " %s\n", sm.op); }
    P("<\n");
    if (admin) { PL("Admin", 'a'); P("\n"); }
    else if (rid.size() && sm.pw_on && !preview) { PL("Register", 'l'); P("\n"); }
    if (!preview) P_verified(rid);
    P("-\n`c%s ScotMesh microReticulum\n`c%s " MIDDOT " %s", SM_FLAG, SCOTMESH_FW_TAG, BOARD_SHORT_NAME);
    if (sm_pn <= SM_HOME_BUDGET || pass == 4) break;
    dropped |= order[pass];
  }
  if (dropped) NOTICE("[pages] home over budget, optional rows dropped");
}

// Routes (path table) and neighbours: rows until the row count or the byte budget runs out.
struct SmListCtx { bool shrt; int o, n, seen, rows; bool more; double now; size_t limit; };
static bool sm_route_row(const RNS::Bytes& k, uint8_t hops, double heard, const RNS::Bytes&, void* vc) {
  SmListCtx& c = *(SmListCtx*)vc;
  if (c.seen++ < c.o) return true;
  if (c.rows >= c.n) { c.more = true; return false; }
  char age[8]; std::string h = k.toHex(); if (c.shrt) h.resize(8);
  size_t before = sm_pn; P("%s %u %s\n", h.c_str(), hops, sm_age(c.now - heard, age));
  if (sm_pn > c.limit) { pb_cut(before); c.more = true; return false; }
  c.rows++; return true;
}
static void pg_list(bool routes, const RNS::Bytes& rid) {
  if (!(sm.home & SMH_ROUTES) && !sm_is_admin(rid)) { pg_denied(rid); return; }
  char pg = routes ? 'r' : 'b';
  bool form = Vis("a", "1"), shrt = form ? Fis("s", "1") : Vis("s", "1");
  int n = atoi(form ? Fv("n") : Vv("n")); if (n < 1 || n > 30) n = 10;
  int o = atoi(Vv("o")); if (o < 0) o = 0;
  size_t total = routes ? RNS::Transport::new_path_table().size() : sm_nbrs.size();
  if (routes) P("#!c=0\n>Routes " DIM("%u " MIDDOT " hops " MIDDOT " heard") "\n", (unsigned)total);
  else P("#!c=0\n>Neighbours " DIM("heard " MIDDOT " name") "\n");
  SmListCtx c{shrt, o, n, 0, 0, false, RNS::Utilities::OS::time(), (size_t)(SM_HOME_BUDGET - 165 - (o > 0 ? 36 : 0))};   // room for the footer (+ back link)
  if (routes) sm_walk_paths(sm_route_row, &c);
  else for (size_t i = o; i < sm_nbrs.size(); i++) {
    if (c.rows >= n) { c.more = true; break; }
    char age[8]; std::string h = sm_nbrs[i].id.toHex(); if (shrt) h.resize(8);
    size_t before = sm_pn; P("%s %s%s%s\n", h.c_str(), sm_age(c.now - sm_nbrs[i].heard, age), sm_nbrs[i].name[0] ? " " : "", sm_nbrs[i].name);
    if (sm_pn > c.limit) { pb_cut(before); c.more = true; break; }
    c.rows++;
  }
  if (total == 0) P(DIM("None heard yet"));
  else P(DIM("%d-%d/%u"), c.rows ? o + 1 : o, o + c.rows, (unsigned)total);
  if (c.more) { P(" "); PLf("next", pg, "s=%d|n=%d|o=%d", shrt, n, o + c.rows); }
  if (o > 0) { P(" "); PLf("back", pg, "s=%d|n=%d|o=%d", shrt, n, o > n ? o - n : 0); }
  char nb[4]; snprintf(nb, sizeof nb, "%d", n);
  P("\nShort "); PC("s", shrt); P(" Rows "); PF(2, "n", nb); P(" "); PL("Apply", pg, "s|n|a=1");
  P("\n"); PL(routes ? "Neighbours" : "Routes", routes ? 'b' : 'r'); P("  "); PL("Home", 'I');
}

static void pg_register(const RNS::Bytes& rid) {
  uint32_t now = millis(); Ph("Register as an admin");
  if (!sm.pw_on) { P("Registration is switched off.\nAsk an admin to add your identity.\n"); if (rid.size()) P(DIM("%s") "\n", rid.toHex().c_str()); PL("Home", 'I'); return; }
  if (!rid.size()) { P("Identify first, then reload.\n" DIM("The password registers the identity") "\n" DIM("you are browsing with.") "\n"); PL("Home", 'I'); return; }
  if (sm_is_admin(rid)) { Pmsg('o', "You are already an admin."); PL("Admin", 'a'); return; }
  for (auto& x : sm_pending) if (x.id == rid) { Pmsg('o', "Password accepted."); P("An admin must approve you.\n"); PL("Home", 'I'); return; }
  if (Vis("a", "r")) {
    SmFail* f = nullptr; for (auto& x : sm_fails) if (x.id == rid) f = &x;
    char m[40];
    if ((int32_t)(sm_reg_paused_until - now) > 0) Pmsg('b', "Registration paused, try later.");
    else if (f && (int32_t)(f->lock_until - now) > 0) { snprintf(m, sizeof m, "Locked for %lu min.", (unsigned long)((f->lock_until - now) / 60000 + 1)); Pmsg('b', m); }
    else {
      uint8_t h[32]; sm_pbkdf2(Fv("p"), sm.pw_salt, h);
      if (sm.pw_set && memcmp(h, sm.pw_hash, 32) == 0) {
        if (f) f->n = 0;
        if (sm.pw_approval) {
          if (sm_pending.size() >= 5) sm_pending.erase(sm_pending.begin());
          sm_pending.push_back({rid, now}); strcpy(sm_last_attempt, "ok, waiting"); sm_change(rid, "asked to be admin");
          Pmsg('o', "Password accepted."); P("An admin must approve you.\n"); PL("Home", 'I'); return;
        }
        if (!sm_admin_add(rid)) { Pmsg('b', "Admin list is full."); return; }
        strcpy(sm_last_attempt, "registered"); sm_change(rid, "registered by pw");
        Pmsg('o', "Welcome - you are now an admin."); PL("Open admin", 'a'); return;
      }
      if (!f) { if (sm_fails.size() >= 8) sm_fails.erase(sm_fails.begin()); sm_fails.push_back({rid, 0, 0}); f = &sm_fails.back(); }
      f->n++; sm_global_fails[sm_gf_next] = now; sm_gf_next = (sm_gf_next + 1) % 10;
      snprintf(sm_last_attempt, sizeof sm_last_attempt, "wrong %u/3", f->n);
      if (f->n >= 3) { f->lock_until = now + 15UL * 60000UL; f->n = 0; Pmsg('b', "Wrong password. Locked for 15 min."); }
      else { snprintf(m, sizeof m, "Wrong password. %u left.", 3 - f->n); Pmsg('b', m); }
      int recent = 0; for (uint32_t t : sm_global_fails) if (t && now - t < 3600000UL) recent++;
      if (recent >= 10) { sm_reg_paused_until = now + 3600000UL; NOTICE("[auth] 10 wrong passwords in an hour, registration paused"); }
      NOTICEF("[auth] %s wrong password", rid.toHex().c_str());
    }
  }
  P_verified(rid); P("\n" DIM("Password") " `<!20|p`>\n"); PL("Register", 'l', "p|a=r"); P("   "); PL("Cancel", 'I');
}

// Admin hub and its three sections
static void P_item(const char* label, char pg, const char* note = "") { PL(label, pg); if (*note) P(" " DIM("%s"), note); P("\n"); }
static void pg_hub() {
  Ph(nomadnet_name); P("%d%% " MIDDOT " up %s\n", sm_pct(), sm_up());
  if (sm_trial) { P("`Fda3! Radio trial`f "); PL("confirm", 'f'); P("\n"); }
  if (!sm_pending.empty()) { char l[16]; snprintf(l, sizeof l, "%u waiting", (unsigned)sm_pending.size()); P("`Fda3!`f "); PL(l, 'q'); P("\n"); }
  P("\n>>Admin\n"); PL("Settings", 's'); P("  "); PL("Access", 'c'); P("  "); PL("Device", 'd'); P("\n<\n"); PL("Home", 'I');
}
static const char* SM_ROLE_NAME[] = {"Fixed relay", "Access point", "Mobile", "End device"};
static int sm_role() {
  if (!sm_transport_on()) return 3;
  auto m = lora_interface ? lora_interface.mode() : RNS::Type::Interface::MODE_FULL;
  return m == RNS::Type::Interface::MODE_ACCESS_POINT ? 1 : m == RNS::Type::Interface::MODE_ROAMING ? 2 : 0;
}
static void pg_settings() {
  char r[24], w[16]; snprintf(r, sizeof r, "%s SF%d", sm_mhz(lora_freq), lora_sf); snprintf(w, sizeof w, "below %u%%", sm.pwr_below);
  Ph("Settings"); P_item("Name & announce", 'n'); P_item("Home page", 'h'); P_item("Map (rmap.world)", 'g', sm.map_on ? "published" : "off");
  P_item("Radio", 'f', r); P_item("Role", 'w', SM_ROLE_NAME[sm_role()]); P_item("Power", 'y', w); P("\n"); PBACK();
}
static void pg_access() {
  RNS::Bytes b; char a[8], c[8];
  snprintf(a, sizeof a, "%u/8", (unsigned)RNS::Transport::remote_management_allowed().size()); snprintf(c, sizeof c, "%u", (unsigned)sm_changes_read(b));
  Ph("Access"); P_item("Admins", 'k', a); P_item("Password", 'p', sm.pw_on ? "on" : "off"); P_item("Change log", 'j', c); P("\n"); PBACK();
}
static void pg_device() {
  Ph("Device"); P_item("Health", 'e'); P_item("Lights & Bluetooth", 'i', sm.leds == 0 ? "lights on" : sm.leds == 1 ? "lights off" : "lights 10 min");
  P_item("Logs", 'o'); P_item("Maintenance", 'x'); P_item("Restart & update", 'm'); P_item("About", 'u'); P("\n"); PBACK();
}

static void pg_name(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o';
  if (Vis("a", "s")) {
    char nm[33]; strncpy(nm, Fv("n"), 32); nm[32] = 0; for (int i = strlen(nm) - 1; i >= 0 && nm[i] == ' '; i--) nm[i] = 0;
    if (!nm[0]) { msg = "Name must be 1-32 characters."; kind = 'b'; }
    else {
      bool ch = strcmp(nm, nomadnet_name) != 0; strncpy(nomadnet_name, nm, sizeof(nomadnet_name) - 1);
      strncpy(sm.op, Fv("o"), sizeof(sm.op) - 1); sm.op[sizeof(sm.op) - 1] = 0;
      int ai = atoi(Fv("ai")); if (Qhas("field_ai") && ai >= 0 && ai <= 4) { sm.ann = ai; sm_nn_due = millis() + sm_ann_ms(); }
      sm_save();
#ifdef HAS_PROVISIONING
      RNS::Provisioning::Provisioner::instance().field(PROV_NS_GENERAL, PROV_GENERAL_NOMADNET_NAME, RNS::Provisioning::Value(nomadnet_name));
      RNS::Provisioning::Provisioner::instance().commit(PROV_NS_GENERAL);
#endif
      if (ch && nomadnet_destination) nomadnet_destination.announce(RNS::Bytes(nomadnet_name));
      sm_change(rid, ch ? "renamed node" : "name page saved");
      msg = ch ? "Saved and announced." : "Saved.";
    }
  }
  static const char* AL[] = {"30m", "1h", "3h", "6h", "12h"}; static const char* AV[] = {"0", "1", "2", "3", "4"};
  Ph("Name & announce"); Pmsg(kind, msg);
  P("Name     "); PF(32, "n", nomadnet_name); P("\nOperator "); PF(22, "o", sm.op); P("\nAnnounce every");
  for (int i = 0; i < 5; i++) { P(" "); PR("ai", AV[i], sm.ann == i); P("%s", AL[i]); }
  P("\n"); PL("Save", 'n', "n|o|ai|a=s"); P("   "); PBACK();
}

static void pg_homelayout(const RNS::Bytes& rid) {
  static const struct { uint8_t bit; const char* k; const char* l; } K[] = {{SMH_BAT, "b", "Battery"}, {SMH_UP, "u", "Uptime"}, {SMH_RADIO, "r", "Radio"}, {SMH_PATHS, "d", "Paths"}, {SMH_AIR, "x", "Airtime"}, {SMH_OP, "o", "Operator"}, {SMH_ROUTES, "p", "Routes pages"}};
  const char* msg = nullptr;
  if (Vis("a", "s")) { uint8_t h = 0; for (auto& k : K) if (Fis(k.k, "1")) h |= k.bit; sm.home = h; sm.api = Fis("api", "1"); sm_save(); sm_change(rid, "home page layout"); msg = "Saved."; }
  Ph("Home page"); Pmsg('o', msg); P(DIM("Ticked = public") "\n");
  for (auto& k : K) { PC(k.k, sm.home & k.bit); P(" %s\n", k.l); }
  PC("api", sm.api); P(" Telemetry API\n"); PL("Save", 'h', "*|a=s"); P("  "); PL("Preview", 'I', "v=1"); P("  "); PBACK();
}

static void pg_map(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o';
  if (Vis("a", "s")) {
    double la, lo; float h = atof(Fv("h"));
    if (!sm_parse_pos(Fv("p"), la, lo)) { msg = "Paste like 56.19858, -3.16662"; kind = 'b'; }
    else if (!(h > -500 && h < 9000)) { msg = "Height in metres, e.g. 310"; kind = 'b'; }
    else {
      sm.lat = la; sm.lon = lo; sm.height = (float)std::round(h); sm.map_on = Fis("on", "1"); sm.map_coarse = Fis("pr", "k"); sm_save();
      sm_change(rid, sm.map_on ? "map position, on" : "map position, off");
      if (sm.map_on) { sm_disc_start(); msg = "Saved. Announcing."; } else msg = "Saved.";
    }
  }
  if (Vis("a", "an") && sm.map_on) { sm_disc_start(); msg = "Announcing."; }
  char pos[40], ht[8]; snprintf(pos, sizeof pos, "%.5f, %.5f", sm.lat, sm.lon); snprintf(ht, sizeof ht, "%d", (int)sm.height);
  Ph("Map (rmap.world)"); Pmsg(kind, msg);
  P("Paste from Google Maps:\n"); PF(40, "p", pos);
  P("\nHeight "); PF(5, "h", ht); P("m  "); PR("pr", "e", !sm.map_coarse); P(" Exact "); PR("pr", "k", sm.map_coarse); P(" ~1 km\n");
  PC("on", sm.map_on); P(" Publish on rmap.world\n");
  if (sm.map_on) {
    if (sm_disc_busy) P("`Fda3Working out the stamp...`f\n");
    else if (sm_disc_last) P("`F2c5Sent %lu min ago`f\n", (unsigned long)((millis() - sm_disc_last) / 60000));
    else P(DIM("Not sent yet") "\n");
  }
  PL("Save", 'g', "p|h|pr|on|a=s"); if (sm.map_on) { P("  "); PL("Announce now", 'g', "a=an"); } P("  "); PBACK();
}

static void pg_radio(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o'; uint32_t now = millis();
  auto start = [&](const SmRadio& r) {
    if (!sm_trial) sm_trial_prev = sm_radio_now();
    sm_trial = true; sm_trial_until = now + SM_TRIAL_MS; sm_radio_apply(r);
    sm_change(rid, "radio trial"); msg = "Trial on. Keep within 5 min.";
  };
  if (Vis("a", "t")) {
    SmRadio r{(uint32_t)(atof(Fv("fq")) * 1e6 + 0.5), (uint32_t)(atof(Fv("bw")) * 1000 + 0.5), atoi(Fv("sf")), atoi(Fv("cr")), atoi(Fv("tx"))};
    static const uint32_t bws[] = {7800, 10400, 15600, 20800, 31250, 41700, 62500, 125000, 250000, 500000}; bool bw_ok = false; for (auto b : bws) if (b == r.bw) bw_ok = true;
    if (!(r.f > 137000000 && r.f < 1020000000) || !bw_ok || r.sf < 5 || r.sf > 12 || r.cr < 5 || r.cr > 8 || r.txp < -9 || r.txp > 22) { msg = "Out of range. Nothing changed."; kind = 'b'; }
    else start(r);
  }
  if (Vis("a", "p")) start(Vis("v", "433") ? SmRadio{433775000, 125000, 8, 5, 7} : SmRadio{867500000, 125000, 9, 5, 22});
  if (Vis("a", "k") && sm_trial) { sm_trial = false; eeprom_conf_save(); sm_change(rid, "radio kept"); msg = "Kept and saved."; }
  Ph("Radio"); Pmsg(kind, msg);
  if (sm_trial && !msg) { P("`Fda3Trial: reverts in %lu min`f ", (unsigned long)((sm_trial_until - now) / 60000 + 1)); PL("Keep", 'f', "a=k"); P("\n"); }
  char v[5][12]; snprintf(v[0], 12, "%.3f", lora_freq / 1e6); snprintf(v[1], 12, "%lu", (unsigned long)(lora_bw / 1000)); snprintf(v[2], 12, "%d", lora_sf); snprintf(v[3], 12, "%d", lora_cr); snprintf(v[4], 12, "%d", lora_txp);
  P("MHz "); PF(8, "fq", v[0]); P(" kHz "); PF(3, "bw", v[1]); P("\nSF "); PF(2, "sf", v[2]); P(" CR "); PF(1, "cr", v[3]); P(" dBm "); PF(2, "tx", v[4]); P("\n");
  PL("Try these", 'f', "fq|bw|sf|cr|tx|a=t"); P("\n" DIM("Preset:") " "); PL("ScotMesh 868", 'f', "a=p|v=868"); P(" "); PL("433", 'f', "a=p|v=433"); P("\n"); PBACK();
}

static void pg_role(const RNS::Bytes& rid) {
  const char* msg = nullptr;
  if (Vis("a", "s") && Qhas("field_r")) {
    int r = atoi(Fv("r"));
    if (r >= 0 && r <= 3) {
#ifdef HAS_PROVISIONING
      auto& Pv = RNS::Provisioning::Provisioner::instance();
      Pv.field(1, 1, RNS::Provisioning::Value(r != 3)); Pv.commit(1);
      if (r != 3) { Pv.field(PROV_NS_GENERAL, PROV_GENERAL_LORA_MODE, RNS::Provisioning::Value::make_enum(r == 1 ? RNS::Type::Interface::MODE_ACCESS_POINT : r == 2 ? RNS::Type::Interface::MODE_ROAMING : RNS::Type::Interface::MODE_FULL)); Pv.commit(PROV_NS_GENERAL); }
#endif
      char w[20]; snprintf(w, sizeof w, "role: %s", SM_ROLE_NAME[r]); sm_change(rid, w); msg = "Saved. Restart to apply.";
    }
  }
  static const char* X[] = {"FULL", "ACCESS_POINT", "ROAMING", "transport off"}; static const char* RV[] = {"0", "1", "2", "3"};
  int cur = sm_role();
  Ph("Role"); Pmsg('o', msg);
  for (int i = 0; i < 4; i++) { PR("r", RV[i], cur == i); P(" %s " DIM("%s") "\n", SM_ROLE_NAME[i], X[i]); }
  P(DIM("Relays forward for others; end devices never do.") "\n"); PL("Save", 'w', "r|a=s"); P("  "); PBACK();
}

static void pg_power(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o';
  if (Vis("a", "s")) {
    int n = atoi(Fv("lb"));
    if (n < 5 || n > 60) { msg = "Threshold: 5-60%."; kind = 'b'; }
    else { sm.pwr_below = n; sm.pwr_act = Fis("la", "0") ? 0 : Fis("la", "2") ? 2 : 1; sm.pwr_lock = Fis("bl", "1"); sm_save(); sm_change(rid, "power settings"); msg = "Saved."; }
  }
  char lb[4]; snprintf(lb, sizeof lb, "%u", sm.pwr_below);
  Ph("Power"); Pmsg(kind, msg); P("Below "); PF(2, "lb", lb); P("%% battery:\n");
  PR("la", "1", sm.pwr_act == 1); P(" Lower TX power to 10 dBm\n"); PR("la", "2", sm.pwr_act == 2); P(" Radio off until charged\n"); PR("la", "0", sm.pwr_act == 0); P(" Nothing\n");
  PC("bl", sm.pwr_lock); P(" Radio off below 3.3 V\n");
  if (sm_power_limited || sm_power_sleep) Pmsg('a', sm_power_sleep ? "Radio off now (low battery)" : "TX power lowered now");
  PL("Save", 'y', "lb|la|bl|a=s"); P("  "); PBACK();
}

static void pg_health() {
  Ph("Health");
  P(DIM("RAM") " %u KB free, flash %u KB\n", (unsigned)(RNS::Utilities::Memory::heap_available() / 1024), (unsigned)(RNS::Utilities::OS::storage_available() / 1024));
  P(DIM("Up") " %s, %lu starts (%s)\n", sm_up(), (unsigned long)sm.reboots, sm_reset_reason);
  P(DIM("Radio") " noise %d, last %d/%ddB\n", noise_floor, last_rssi, (int)((int8_t)last_snr_raw) / 4);
  P(DIM("Air") " %.1f%% now, %.1f%% avg\n", airtime * 100, longterm_airtime * 100);
  P(DIM("Pkts") " rx %lu, tx %lu\n", (unsigned long)(lora_interface ? lora_interface.rx() : 0), (unsigned long)(lora_interface ? lora_interface.tx() : 0));
  P(DIM("Tables") " paths %u/%u, ann %u\nknown %u, links %u, nbrs %u\n", (unsigned)RNS::Transport::new_path_table().size(), (unsigned)RNS::Transport::path_table_maxsize(),
    (unsigned)RNS::Transport::announce_table().size(), (unsigned)RNS::Identity::known_destinations().size(), (unsigned)RNS::Transport::active_links().size(), (unsigned)sm_nbrs.size());
  PBACK();
}

static void pg_lights_bt(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o';
  if (Vis("a", "l")) { sm.leds = Fis("l", "off") ? 1 : Fis("l", "b10") ? 2 : 0; sm_save(); sm_change(rid, "lights setting"); msg = "Saved."; }
  if (Vis("a", "bl")) { sm_blink_until = millis() + 30000UL; msg = "Blinking for 30 s."; }
#if HAS_BLUETOOTH || HAS_BLE
  if (Vis("a", "b")) { bool on = Fis("b", "on"); if (on) bt_start(); else bt_stop(); bt_conf_save(on); sm_change(rid, on ? "Bluetooth on" : "Bluetooth off"); msg = "Saved."; }
#if SM_CAN_UNPAIR
  if (Vis("a", "u")) { Ph("Forget all paired phones?"); P(DIM("They will need to pair again.") "\n"); PLf("Yes, unpair", 'i', "a=uy|k=%s", sm_token("unpair")); P("  "); PL("Cancel", 'i'); return; }
  if (Vis("a", "uy")) {
    if (sm_token_use(Vv("k"), "unpair")) {
  #if MCU_VARIANT == MCU_NRF52
      Bluefruit.Periph.clearBonds();
  #else
      bt_debond_all();
  #endif
      sm_change(rid, "Bluetooth unpaired"); msg = "All phones unpaired.";
    } else { msg = "Expired. Nothing changed."; kind = 'b'; }
  }
#endif
#endif
  Ph("Lights & Bluetooth"); Pmsg(kind, msg);
  PR("l", "on", sm.leds == 0); P(" On "); PR("l", "off", sm.leds == 1); P(" Off "); PR("l", "b10", sm.leds == 2); P(" 10 min after start\n");
  PL("Save", 'i', "l|a=l"); P("  "); PL("Blink 30 s", 'i', "a=bl"); P(" " DIM("errors always show") "\n");
#if HAS_BLUETOOTH || HAS_BLE
  bool on = bt_state != BT_STATE_OFF;
  P(">>Bluetooth\n"); PR("b", "on", on); P(" On "); PR("b", "off", !on); P(" Off  "); PL("Save", 'i', "b|a=b");
#if SM_CAN_UNPAIR
  P("  "); PL("Unpair all", 'i', "a=u");
#endif
  P("\n<\n");
#endif
  PBACK();
}

static void pg_logs() {
  Ph("Log");
  for (int i = 0; i < sm_log_count; i++) P("%.38s\n", sm_log_ring[(sm_log_next + 5 - sm_log_count + i) % 5]);
  PL("Refresh", 'o'); P("  "); PBACK();
}

static void pg_changes() {
  int o = atoi(Vv("o")); if (o < 0) o = 0;
  RNS::Bytes b; size_t total = sm_changes_read(b); uint32_t now = (uint32_t)RNS::Utilities::OS::time();
  P("#!c=0\n>Change log " DIM("%u/32") "\n", (unsigned)total);
  if (!total) P(DIM("No changes yet.") "\n");
  for (size_t i = o; i < total && i < (size_t)o + 3; i++) {
    SmChange c; memcpy(&c, b.data() + i * sizeof(SmChange), sizeof(c)); char age[8];
    P("%s ago %s\n" DIM("%s") "\n", sm_age(now - c.t, age), c.what, RNS::Bytes(c.id, 16).toHex().c_str());
  }
  if (o + 3 < (int)total) { PLf("older", 'j', "o=%d", o + 3); P("\n"); }
  PBACK();
}

static void pg_maint(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o'; const char* a = Vv("a");
  if (!strcmp(a, "cs") || !strcmp(a, "fr")) {
    bool cs = !strcmp(a, "cs");
    Ph(cs ? "Clear stored routes & data?" : "Factory reset?");
    P(DIM("%s") "\n", cs ? "Routes are relearned; the node restarts." : "Settings to defaults. Keeps identity + admins.");
    PLf("Yes", 'x', "a=y|w=%s|k=%s", a, sm_token(a)); P("  "); PL("Cancel", 'x'); return;
  }
  if (!strcmp(a, "y")) {
    const char* w = Vv("w");
    if (!sm_token_use(Vv("k"), w)) { msg = "Expired."; kind = 'b'; }
    else if (!strcmp(w, "cs")) { sm_change(rid, "cleared stored data"); RNS::Transport::clear_storage(); hard_reset(); }
    else if (!strcmp(w, "fr")) {
      sm_change(rid, "factory reset");
      std::set<RNS::Bytes> keep = RNS::Transport::remote_management_allowed();
#ifdef HAS_PROVISIONING
      RNS::Provisioning::Provisioner::instance().factory_reset();
#endif
      sm_admins_persist(keep);
      uint32_t reboots = sm.reboots; sm = SmConfig(); sm.reboots = reboots; sm_save(); hard_reset();
    }
  }
  if (!strcmp(a, "an")) { if (nomadnet_destination) nomadnet_destination.announce(RNS::Bytes(nomadnet_name)); sm_change(rid, "announce now"); msg = "Announced."; }
  if (!strcmp(a, "sc")) { sm.sched = Fis("sm", "d") ? 1 : Fis("sm", "w") ? 2 : 0; sm_save(); sm_change(rid, "auto restart"); msg = "Saved."; }
  Ph("Maintenance"); Pmsg(kind, msg); PL("Announce now", 'x', "a=an");
  P("\n>>Auto restart\n"); PR("sm", "o", sm.sched == 0); P(" Off "); PR("sm", "d", sm.sched == 1); P(" Every day "); PR("sm", "w", sm.sched == 2); P(" Every week "); PL("Save", 'x', "sm|a=sc");
  P("\n>>Reset\n"); PL("Clear routes & data", 'x', "a=cs"); P("  "); PL("Factory reset", 'x', "a=fr"); P("\n<\n"); PBACK();
}

static void pg_update(const RNS::Bytes& rid) {
  const char* a = Vv("a"); const char* msg = nullptr;
  if (!strcmp(a, "cr")) { Ph("Restart the node?"); P(DIM("Offline for about 15 seconds.") "\n\n"); PLf("Yes, restart", 'm', "a=dr|k=%s", sm_token("restart")); P("   "); PL("Cancel", 'm'); return; }
  if (!strcmp(a, "dr")) {
    if (sm_token_use(Vv("k"), "restart")) { sm_change(rid, "restart"); P("#!c=0\n`F2c5Restarting. Reload in 15 seconds.`f"); sm_dfu_action = 1; sm_dfu_action_at = millis(); return; }
    msg = "Expired.";
  }
#if MCU_VARIANT == MCU_NRF52
  bool power_ok = battery_percent >= 30 || sm_charging() || battery_voltage < 0.1;
  bool ble = !strcmp(a, "cb"), usb = !strcmp(a, "cu");
  if (ble || usb) {
    if (!power_ok) { Ph("Firmware update"); Pmsg('b', "Battery low and not charging."); P(DIM("Needs 30%% or a charger.") "\n"); PL("Back", 'm'); return; }
    if (ble) { Ph("Bluetooth update window?"); P("Restarts and advertises \"" BOARD_SHORT_NAME " DFU\"\nfor 20 min. Flash the .zip with\nnRF DFU or nRF Connect.\n`Fda3Someone must be in range.`f\n"); }
    else { Ph("USB bootloader?"); P("Restarts into the bootloader and\nstays there until flashed or reset.\n`Fda3Only if someone is with the node.`f\n"); }
    P("\n"); PLf("Yes, start", 'm', "a=%s|k=%s", ble ? "db" : "du", sm_token(a)); P("\n" DIM("This link works once, for 2 min.")); return;
  }
  bool db = !strcmp(a, "db"), du = !strcmp(a, "du");
  if (db || du) {
    if (!sm_token_use(Vv("k"), db ? "cb" : "cu")) msg = "Expired.";
    else {
      sm_change(rid, db ? "BLE update window" : "USB bootloader");
      if (db) P("#!c=0\n`F2c5Update window open for 20 min.`f\nLook for \"" BOARD_SHORT_NAME " DFU\".");
      else P("#!c=0\n`F2c5Now in the USB bootloader.`f\n" DIM("Offline until flashed or reset."));
      sm_dfu_action = db ? 2 : 3; sm_dfu_action_at = millis(); return;
    }
  }
#endif
  Ph("Restart & update"); Pmsg('b', msg);
  P("Up %s  ", sm_up()); PL("Restart", 'm', "a=cr"); P("\n>>Firmware update\n");
#if MCU_VARIANT == MCU_NRF52
  P(DIM("nRF52840") "\n");
  if (sm_dfu_window) P("`Fda3Update window open now`f\n");
  if (!power_ok) Pmsg('b', "Battery low: needs 30% or charging");
  else { PL("Bluetooth update", 'm', "a=cb"); P("\n"); PL("USB bootloader", 'm', "a=cu"); P("\n"); }
#else
  P("Not possible over the air on\nthis board yet. Update over USB.\n");
#endif
  P("<\n"); PBACK();
}

static void pg_about() {
  auto hx = [](const RNS::Destination& d) { return d ? d.hash().toHex() : std::string("-"); };
  Ph("About"); P("%s " MIDDOT " " BOARD_SHORT_NAME "\n", SCOTMESH_FW_TAG);
  P(DIM("Transport identity") "\n%s\n", RNS::Transport::identity().hash().toHex().c_str());
  P(DIM("Management") "\n%s\n", hx(RNS::Transport::remote_management_destination()).c_str());
  P(DIM("NomadNet") "\n%s\n", hx(nomadnet_destination).c_str());
  P(DIM("Probe") "\n%s\n", hx(RNS::Transport::probe_destination()).c_str());
  PBACK();
}

static void pg_admins(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o'; const char* a = Vv("a"); int o = atoi(Vv("o")); if (o < 0) o = 0;
  std::set<RNS::Bytes> ids = RNS::Transport::remote_management_allowed();
  std::vector<RNS::Bytes> list(ids.begin(), ids.end());
  auto what_for = [&](int i, char* w) { snprintf(w, 20, "rm%.8s", list[i].toHex().c_str()); };
  if (!strcmp(a, "ad")) {
    char h[40]; strncpy(h, Fv("h"), 39); h[39] = 0; for (char* c = h; *c; c++) *c = tolower((unsigned char)*c);
    bool hex = strlen(h) == 32 && strspn(h, "0123456789abcdef") == 32; RNS::Bytes id; if (hex) id.assignHex(h);
    if (!hex) { msg = "An identity is 32 hex characters."; kind = 'b'; }
    else if (ids.count(id)) { msg = "Already an admin."; kind = 'b'; }
    else if (!sm_admin_add(id)) { msg = "The list is full (8)."; kind = 'b'; }
    else { sm_change(rid, "added an admin"); msg = "Added."; ids = RNS::Transport::remote_management_allowed(); list.assign(ids.begin(), ids.end()); }
  }
  if (!strcmp(a, "rm")) {
    int i = atoi(Vv("i"));
    if (i >= 0 && i < (int)list.size()) {
      char w[20]; what_for(i, w);
      Ph("Remove this admin?"); P("%s\n\n", list[i].toHex().c_str()); PLf("Yes, remove", 'k', "a=ry|i=%d|k=%s", i, sm_token(w)); P("   "); PL("Cancel", 'k'); return;
    }
  }
  if (!strcmp(a, "ry")) {
    int i = atoi(Vv("i")); char w[20] = "";
    if (i >= 0 && i < (int)list.size()) what_for(i, w);
    if (!w[0] || !sm_token_use(Vv("k"), w)) { msg = "Expired - nothing changed."; kind = 'b'; }
    else if (ids.size() <= 1) { msg = "You cannot remove the last admin."; kind = 'b'; }
    else { ids.erase(list[i]); sm_admins_persist(ids); sm_change(rid, "removed an admin"); msg = "Removed."; list.assign(ids.begin(), ids.end()); }
  }
  P("#!c=0\n>Admins " DIM("%u/8") "\n", (unsigned)list.size()); Pmsg(kind, msg);
  for (int i = o; i < (int)list.size() && i < o + 3; i++) {
    std::string h = list[i].toHex();
    if (list[i] == rid) P("%s `F2c5you`f\n", h.c_str()); else { PLf(h.c_str(), 'k', "a=rm|i=%d", i); P("\n"); }
  }
  if ((int)list.size() > 3) { PLf("more", 'k', "o=%d", o + 3 < (int)list.size() ? o + 3 : 0); P("\n"); }
  if (list.size() < 8) { P(DIM("Add") " "); PF(32, "h", ""); P(" "); PL("Add", 'k', "h|a=ad"); P("\n"); }
  PBACK();
}

static void pg_queue(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o'; const char* a = Vv("a"); int i = atoi(Vv("i"));
  if ((!strcmp(a, "ap") || !strcmp(a, "dn")) && i >= 0 && i < (int)sm_pending.size()) {
    RNS::Bytes id = sm_pending[i].id; sm_pending.erase(sm_pending.begin() + i);
    if (!strcmp(a, "dn")) { sm_change(rid, "denied a request"); msg = "Denied."; }
    else if (!sm_admin_add(id)) { msg = "Admin list is full (8)."; kind = 'b'; }
    else { sm_change(rid, "approved an admin"); msg = "Approved."; }
  }
  Ph("Waiting for approval"); Pmsg(kind, msg);
  if (sm_pending.empty()) P(DIM("Nobody is waiting.") "\n");
  for (size_t k = 0; k < sm_pending.size() && k < 2; k++) {
    P("%s\n" DIM("%lu min ago") " ", sm_pending[k].id.toHex().c_str(), (unsigned long)((millis() - sm_pending[k].at) / 60000));
    PLf("approve", 'q', "a=ap|i=%u", (unsigned)k); P(" "); PLf("deny", 'q', "a=dn|i=%u", (unsigned)k); P("\n");
  }
  if (sm_pending.size() > 2) P(DIM("+%u more") "\n", (unsigned)(sm_pending.size() - 2));
  PBACK();
}

static void pg_password(const RNS::Bytes& rid) {
  const char* msg = nullptr; char kind = 'o';
  if (Vis("a", "s")) {
    bool on = Fis("e", "1"), ap = Fis("v", "1"); const char* p1 = Fv("p1"); const char* p2 = Fv("p2");
    if ((*p1 || *p2) && strcmp(p1, p2)) { msg = "Passwords differ. Unchanged."; kind = 'b'; }
    else if (*p1 && strlen(p1) < 8) { msg = "At least 8 characters. Unchanged."; kind = 'b'; }
    else if (on && !sm.pw_set && !*p1) { msg = "Set a password first."; kind = 'b'; }
    else {
      if (*p1) { RNS::Bytes s = RNS::Cryptography::random(16); memcpy(sm.pw_salt, s.data(), 16); sm_pbkdf2(p1, sm.pw_salt, sm.pw_hash); sm.pw_set = 1; }
      sm.pw_on = on; sm.pw_approval = ap; if (on) sm_reg_paused_until = 0; sm_save(); sm_change(rid, "password settings"); msg = "Saved.";
    }
  }
  Ph("Password registration"); Pmsg(kind, msg);
  if ((int32_t)(sm_reg_paused_until - millis()) > 0) Pmsg('b', "Paused after 10 wrong tries");
  PC("e", sm.pw_on); P(" On   "); PC("v", sm.pw_approval); P(" Needs approval\nNew   `<!16|p1`>\nAgain `<!16|p2`> blank=keep\n");
  PL("Save", 'p', "e|v|p1|p2|a=s"); P("  "); PBACK();
  if (sm_last_attempt[0]) P("\n>>Last attempt\n%s", sm_last_attempt);
}

// ---------------------------------------------------------------------------
// Telemetry API (JSON, no micron, open to unidentified clients)
// ---------------------------------------------------------------------------
static void J_bat() { P("\"percent\":%d,\"voltage\":%.2f,\"charging\":%s", sm_pct(), battery_voltage, sm_charging() ? "true" : "false"); }
static void J_up() { P("\"uptime\":%lu,\"reset\":\"%s\"", (unsigned long)(sm_uptime_ms() / 1000), sm_reset_reason); }
static void J_net() {
  P("\"routes\":%u,\"neighbours\":%u,\"rx\":%lu,\"tx\":%lu,\"links\":%u", (unsigned)RNS::Transport::new_path_table().size(), (unsigned)sm_nbrs.size(),
    (unsigned long)(lora_interface ? lora_interface.rx() : 0), (unsigned long)(lora_interface ? lora_interface.tx() : 0), (unsigned)RNS::Transport::active_links().size());
}
static void J_ram() { P("\"free_ram\":%u,\"free_flash\":%u", (unsigned)RNS::Utilities::Memory::heap_available(), (unsigned)RNS::Utilities::OS::storage_available()); }
static void J_clean(char* s) { for (; *s; s++) if (*s == '"' || *s == '\\') *s = '\''; }
struct SmApiCtx { bool shrt; int o, n, seen, rows; bool more; double now; };
static bool sm_api_path_row(const RNS::Bytes& k, uint8_t hops, double heard, const RNS::Bytes& via, void* vc) {
  SmApiCtx& c = *(SmApiCtx*)vc;
  if (c.seen++ < c.o) return true;
  if (c.rows >= c.n) { c.more = true; return false; }
  std::string d = k.toHex(), v = via ? via.toHex() : std::string(); if (c.shrt) { d.resize(8); if (v.size() > 8) v.resize(8); }
  size_t before = sm_pn; P("%s[\"%s\",%u,%ld,\"%s\"]", c.rows ? "," : "", d.c_str(), hops, (long)(c.now - heard), v.c_str());
  if (sm_pn > SM_HOME_BUDGET - 16) { pb_cut(before); c.more = true; return false; }
  c.rows++; return true;
}
static void api_reply(const char* path) {
  if (!sm.api) { P("{\"error\":\"api disabled\"}"); return; }
  const char* e = path + 4; if (*e == '/') e++;
  if (!*e) { P("{\"v\":1,\"api\":[\"bat\",\"up\",\"radio\",\"net\",\"sys\",\"health\",\"pos\",\"paths\",\"nbrs\",\"all\"]}"); return; }
  if (!strcmp(e, "bat")) { P("{"); J_bat(); P("}"); return; }
  if (!strcmp(e, "up")) { P("{"); J_up(); P("}"); return; }
  if (!strcmp(e, "net")) { P("{"); J_net(); P("}"); return; }
  if (!strcmp(e, "all")) { P("{"); J_bat(); P(","); J_up(); P(","); J_net(); P(",\"airtime\":%.1f}", airtime * 100); return; }
  if (!strcmp(e, "radio")) {
    P("{\"freq\":%lu,\"bw\":%lu,\"sf\":%d,\"cr\":%d,\"txp\":%d,\"airtime\":%.1f,\"noise\":%d,\"rssi\":%d,\"snr\":%d}",
      (unsigned long)lora_freq, (unsigned long)lora_bw, lora_sf, lora_cr, lora_txp, airtime * 100, noise_floor, last_rssi, (int)((int8_t)last_snr_raw) / 4);
    return;
  }
  if (!strcmp(e, "sys")) { char nm[64]; strncpy(nm, nomadnet_name, 63); nm[63] = 0; J_clean(nm); P("{\"fw\":\"%s\",\"board\":\"%s\",\"name\":\"%s\",", SCOTMESH_FW_TAG, BOARD_SHORT_NAME, nm); J_ram(); P("}"); return; }
  if (!strcmp(e, "health")) {
    P("{"); J_ram(); P(",\"reboots\":%lu,\"reset\":\"%s\",\"paths\":%u,\"paths_max\":%u,\"announces\":%u,\"neighbours\":%u}", (unsigned long)sm.reboots, sm_reset_reason,
      (unsigned)RNS::Transport::new_path_table().size(), (unsigned)RNS::Transport::path_table_maxsize(), (unsigned)RNS::Transport::announce_table().size(), (unsigned)sm_nbrs.size());
    return;
  }
  if (!strcmp(e, "pos")) {
    if (!sm.map_on) { P("{\"error\":\"not published\"}"); return; }
    double la = sm.lat, lo = sm.lon; if (sm.map_coarse) { la = std::round(la * 100) / 100; lo = std::round(lo * 100) / 100; }
    P("{\"lat\":%.5f,\"lon\":%.5f,\"height\":%d}", la, lo, (int)sm.height); return;
  }
  bool paths = !strcmp(e, "paths"), nbrs = !strcmp(e, "nbrs");
  if (!paths && !nbrs) { P("{\"error\":\"unknown endpoint\",\"see\":\"/api\"}"); return; }
  SmApiCtx c{!strcmp(Q("s"), "1"), atoi(Q("o")), Qhas("n") ? atoi(Q("n")) : 5, 0, 0, false, RNS::Utilities::OS::time()};
  if (c.o < 0) c.o = 0;
  if (c.n < 1) c.n = 1;
  if (c.n > 15) c.n = 15;
  if (paths) {
    P("{\"total\":%u,\"o\":%d,\"cols\":[\"dest\",\"hops\",\"age_s\",\"via\"],\"rows\":[", (unsigned)RNS::Transport::new_path_table().size(), c.o);
    sm_walk_paths(sm_api_path_row, &c);
  } else {
    P("{\"total\":%u,\"o\":%d,\"cols\":[\"dest\",\"age_s\",\"name\"],\"rows\":[", (unsigned)sm_nbrs.size(), c.o);
    for (size_t i = c.o; i < sm_nbrs.size(); i++) {
      if (c.rows >= c.n) { c.more = true; break; }
      std::string d = sm_nbrs[i].id.toHex(); if (c.shrt) d.resize(8);
      char nm[20]; strncpy(nm, sm_nbrs[i].name, 19); nm[19] = 0; J_clean(nm);
      size_t before = sm_pn; P(nm[0] ? "%s[\"%s\",%ld,\"%s\"]" : "%s[\"%s\",%ld,null]", c.rows ? "," : "", d.c_str(), (long)(c.now - sm_nbrs[i].heard), nm);
      if (sm_pn > SM_HOME_BUDGET - 16) { pb_cut(before); c.more = true; break; }
      c.rows++;
    }
  }
  P(c.more ? "],\"more\":true}" : "]}");
}

// ---------------------------------------------------------------------------
// Request handler (one for every page and API path)
// ---------------------------------------------------------------------------
RNS::Bytes sm_serve(const RNS::Bytes& path_b, const RNS::Bytes& data, const RNS::Bytes& request_id, const RNS::Bytes& link_id, const RNS::Identity& remote_identity, double requested_at) {
  char path[24]; size_t pl = path_b.size() < sizeof(path) - 1 ? path_b.size() : sizeof(path) - 1; memcpy(path, path_b.data(), pl); path[pl] = 0;
  RNS::Bytes rid = remote_identity ? remote_identity.hash() : RNS::Bytes{};
  bool api = !strncmp(path, "/api", 4);
  pb_reset();
  if (RNS::Utilities::Memory::heap_available() < SM_RAM_FLOOR) P(api ? "{\"error\":\"busy\"}" : "#!c=0\n>Busy\nLow on memory, try again later.");
  else if (sm_parse(data), api) api_reply(path);
  else {
    char pg = !strcmp(path, "/page/index.mu") ? 'I' : (strlen(path) == 10 && !strcmp(path + 7, ".mu")) ? path[6] : '?';
    if (pg == 'I') pg_home(rid);
    else if (pg == 'r' || pg == 'b') pg_list(pg == 'r', rid);
    else if (pg == 'l') pg_register(rid);
    else if (!sm_is_admin(rid)) pg_denied(rid);
    else switch (pg) {
      case 'a': pg_hub(); break;
      case 's': pg_settings(); break;
      case 'c': pg_access(); break;
      case 'd': pg_device(); break;
      case 'n': pg_name(rid); break;
      case 'h': pg_homelayout(rid); break;
      case 'g': pg_map(rid); break;
      case 'f': pg_radio(rid); break;
      case 'w': pg_role(rid); break;
      case 'y': pg_power(rid); break;
      case 'k': pg_admins(rid); break;
      case 'q': pg_queue(rid); break;
      case 'p': pg_password(rid); break;
      case 'j': pg_changes(); break;
      case 'e': pg_health(); break;
      case 'i': pg_lights_bt(rid); break;
      case 'o': pg_logs(); break;
      case 'x': pg_maint(rid); break;
      case 'm': pg_update(rid); break;
      case 'u': pg_about(); break;
      default: Ph("Not found"); PL("Home", 'I');
    }
  }
  if (sm_pn > SM_HARD_LIMIT) {
    NOTICEF("[pages] %s reply %u B over one packet, not sent", path, (unsigned)sm_pn);
    pb_reset(); if (api) P("{\"error\":\"too large\"}"); else { Ph("Page too large"); PL("Home", 'I'); }
  }
  MsgPack::Packer packer; packer.packBinary((const uint8_t*)sm_pb, sm_pn);
  return RNS::Bytes(packer.data(), packer.size());
}

static const char SM_PAGE_IDS[] = "rblascdnhgfwykqpjeioxmu";
static const char* SM_API_PATHS[] = {"/api", "/api/bat", "/api/up", "/api/radio", "/api/net", "/api/sys", "/api/health", "/api/pos", "/api/all", "/api/paths", "/api/nbrs"};

void sm_register(RNS::Destination& dest) {
  dest.register_request_handler("/page/index.mu", sm_serve, RNS::Type::Destination::ALLOW_ALL);
  for (const char* c = SM_PAGE_IDS; *c; c++) { char p[12]; snprintf(p, sizeof p, "/page/%c.mu", *c); dest.register_request_handler(p, sm_serve, RNS::Type::Destination::ALLOW_ALL); }
  for (const char* p : SM_API_PATHS) dest.register_request_handler(p, sm_serve, RNS::Type::Destination::ALLOW_ALL);
  RNS::Transport::register_announce_handler(std::make_shared<SmAnnounceWatch>());
  sm_disc = RNS::Destination(RNS::Transport::identity(), RNS::Type::Destination::IN, RNS::Type::Destination::SINGLE, "rnstransport", "discovery.interface");
  sm_disc_due = millis() + 5UL * 60000UL;          // first rmap.world announce 5 min after start
  sm_nn_due = millis() + sm_ann_ms();              // the start-up announce already went out
  NOTICEF("[scotmesh] %u pages/API paths registered, fw %s", (unsigned)(sizeof(SM_PAGE_IDS) + sizeof(SM_API_PATHS) / sizeof(SM_API_PATHS[0])), SCOTMESH_FW_TAG);
}

// Early boot: settings, start counter, reset reason.
void sm_boot() {
  sm_load(); sm.reboots++; sm_save();
#if MCU_VARIANT == MCU_NRF52
  uint32_t rr = readResetReason();
  sm_reset_reason = rr == 0 ? "power-on" : (rr & POWER_RESETREAS_DOG_Msk) ? "watchdog" : (rr & POWER_RESETREAS_SREQ_Msk) ? "soft-reset" : (rr & POWER_RESETREAS_LOCKUP_Msk) ? "lockup" : (rr & POWER_RESETREAS_RESETPIN_Msk) ? "reset-pin" : (rr & POWER_RESETREAS_OFF_Msk) ? "wake" : "other";
#elif MCU_VARIANT == MCU_ESP32
  switch (esp_reset_reason()) {
    case ESP_RST_POWERON: sm_reset_reason = "power-on"; break; case ESP_RST_SW: sm_reset_reason = "soft-reset"; break; case ESP_RST_PANIC: sm_reset_reason = "panic"; break;
    case ESP_RST_INT_WDT: case ESP_RST_TASK_WDT: case ESP_RST_WDT: sm_reset_reason = "watchdog"; break; case ESP_RST_BROWNOUT: sm_reset_reason = "brown-out"; break; default: sm_reset_reason = "other";
  }
#endif
}

// Called every loop pass.
void sm_loop() {
  uint32_t now = millis(); uint64_t up = sm_uptime_ms();
  // lights
  sm_leds_off = sm.leds == 1 || (sm.leds == 2 && up > 600000ULL);
  if ((int32_t)(sm_blink_until - now) > 0) {       // "Blink 30 s" wins over "lights off"
    sm_leds_off = false;
    if ((now / 250) & 1) { led_tx_off(); led_rx_on(); } else { led_rx_off(); led_tx_on(); }
  }
  // radio trial
  if (sm_trial && (int32_t)(now - sm_trial_until) >= 0) { sm_trial = false; sm_radio_apply(sm_trial_prev); NOTICE("[radio] trial not confirmed within 5 min, reverted"); }
  // restart / update actions run a few seconds after the reply has gone out
  if (sm_dfu_action && now - sm_dfu_action_at > 3000) {
    uint8_t what = sm_dfu_action; sm_dfu_action = 0;
#if MCU_VARIANT == MCU_NRF52
    if (what == 2) { uint8_t sd = 0; sd_softdevice_is_enabled(&sd); if (sd) { sd_power_gpregret_clr(1, 0xFF); sd_power_gpregret_set(1, SM_DFU_MAGIC); } else NRF_POWER->GPREGRET2 = SM_DFU_MAGIC; }
    if (what == 3) enterUf2Dfu();
#endif
    (void)what; hard_reset();
  }
  // BLE update window timeout
  if (sm_dfu_window && now > SM_DFU_WINDOW_MS) { NOTICE("[dfu] update window closed, restarting normally"); hard_reset(); }
  // auto restart
  if (sm.sched && !sm_trial && !sm_dfu_window && up > (sm.sched == 1 ? 86400000ULL : 604800000ULL)) { NOTICE("[scotmesh] scheduled restart"); hard_reset(); }
  // power management, once a minute
  static uint32_t last_pwr = 0;
  if (now - last_pwr > 60000UL && battery_voltage > 0.1) {
    last_pwr = now;
    bool low = !sm_charging() && battery_percent < sm.pwr_below, recovered = sm_charging() || battery_percent >= sm.pwr_below + 10;
    bool undervolt = sm.pwr_lock && !sm_charging() && battery_voltage < 3.3, voltok = battery_voltage >= 3.5 || sm_charging();
    if ((low && sm.pwr_act == 2) || undervolt) { if (!sm_power_sleep) { sm_power_sleep = true; stopRadio(); NOTICE("[power] low battery, radio off"); } }
    else if (sm_power_sleep && recovered && voltok) { sm_power_sleep = false; startRadio(); NOTICE("[power] battery recovered, radio on"); }
    if (low && sm.pwr_act == 1 && !sm_power_limited && lora_txp > 10) { sm_saved_txp = lora_txp; lora_txp = 10; setTXPower(); sm_power_limited = true; NOTICE("[power] low battery, TX power lowered"); }
    else if (sm_power_limited && recovered) { lora_txp = sm_saved_txp; setTXPower(); sm_power_limited = false; NOTICE("[power] battery recovered, TX power restored"); }
  }
  // announces
  if (sm.map_on && sm_disc && !sm_disc_busy && sm_disc_due && (int32_t)(now - sm_disc_due) >= 0) { sm_disc_due = now + sm_ann_ms(); sm_disc_start(); }
  if (sm_nn_due && (int32_t)(now - sm_nn_due) >= 0 && nomadnet_destination) { sm_nn_due = now + sm_ann_ms(); nomadnet_destination.announce(RNS::Bytes(nomadnet_name)); NOTICE("[nomadnet] periodic announce"); }
  sm_disc_work();
}
