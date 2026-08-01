// DID-auth firmware verification example for ESP32.
//
// Flow:
//   1. Device boots in AP mode ("ESP32-VC-Uploader") and serves a small upload
//      form so an operator can push a verifiable credential (vc.json).
//   2. Once a VC is present, the device joins the configured Wi-Fi network.
//   3. The device rebuilds a verifiable presentation (VP) from the VC's
//      selectively-disclosed claims (Merkle proof over deviceModel /
//      firmwareHash / firmwareVersion) and POSTs it to the gateway's
//      /vp/verify endpoint.
//   4. Locally, the device hashes its own firmware image and compares it
//      against the hash asserted in the credential.
//
// Tested against arduino-esp32 core 3.x (ESP-IDF 5.x) and the library
// versions pinned in platformio.ini.

#include <WiFi.h>
#include <AsyncTCP.h>
#include <ESPAsyncWebServer.h>
#include <FS.h>
#include <SPIFFS.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include "mbedtls/sha256.h"
#include <vector>
#include <algorithm>

// Set to 1 to verify the VC's Ed25519 signature on-device (requires an
// OpenSSL-compatible crypto backend; not available on stock arduino-esp32).
#define VERIFY_SIGNATURE 0
// Set to 1 when the device DID's key lives in a secure element.
#define USE_SECURE_ELEMENT 0

#if VERIFY_SIGNATURE
#include <openssl/evp.h>
#include <openssl/pem.h>
#endif

#if USE_SECURE_ELEMENT
const char deviceDID[] PROGMEM = R"did({"@context":["https://www.w3.org/ns/did/v1"],"id":"did:local:esp32-device","verificationMethod":[{"id":"did:local:esp32-device#key-1","type":"Ed25519VerificationKey2020","controller":"did:local:esp32-device","publicKeyPem":"YOUR PUBLIC KEY HERE","secureElement":true}]})did";
#else
const char deviceDID[] PROGMEM = R"did({"@context":["https://www.w3.org/ns/did/v1"],"id":"did:local:esp32-device","verificationMethod":[{"id":"did:local:esp32-device#key-1","type":"Ed25519VerificationKey2020","controller":"did:local:esp32-device","publicKeyPem":"YOUR PUBLIC KEY HERE","secureElement":false}]})did";
#endif

const char* apSSID = "ESP32-VC-Uploader";
const char* apPassword = "12345678";

const char* staSSID = "<<HOME WIFI SSID>>";
const char* staPassword = "<<HOME WIFI PASSWORD>>";

const char* verificationURL = "http://192.168.68.61:8000/vp/verify";
const char* firmwareFile = "/firmware.bin";

AsyncWebServer server(80);
bool onWiFi = false;

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

bool verifyFirmwareFile(const char* path, const char* expected) {
  if (!SPIFFS.exists(path)) {
    Serial.println("[FW] File not found");
    return false;
  }
  File fw = SPIFFS.open(path, FILE_READ);
  if (!fw) {
    Serial.println("[FW] Failed to open file");
    return false;
  }
  mbedtls_sha256_context ctx;
  mbedtls_sha256_init(&ctx);
  mbedtls_sha256_starts(&ctx, 0);
  uint8_t buf[512];
  while (fw.available()) {
    size_t len = fw.read(buf, sizeof(buf));
    mbedtls_sha256_update(&ctx, buf, len);
  }
  uint8_t out[32];
  mbedtls_sha256_finish(&ctx, out);
  mbedtls_sha256_free(&ctx);
  fw.close();
  char hex[65];
  for (int i = 0; i < 32; ++i) sprintf(hex + i * 2, "%02x", out[i]);
  bool ok = strcmp(hex, expected) == 0;
  Serial.println(ok ? "[FW] Hash match" : "[FW] Hash mismatch");
  return ok;
}

String sha256Hex(const String &data) {
  uint8_t out[32];
  mbedtls_sha256((const unsigned char*)data.c_str(), data.length(), out, 0);
  char hex[65];
  for (int i = 0; i < 32; ++i) sprintf(hex + i * 2, "%02x", out[i]);
  hex[64] = 0;
  return String(hex);
}

// ---------------------------------------------------------------------------
// Optional on-device signature verification (VERIFY_SIGNATURE == 1)
// ---------------------------------------------------------------------------

#if VERIFY_SIGNATURE
const char* issuerPubKeyPem = "-----BEGIN PUBLIC KEY-----\nYOUR PUBLIC KEY HERE\n-----END PUBLIC KEY-----\n";

int b64Index(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

size_t decodeBase64(const char* src, size_t len, uint8_t* out) {
  int val = 0, valb = -8;
  size_t outLen = 0;
  for (size_t i = 0; i < len; i++) {
    int d = b64Index(src[i]);
    if (d == -1) {
      if (src[i] == '=') break;
      continue;
    }
    val = (val << 6) + d;
    valb += 6;
    if (valb >= 0) {
      out[outLen++] = (val >> valb) & 0xFF;
      valb -= 8;
    }
  }
  return outLen;
}

size_t decodeBase64Url(const char* src, uint8_t* out) {
  String s = String(src);
  s.replace('-', '+');
  s.replace('_', '/');
  while (s.length() % 4 != 0) s += '=';
  return decodeBase64(s.c_str(), s.length(), out);
}

void canonicalize(JsonVariant v, String& out) {
  if (v.is<JsonObject>()) {
    JsonObject obj = v.as<JsonObject>();
    std::vector<String> keys;
    for (JsonPair kv : obj) keys.push_back(String(kv.key().c_str()));
    std::sort(keys.begin(), keys.end());
    out += '{';
    bool first = true;
    for (String& k : keys) {
      if (!first) out += ',';
      first = false;
      out += '"' + k + "\":";
      canonicalize(obj[k], out);
    }
    out += '}';
  } else if (v.is<JsonArray>()) {
    JsonArray arr = v.as<JsonArray>();
    out += '[';
    for (size_t i = 0; i < arr.size(); i++) {
      if (i) out += ',';
      canonicalize(arr[i], out);
    }
    out += ']';
  } else if (v.is<const char*>()) {
    out += '"';
    out += v.as<const char*>();
    out += '"';
  } else {
    out += v.as<String>();
  }
}

bool verifySignature(const JsonDocument& doc) {
  if (doc["proof"].isNull()) {
    Serial.println("[SIG] Missing proof");
    return false;
  }
  const char* sigB64 = doc["proof"]["jws"] | "";
  JsonDocument tmp;
  tmp.set(doc);
  tmp.remove("proof");
  String canonical;
  canonicalize(tmp.as<JsonVariant>(), canonical);

  uint8_t sig[64];
  size_t sigLen = decodeBase64Url(sigB64, sig);
  if (sigLen != 64) return false;

  BIO* bio = BIO_new_mem_buf((void*)issuerPubKeyPem, -1);
  EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
  BIO_free(bio);
  if (!pkey) return false;

  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  if (!ctx) { EVP_PKEY_free(pkey); return false; }
  bool ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
            EVP_DigestVerify(ctx, sig, sigLen,
                              (const uint8_t*)canonical.c_str(),
                              canonical.length()) == 1;
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pkey);
  return ok;
}
#endif

// ---------------------------------------------------------------------------
// Web UI (AP mode credential upload)
// ---------------------------------------------------------------------------

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE html><html><head><title>Upload VC</title></head><body>
<h2>Upload Verifiable Credential</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
  <input type="file" name="vc">
  <input type="submit" value="Upload">
</form>
</body></html>
)rawliteral";

void handleUpload(AsyncWebServerRequest *request, String filename, size_t index, uint8_t *data, size_t len, bool final) {
  static File file;
  if (index == 0) {
    Serial.printf("[UPLOAD] Start: %s\n", filename.c_str());
    file = SPIFFS.open("/vc.json", FILE_WRITE);
  }
  if (file) {
    file.write(data, len);
  }
  if (final) {
    Serial.printf("[UPLOAD] Done: %s (%u bytes)\n", filename.c_str(), (index + len));
    file.close();
  }
}

// ---------------------------------------------------------------------------
// Credential verification: rebuild a VP with Merkle-disclosed claims and
// POST it to the gateway, then check the local firmware hash.
// ---------------------------------------------------------------------------

void verifyVC() {
  File file = SPIFFS.open("/vc.json", FILE_READ);
  if (!file) {
    Serial.println("[ERROR] Failed to open VC file");
    return;
  }

  String raw = file.readString();
  file.close();

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, raw);
  if (err) {
    Serial.println("[ERROR] JSON parse failed");
    return;
  }

  JsonObject vcObj = doc["vc"].as<JsonObject>();
  if (vcObj.isNull()) {
    Serial.println("[ERROR] 'vc' field not found");
    return;
  }
  String vcOnly;
  serializeJson(vcObj, vcOnly);

  JsonObject claims = doc["proof_data"]["claims"].as<JsonObject>();
  JsonObject salts = doc["proof_data"]["salts"].as<JsonObject>();
  const char* fwHash = claims["firmwareHash"] | "";
  const char* fwSalt = salts["firmwareHash"] | "";
  const char* fwVer = claims["firmwareVersion"] | "";
  const char* fwVerSalt = salts["firmwareVersion"] | "";
  const char* devModel = claims["deviceModel"] | "";
  const char* devSalt = salts["deviceModel"] | "";

#if VERIFY_SIGNATURE
  JsonDocument vcDoc;
  DeserializationError err2 = deserializeJson(vcDoc, vcOnly);
  if (!err2 && verifySignature(vcDoc)) {
    Serial.println("[SIG] Signature valid");
  } else {
    Serial.println("[SIG] Signature invalid");
  }
#endif

  // Rebuild the Merkle proof for the firmwareHash leaf (index 1) so the
  // gateway can check it against the VC's commitmentRoot without the
  // device disclosing deviceModel/firmwareVersion.
  String keys[3] = {"deviceModel", "firmwareHash", "firmwareVersion"};
  String values[3] = {devModel, fwHash, fwVer};
  String saltArr[3] = {devSalt, fwSalt, fwVerSalt};
  String leaves[3];
  for (int i = 0; i < 3; ++i) {
    leaves[i] = sha256Hex(keys[i] + ":" + values[i] + ":" + saltArr[i]);
  }
  std::vector<String> level(leaves, leaves + 3);
  std::vector<String> proof;
  int idx = 1;  // firmwareHash index
  while (level.size() > 1) {
    if (level.size() % 2 == 1) level.push_back(level.back());
    std::vector<String> next;
    for (size_t i = 0; i < level.size(); i += 2) {
      String a = level[i];
      String b = level[i + 1];
      if (i == (size_t)idx || i + 1 == (size_t)idx) {
        String sibling = (i == (size_t)idx) ? b : a;
        proof.push_back(sibling);
        idx = next.size();
      }
      String combined = (a < b) ? a + b : b + a;
      next.push_back(sha256Hex(combined));
    }
    level = next;
  }

  JsonDocument vpDoc;
  JsonObject vp = vpDoc["vp"].to<JsonObject>();
  JsonArray ctx = vp["@context"].to<JsonArray>();
  ctx.add("https://www.w3.org/ns/credentials/v2");
  JsonArray typ = vp["type"].to<JsonArray>();
  typ.add("VerifiablePresentation");
  vp["holder"] = "did:local:esp32-device";
  JsonArray vcArr = vp["verifiableCredential"].to<JsonArray>();
  vcArr.add(vcObj);
  JsonArray discArr = vpDoc["disclosures"].to<JsonArray>();
  JsonObject d = discArr.add<JsonObject>();
  JsonObject claimObj = d["claim"].to<JsonObject>();
  claimObj["firmwareHash"] = fwHash;
  d["salt"] = fwSalt;
  JsonArray proofArr = d["merkleProof"].to<JsonArray>();
  for (String &p : proof) proofArr.add(p);

  String vpPayload;
  serializeJson(vpDoc, vpPayload);

  Serial.println("[DEBUG] VP Payload:");
  Serial.println(vpPayload);

  HTTPClient http;
  http.begin(verificationURL);
  http.addHeader("Content-Type", "application/json");

  int httpCode = http.POST(vpPayload);
  Serial.printf("[VERIFY] HTTP Status: %d\n", httpCode);

  if (httpCode > 0) {
    String response = http.getString();
    Serial.println("[VERIFY] Response: " + response);
  } else {
    Serial.println("[VERIFY] Error: " + http.errorToString(httpCode));
  }

  http.end();

  verifyFirmwareFile(firmwareFile, fwHash);
}

// ---------------------------------------------------------------------------
// Setup / main loop
// ---------------------------------------------------------------------------

void setup() {
  Serial.begin(115200);
  if (!SPIFFS.begin(true)) {
    Serial.println("SPIFFS mount failed");
    return;
  }

  WiFi.softAP(apSSID, apPassword);
  Serial.println("[AP MODE] Connect to: " + String(apSSID));
  Serial.println("IP address: " + WiFi.softAPIP().toString());

  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request){
    request->send_P(200, "text/html", index_html);
  });

  server.on("/upload", HTTP_POST, [](AsyncWebServerRequest *request){
    request->send(200, "text/plain", "File uploaded. Rebooting...");
    delay(2000);
    ESP.restart();
  }, handleUpload);

  server.on("/delete", HTTP_GET, [](AsyncWebServerRequest *request){
    if (!onWiFi) {
      request->send(403, "text/plain", "Not allowed in AP mode");
      return;
    }
    if (SPIFFS.exists("/vc.json")) {
      SPIFFS.remove("/vc.json");
      request->send(200, "text/plain", "VC deleted. Restarting...");
      delay(2000);
      ESP.restart();
    } else {
      request->send(404, "text/plain", "No VC file found");
    }
  });

  server.begin();
}

void loop() {
  if (SPIFFS.exists("/vc.json") && !onWiFi) {
    delay(5000);
    WiFi.disconnect();

    Serial.println("\n[INFO] Found /vc.json. Connecting to WiFi...");
    WiFi.mode(WIFI_STA);
    WiFi.begin(staSSID, staPassword);

    int retries = 0;
    while (WiFi.status() != WL_CONNECTED && retries < 20) {
      delay(500);
      Serial.print(".");
      retries++;
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.println("\n[CONNECTED] IP: " + WiFi.localIP().toString());
      onWiFi = true;
      verifyVC();
      Serial.println("[INFO] You can delete the VC via: http://" + WiFi.localIP().toString() + "/delete");
    } else {
      Serial.println("\n[ERROR] Failed to connect to WiFi.");
    }
  }

  delay(1000);
}
