#include "Arduino.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include <WiFi.h>
#include <WiFiUdp.h>
#include "mbedtls/sha256.h"
#include "secrets.h"   // SSID, WIFIPASSWORD, SALT
#include "config.h"    // DEVICENAME

// ===================== CONFIG =====================
// Master ESP32's IP og UDP-port — find masterens IP i Serial Monitor ved boot
#define MASTER_IP    "192.168.0.243"   // <-- SKIFT TIL MASTERENS IP
#define MASTER_PORT  5006

// Topic-prefix bruges ikke længere — beholdt som kommentar til reference
// #define MQTT_TOPIC_PREFIX "/devices/device03/raw/"

// ===================== DEVICE IDENTITY =====================
String myName = "UNKNOWN";
float  myX    = 0.0;
float  myY    = 0.0;

void espId() {
  uint8_t mac[6];
  WiFi.macAddress(mac);
  Serial.printf("[BOOT] Min MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  for (int i = 0; i < 3; i++) {
    if (memcmp(mac, espMACs[i], 6) == 0) {
      myName = espNames[i];
      myX    = espPositions[i][0];
      myY    = espPositions[i][1];
      Serial.printf("[BOOT] %s på position (%.1f, %.1f)\n",
        myName.c_str(), myX, myY);
      return;
    }
  }
  Serial.println("[BOOT] ADVARSEL — MAC ikke genkendt i secrets.h!");
}



// ===================== MAC HASH =====================
void macToHash(const uint8_t* mac, char* outHex8) {
  uint8_t input[6 + 20];
  memcpy(input, mac, 6);
  memcpy(input + 6, SALT, strlen(SALT));
  uint8_t digest[32];
  mbedtls_sha256_ret(input, 6 + strlen(SALT), digest, 0);
  snprintf(outHex8, 9, "%02X%02X%02X%02X",
    digest[0], digest[1], digest[2], digest[3]);
}

// ===================== DETECTION QUEUE =====================
#define QUEUE_SIZE 32

typedef struct {
  uint8_t mac[6];
  int8_t  rssi;
} DetectionEvent;

static DetectionEvent eventQueue[QUEUE_SIZE];
static volatile int   queueHead = 0;
static volatile int   queueTail = 0;

static inline bool queueFull()  { return ((queueTail + 1) % QUEUE_SIZE) == queueHead; }
static inline bool queueEmpty() { return queueHead == queueTail; }

// ===================== THROTTLE =====================
#define THROTTLE_MS    500
#define THROTTLE_SLOTS 32

typedef struct { char hash[9]; unsigned long lastSent; } ThrottleEntry;
static ThrottleEntry throttleTable[THROTTLE_SLOTS];
static int           throttleCount = 0;

bool shouldSend(const char* hash) {
  unsigned long now = millis();
  for (int i = 0; i < throttleCount; i++) {
    if (strcmp(throttleTable[i].hash, hash) == 0) {
      if (now - throttleTable[i].lastSent < THROTTLE_MS) return false;
      throttleTable[i].lastSent = now;
      return true;
    }
  }
  if (throttleCount < THROTTLE_SLOTS) {
    strncpy(throttleTable[throttleCount].hash, hash, 9);
    throttleTable[throttleCount].lastSent = now;
    throttleCount++;
  }
  return true;
}

// ===================== TIMESTAMP =====================
String getTimestamp() {
  struct tm timeinfo;
  char buf[30] = "unknown";
  if (getLocalTime(&timeinfo))
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &timeinfo);
  return String(buf);
}

// ===================== UDP =====================
static WiFiUDP udp;

void sendUDP(const char* payload) {
  udp.beginPacket(MASTER_IP, MASTER_PORT);
  udp.write((const uint8_t*)payload, strlen(payload));
  udp.endPacket();
}

// ===================== IEEE80211 STRUCTS =====================
typedef struct {
  uint8_t frame_ctrl[2], duration[2], addr1[6], addr2[6], addr3[6], seq_ctrl[2];
} wifi_ieee80211_mac_hdr_t;
typedef struct { wifi_ieee80211_mac_hdr_t hdr; uint8_t payload[0]; } wifi_ieee80211_packet_t;

// ===================== SNIFFER CALLBACK =====================
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;
  wifi_promiscuous_pkt_t*   pkt  = (wifi_promiscuous_pkt_t*)buf;
  wifi_ieee80211_packet_t*  ipkt = (wifi_ieee80211_packet_t*)pkt->payload;
  uint8_t* mac = ipkt->hdr.addr2;
  if (mac[0] & 0x01) return;  // Broadcast
  if (mac[0] & 0x02) return;  // Randomiseret
  if (!queueFull()) {
    memcpy(eventQueue[queueTail].mac, mac, 6);
    eventQueue[queueTail].rssi = pkt->rx_ctrl.rssi;
    queueTail = (queueTail + 1) % QUEUE_SIZE;
  }
}

// ===================== WIFI =====================
void initWiFi() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(SSID, WIFIPASSWORD);
  Serial.print("[WIFI] Forbinder");
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(500); }
  Serial.println("\n[WIFI] Forbundet: " + WiFi.localIP().toString());
}

// ===================== SETUP =====================
void setup() {
  Serial.begin(115200);
  delay(200);
  Serial.println("========================================");
  Serial.println("[BOOT] " + String(DEVICENAME) + " starter");
  Serial.println("========================================");

  initWiFi();
  udp.begin(WiFi.localIP(), 0);

  espId();

  configTime(0, 0, "pool.ntp.org");
  setenv("TZ", "CET-1CEST,M3.5.0,M10.5.0/3", 1);
  tzset();
  delay(1500);
  Serial.println("[NTP] Tid synkroniseret");

  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  Serial.println("[SNIFFER] Kørende");
  Serial.printf("[UDP] Sender til %s:%d\n", MASTER_IP, MASTER_PORT);
  Serial.println("========================================");
}

// ===================== LOOP =====================
void loop() {
  // Drain queue
  while (!queueEmpty()) {
    DetectionEvent evt = eventQueue[queueHead];
    queueHead = (queueHead + 1) % QUEUE_SIZE;

    char macHash[9];
    macToHash(evt.mac, macHash);
    if (!shouldSend(macHash)) continue;

    Serial.printf("[SNIFFER] Hash: %s  RSSI: %d dBm\n", macHash, evt.rssi);

    char payload[192];
    snprintf(payload, sizeof(payload),
      "{\"slave\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"macHash\":\"%s\",\"rssi\":%d,\"ts\":\"%s\"}",
      myName.c_str(), myX, myY,
      macHash, evt.rssi, getTimestamp().c_str());

    sendUDP(payload);
  }

  // Channel hopping — kanal 1, 6, 11
  static const uint8_t channels[] = {1, 6, 11};
  static uint8_t       channelIdx = 0;
  static unsigned long lastHop    = 0;

  if (millis() - lastHop > 150) {
    channelIdx = (channelIdx + 1) % 3;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(channels[channelIdx], WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    lastHop = millis();
  }
}
