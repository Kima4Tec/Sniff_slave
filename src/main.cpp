#include "Arduino.h"
#include "esp_wifi.h"
#include "esp_now.h"
#include <WiFi.h>
#include "secrets.h"
#include "mbedtls/sha256.h"

// ===================== ESP-NOW PAKKE =====================
typedef struct {
  char  nodeName[16];
  char  deviceName[16];
  int8_t rssi;
  float  distance;
} EspNowPayload;

// ===================== DETECTION QUEUE =====================
#define QUEUE_SIZE 16

typedef struct {
  char    anonId[65];
  int8_t  rssi;
  float   distance;
  bool    isKnown;
  int     knownIndex;
} DetectionEvent;

static DetectionEvent eventQueue[QUEUE_SIZE];
static volatile int   queueHead = 0;
static volatile int   queueTail = 0;

static inline bool queueFull()  { return ((queueTail + 1) % QUEUE_SIZE) == queueHead; }
static inline bool queueEmpty() { return queueHead == queueTail; }

static inline void enqueueEvent(const char* anonId, int8_t rssi, float distance, bool isKnown, int knownIndex) {
  if (!queueFull()) {
    strncpy(eventQueue[queueTail].anonId, anonId, 65);
    eventQueue[queueTail].rssi       = rssi;
    eventQueue[queueTail].distance   = distance;
    eventQueue[queueTail].isKnown    = isKnown;
    eventQueue[queueTail].knownIndex = knownIndex;
    queueTail = (queueTail + 1) % QUEUE_SIZE;
  }
}

static bool dequeueEvent(DetectionEvent* out) {
  if (queueEmpty()) return false;
  *out = eventQueue[queueHead];
  queueHead = (queueHead + 1) % QUEUE_SIZE;
  return true;
}

// ===================== DEVICE IDENTITY =====================
String myName = "UNKNOWN";
float  myX    = 0.0;
float  myY    = 0.0;

// ===================== HASH MAC =====================
void hashMAC(uint8_t* mac, char* output) {
  byte hash[32];
  mbedtls_sha256_ret(mac, 6, hash, 0);
  for (int i = 0; i < 32; i++) {
    sprintf(output + i * 2, "%02x", hash[i]);
  }
  output[64] = '\0';
}

// ===================== AFSTAND FRA RSSI =====================
float calculateDistance(int rssi, int txPower = -59, float n = 2.5) {
  return pow(10.0, (txPower - rssi) / (10.0 * n));
}

// ===================== DEVICE ID =====================
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
      Serial.printf("[BOOT] %s på position (%.1f, %.1f)\n", myName.c_str(), myX, myY);
      return;
    }
  }
  Serial.println("[BOOT] ADVARSEL — MAC ikke genkendt i secrets.h!");
}

// ===================== SNIFFER CALLBACK =====================
void IRAM_ATTR snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

  wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;

  typedef struct {
    uint8_t frame_ctrl[2];
    uint8_t duration[2];
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
    uint8_t seq_ctrl[2];
  } hdr_t;

  hdr_t* hdr = (hdr_t*)pkt->payload;
  uint8_t* mac = hdr->addr2;
  if (mac[0] & 0x01) return;

  int8_t rssi    = pkt->rx_ctrl.rssi;
  float distance = calculateDistance(rssi);

  bool isKnown   = false;
  int knownIndex = -1;
  for (int i = 0; i < knownMACCount; i++) {
    if (memcmp(mac, knownMACs[i], 6) == 0) {
      isKnown    = true;
      knownIndex = i;
      break;
    }
  }

  char anonId[65];
  hashMAC(mac, anonId);
  enqueueEvent(anonId, rssi, distance, isKnown, knownIndex);
}

// ===================== SETUP =====================
void setup() {
  Serial.begin(115200);
  delay(200);

  Serial.println("========================================");
  Serial.println("[BOOT] SLAVE starter");
  Serial.println("========================================");

  // WiFi i station-mode uden at forbinde — kræves til ESP-NOW
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  espId();

  // Init ESP-NOW
  if (esp_now_init() != ESP_OK) {
    Serial.println("[ESP-NOW] Init fejlede!");
    return;
  }

  // Tilføj master som peer
  esp_now_peer_info_t peer = {};
  memcpy(peer.peer_addr, masterMAC, 6);
  peer.channel = 0;
  peer.encrypt = false;
  esp_now_add_peer(&peer);

  Serial.printf("[ESP-NOW] Master: %02X:%02X:%02X:%02X:%02X:%02X\n",
    masterMAC[0], masterMAC[1], masterMAC[2],
    masterMAC[3], masterMAC[4], masterMAC[5]);

  // Start sniffer
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&snifferCallback);
  esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);

  Serial.println("[SNIFFER] Kørende");
  Serial.println("========================================");
}

// ===================== LOOP =====================
void loop() {
  DetectionEvent evt;
  while (dequeueEvent(&evt)) {
    Serial.printf("[SNIFFER] %s — RSSI: %d dBm  ~%.1f m%s\n",
      evt.anonId, evt.rssi, evt.distance,
      evt.isKnown ? "  *** KNOWN ***" : ""
    );

    if (evt.isKnown) {
      EspNowPayload pkt;
      strncpy(pkt.nodeName,   myName.c_str(),              16);
      strncpy(pkt.deviceName, knownNames[evt.knownIndex],  16);
      pkt.rssi     = evt.rssi;
      pkt.distance = evt.distance;

      esp_err_t result = esp_now_send(masterMAC, (uint8_t*)&pkt, sizeof(pkt));
      Serial.printf("[ESP-NOW] Sendt til master: %s\n",
        result == ESP_OK ? "OK" : "FEJL");
    }
  }

  // Channel hopping
  static uint8_t       channel = 1;
  static unsigned long lastHop = 0;
  if (millis() - lastHop > 1000) {
    channel = (channel % 13) + 1;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    lastHop = millis();
  }
}
