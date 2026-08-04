// Tests whether the 2.4GHz radio hardware works at all, via WiFi scanning
// (a separate stack from BLE, but the same underlying radio/crystal).
// No reliance on serial output -- result is shown entirely via the LED,
// since serial reading has been unreliable in this environment all session.
//
// LED behavior:
//   - 3 quick blinks immediately after boot: sketch is running at all.
//   - Then: LED SOLID ON for 10 seconds if WiFi scan found 1+ networks (radio works).
//   - LED OFF entirely (after the 3 blinks) if scan found 0 networks or WiFi failed to init.
//   - Then repeats forever so it's easy to observe over multiple cycles.

#include <WiFi.h>

#define LED_PIN 2

void blink(int count, int ms);

void blink(int count, int ms) {
    for (int i = 0; i < count; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(ms);
        digitalWrite(LED_PIN, LOW);
        delay(ms);
    }
}

void setup() {
    pinMode(LED_PIN, OUTPUT);
}

void loop() {
    // 3 quick blinks: proves the app is running this loop iteration at all.
    blink(3, 150);
    delay(500);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();
    delay(100);

    int networksFound = WiFi.scanNetworks();

    if (networksFound > 0) {
        // Radio works: solid ON for 10 seconds.
        digitalWrite(LED_PIN, HIGH);
        delay(10000);
        digitalWrite(LED_PIN, LOW);
    } else {
        // Radio scan found nothing / failed: stay off, distinctly different from solid-on.
        digitalWrite(LED_PIN, LOW);
        delay(10000);
    }

    delay(2000);
}
