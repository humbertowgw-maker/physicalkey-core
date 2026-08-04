// Absolute minimal test: completely empty setup()/loop(), nothing else.
// If this crashes too, the problem is in the Arduino core's own startup
// sequence, not in anything about our code, BLE, or Serial.
void setup() {
}

void loop() {
    delay(1000);
}
