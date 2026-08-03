// Proves that the exact Ed25519 implementation the ESP32 firmware will use
// (Rhys Weatherley's arduinolibs "Crypto" library, github.com/OperatorFoundation/Crypto or
// rweather/arduinolibs) produces keys and signatures the PhysicalKey backend actually
// accepts — compiled and run natively here since there's no ESP32 board attached to test
// on physically. Ed25519::sign/derivePublicKey are pure math with no hardware dependency,
// so this is a real, meaningful test of the same code path the firmware runs, not a
// reimplementation.
#include <Ed25519.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

static std::string toBase64(const uint8_t *data, size_t len) {
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8) | data[i + 2];
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += table[n & 0x3F];
        i += 3;
    }
    size_t rem = len - i;
    if (rem == 1) {
        uint32_t n = data[i] << 16;
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += "==";
    } else if (rem == 2) {
        uint32_t n = (data[i] << 16) | (data[i + 1] << 8);
        out += table[(n >> 18) & 0x3F];
        out += table[(n >> 12) & 0x3F];
        out += table[(n >> 6) & 0x3F];
        out += "=";
    }
    return out;
}

// Ed25519 SubjectPublicKeyInfo DER has no algorithm parameters, so this 12-byte prefix is
// fixed and identical for every Ed25519 key. Confirmed against backend/scripts/keygen.js's
// output and already verified end-to-end in mobile/ios-crypto-poc.
static const uint8_t ed25519SPKIPrefix[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <genkey|sign> [args...]\n", argv[0]);
        return 1;
    }
    std::string cmd = argv[1];

    if (cmd == "genkey") {
        // Real random bytes from the OS, not Ed25519::generatePrivateKey() — that call
        // goes through the library's RNG class, which expects hardware noise sources to
        // be registered (real entropy gathering on the actual board). derivePublicKey()
        // and sign() below are pure deterministic math with no such dependency, so this
        // still tests the real signing code path; only the *source* of the random private
        // key bytes differs from what generatePrivateKey() would do on real hardware.
        uint8_t privateKey[32];
        FILE *f = fopen("/dev/urandom", "rb");
        fread(privateKey, 1, 32, f);
        fclose(f);

        uint8_t publicKey[32];
        Ed25519::derivePublicKey(publicKey, privateKey);

        uint8_t der[44];
        memcpy(der, ed25519SPKIPrefix, 12);
        memcpy(der + 12, publicKey, 32);

        printf("PRIVATE_HEX=");
        for (int i = 0; i < 32; i++) printf("%02x", privateKey[i]);
        printf("\n");
        printf("PUBLIC_SPKI_B64=%s\n", toBase64(der, 44).c_str());
        return 0;
    }

    if (cmd == "sign") {
        if (argc < 4) {
            fprintf(stderr, "Usage: %s sign <privateKeyHex> <message>\n", argv[0]);
            return 1;
        }
        std::string hex = argv[2];
        std::string message = argv[3];

        uint8_t privateKey[32];
        for (int i = 0; i < 32; i++) {
            sscanf(hex.c_str() + i * 2, "%2hhx", &privateKey[i]);
        }

        uint8_t publicKey[32];
        Ed25519::derivePublicKey(publicKey, privateKey);

        uint8_t signature[64];
        Ed25519::sign(signature, privateKey, publicKey, message.data(), message.size());

        printf("SIGNATURE_B64=%s\n", toBase64(signature, 64).c_str());
        return 0;
    }

    fprintf(stderr, "Unknown command: %s\n", cmd.c_str());
    return 1;
}
