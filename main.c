#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

// 1. Handle status buffers externally (parity with the reference project setup)
#define MAVLINK_EXTERNAL_RX_STATUS 1

// 2. Instantiate the status array FIRST so the headers can see it when they load
#include "mavlink_types.h"
mavlink_status_t m_mavlink_status[MAVLINK_COMM_NUM_BUFFERS];

// 3. NOW include the main dialect parsing engine (which pulls in mavlink_helpers.h + aes.h)
#include "common/mavlink.h"

// Same hardcoded AES-128 key/IV compiled into mavlink_helpers.h. Used here ONLY
// to independently verify that the bytes on the wire are genuine ciphertext.
static const uint8_t g_key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
static const uint8_t g_iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

static void hexdump(const char *label, const uint8_t *p, uint8_t n) {
    printf("%s", label);
    for (uint8_t i = 0; i < n; i++) printf("%02X ", p[i]);
    printf("\n");
}

int main(void) {
    printf("========== MAVLINK AES-128-CTR ENCRYPTION TEST ==========\n");

    // ---- Known plaintext field values we will pack into an ATTITUDE message ----
    const uint32_t in_time_boot_ms = 12345;   // 0x00003039
    const float in_roll = 0.10f, in_pitch = -0.20f, in_yaw = 1.57f;
    const float in_rollspeed = 0.01f, in_pitchspeed = 0.02f, in_yawspeed = 0.03f;

    // Reconstruct the expected plaintext of the first 4 payload bytes (little-endian time_boot_ms).
    uint8_t expected_plain_head[4];
    memcpy(expected_plain_head, &in_time_boot_ms, 4);

    // ---- TRANSMITTER: pack (pack -> finalize -> encrypts payload IN PLACE) ----
    mavlink_message_t tx_msg;
    mavlink_msg_attitude_pack(1, 1, &tx_msg,
                              in_time_boot_ms, in_roll, in_pitch, in_yaw,
                              in_rollspeed, in_pitchspeed, in_yawspeed);

    uint8_t *tx_payload = (uint8_t *)_MAV_PAYLOAD_NON_CONST(&tx_msg);
    printf("\n[TX] msgid=%u len=%u\n", tx_msg.msgid, tx_msg.len);
    hexdump("[TX] payload on the wire (ciphertext): ", tx_payload, tx_msg.len);
    hexdump("[TX] expected plaintext head (LE 12345): ", expected_plain_head, 4);

    // PROOF 1: the packed payload must NOT match the plaintext (i.e. it is encrypted).
    assert(memcmp(tx_payload, expected_plain_head, 4) != 0 &&
           "payload matches plaintext -> encryption did NOT run (is ENCRYPTION defined?)");
    printf("[TX] PROOF 1 OK: on-wire payload differs from plaintext -> encrypted.\n");

    // PROOF 2: decrypting a copy with the shared key/IV must recover the plaintext.
    uint8_t decrypted_copy[MAVLINK_MAX_PAYLOAD_LEN];
    memcpy(decrypted_copy, tx_payload, tx_msg.len);
    {
        struct AES_ctx ctx;
        AES_init_ctx_iv(&ctx, g_key, g_iv);
        AES_CTR_xcrypt_buffer(&ctx, decrypted_copy, tx_msg.len);
    }
    assert(memcmp(decrypted_copy, expected_plain_head, 4) == 0 &&
           "independent AES decrypt did not recover plaintext -> key/IV mismatch");
    printf("[TX] PROOF 2 OK: independent AES-CTR decrypt recovers the plaintext.\n");

    // Serialize the (encrypted) frame down to raw bytes for the "radio link".
    uint8_t buffer[MAVLINK_MAX_PACKET_LEN];
    uint16_t packet_len = mavlink_msg_to_send_buffer(buffer, &tx_msg);
    printf("[TX] serialized frame length: %u bytes\n", packet_len);

    // ---- RECEIVER: feed bytes through the parser (frame_char -> decrypts on FRAMING_OK) ----
    mavlink_message_t rx_msg;
    mavlink_status_t rx_status;
    int got_frame = 0;

    printf("\n[RX] parsing serialized byte stream...\n");
    for (uint16_t i = 0; i < packet_len; i++) {
        uint8_t res = mavlink_frame_char(MAVLINK_COMM_0, buffer[i], &rx_msg, &rx_status);
        if (res == MAVLINK_FRAMING_OK) {
            got_frame = 1;
            printf("[RX] frame OK, msgid=%u len=%u\n", rx_msg.msgid, rx_msg.len);
            hexdump("[RX] payload after parser decrypt: ", (uint8_t *)_MAV_PAYLOAD_NON_CONST(&rx_msg), rx_msg.len);

            mavlink_attitude_t att;
            mavlink_msg_attitude_decode(&rx_msg, &att);

            // PROOF 3: decoded fields match what we packed -> encrypt/decrypt roundtrip works.
            assert(att.time_boot_ms == in_time_boot_ms);
            assert(att.roll == in_roll && att.pitch == in_pitch && att.yaw == in_yaw);
            assert(att.rollspeed == in_rollspeed && att.pitchspeed == in_pitchspeed && att.yawspeed == in_yawspeed);
            printf("[RX] PROOF 3 OK: decoded time_boot_ms=%u roll=%.2f pitch=%.2f yaw=%.2f\n",
                   att.time_boot_ms, att.roll, att.pitch, att.yaw);
        } else if (res == MAVLINK_FRAMING_BAD_CRC) {
            printf("[RX] BAD CRC at byte %u\n", i);
        }
    }

    assert(got_frame && "receiver never completed a frame");

    printf("\n==================== ENCRYPTION ROUNDTRIP OK ====================\n");
    return 0;
}
