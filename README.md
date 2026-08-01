# MAVLink AES-128-CTR Encryption — How to Run the Test

This repo has AES-128 (CTR mode) payload encryption built directly into the
MAVLink C library. `main.c` is a self-contained test that **proves** the
encryption is working end-to-end.

---

## What's integrated

| File | Change |
|------|--------|
| `aes.h` (repo root) | The tiny-AES-C library (AES-128-CTR). Copied from `AES/aes.h`. |
| `mavlink_helpers.h` | `#include "aes.h"`, `#define ENCRYPTION`, and encrypt/decrypt hooks. |
| `main.c` | Roundtrip test that packs → encrypts → serializes → parses → decrypts → verifies. |

Encryption is transparent: when `#define ENCRYPTION` is set (it is, in
`mavlink_helpers.h`), every message with `msgid != 0` has its payload encrypted
on send and decrypted on receive automatically. `HEARTBEAT` (msgid 0) stays in
cleartext by design.

---

## How to run

### Option A — Direct compile (no CMake needed) ✅ recommended

`cmake` is **not installed** on this machine, so the simplest path is to compile
`main.c` directly with the C compiler. From the repo root:

```sh
cc -std=c99 -I. -Wall -o mavlink_test main.c
./mavlink_test
```

- `-I.` tells the compiler to look in the current folder for headers
  (so `#include "aes.h"` and `#include "common/mavlink.h"` resolve).
- The binary `mavlink_test` is git-ignored, so you won't accidentally commit it.

### Option B — CMake (e.g. from CLion, or after `brew install cmake`)

The repo already has a `CMakeLists.txt` with a `mavlink_test` target.

From a terminal:
```sh
brew install cmake          # only once, if cmake is missing
cmake -S . -B build
cmake --build build
./build/mavlink_test
```

From **CLion**: just open the project and click **Run** ▶ on the
`mavlink_test` target (CLion ships its own bundled CMake, so no install needed).

---

## What you should see

```
========== MAVLINK AES-128-CTR ENCRYPTION TEST ==========

[TX] msgid=30 len=28
[TX] payload on the wire (ciphertext): D5 BC DF 73 55 AC B0 8D ...
[TX] expected plaintext head (LE 12345): 39 30 00 00
[TX] PROOF 1 OK: on-wire payload differs from plaintext -> encrypted.
[TX] PROOF 2 OK: independent AES-CTR decrypt recovers the plaintext.
[TX] serialized frame length: 40 bytes

[RX] parsing serialized byte stream...
[RX] frame OK, msgid=30 len=28
[RX] payload after parser decrypt: 39 30 00 00 CD CC CC 3D ...
[RX] PROOF 3 OK: decoded time_boot_ms=12345 roll=0.10 pitch=-0.20 yaw=1.57

==================== ENCRYPTION ROUNDTRIP OK ====================
```

If it ends with `ENCRYPTION ROUNDTRIP OK` and exit code `0`, encryption works.

### What each proof means

1. **PROOF 1 — it's actually encrypted.** After packing an `ATTITUDE` message
   with `time_boot_ms = 12345`, the payload bytes on the wire do **not** match
   the plaintext (`39 30 00 00` = 12345 little-endian). They're ciphertext.
2. **PROOF 2 — the key is correct.** Independently decrypting those wire bytes
   with the shared key/IV recovers the original plaintext.
3. **PROOF 3 — full roundtrip.** Feeding the serialized frame through the normal
   MAVLink parser (`mavlink_frame_char`) auto-decrypts the payload, and the
   decoded fields exactly match what was sent. Notice the RX payload starts with
   `39 30 00 00` again — the parser decrypted it back to plaintext.

The test uses `assert()`, so if any proof fails the program aborts with a
message pointing at what broke.

---

## Proving the test isn't lying (optional sanity check)

Want to confirm the encryption path is what's doing the work? Temporarily turn
it off and watch **PROOF 1 fail**:

1. In `mavlink_helpers.h`, comment out the line:
   ```c
   #define ENCRYPTION
   ```
2. Recompile and run:
   ```sh
   cc -std=c99 -I. -o mavlink_test main.c && ./mavlink_test
   ```
3. It will now abort at PROOF 1 (`payload matches plaintext -> encryption did
   NOT run`), because the payload is sent in cleartext.
4. **Restore** the `#define ENCRYPTION` line afterwards.

---

## Key / IV

Both sides share a hardcoded AES-128 key and IV (defined in the encrypt/decrypt
hooks in `mavlink_helpers.h`):

```
key = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
iv  = f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff
```

> ⚠️ **Known limitation (accepted for now):** the IV is fixed for every message.
> In CTR mode, reusing the same key+IV across messages lets an attacker recover
> the XOR of two plaintexts. This is fine for a functional proof-of-concept and
> matches the reference project, but it is **not** strong crypto. A future
> improvement is to derive a per-message IV from the sequence number + sysid.

When you later split this into separate **GCS** and **drone** projects, both
must use the **same `aes.h`, the same hooks, and the identical key/IV**.
