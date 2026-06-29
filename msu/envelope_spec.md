# MSU CryptoLib Standalone Envelope

This is a small binary response envelope used by the standalone CryptoLib tools for TC apply/process responses and status messages.

It is intentionally simple: a fixed header followed by the original input bytes and, when available, output bytes.

## Version 1

All multi-byte integer fields are unsigned big-endian.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `MSUC` (`0x4d 0x53 0x55 0x43`) |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `header_len` | `28` |
| 6 | 2 | `kind` | Envelope kind enum. `1` means security response. `2` means status message. `3` means anti-replay counter set request. `4` means anti-replay enforcement set request. |
| 8 | 4 | `payload_len` | Number of bytes after the header |
| 12 | 8 | `status` | For kind `1`: NUL-padded ASCII `SUCCESS` or `FAIL`. For kinds `2`, `3`, and `4`: zero-filled. |
| 20 | 4 | `crypto_status` | For kind `1`: CryptoLib status as signed int32, encoded big-endian. For kinds `2`, `3`, and `4`: zero-filled. |
| 24 | 2 | `input_len` | For kind `1`: number of input bytes included in the payload. For kinds `2`, `3`, and `4`: zero-filled. |
| 26 | 2 | `output_len` | For kind `1`: number of output bytes included in the payload. For kinds `2`, `3`, and `4`: zero-filled. |

Defined `kind` values:

| Value | Name | Description |
| ---: | --- | --- |
| 1 | Security response | TC apply/process security result with input bytes and optional output bytes |
| 2 | Status message | Plain text standalone status/debug message |
| 3 | Anti-replay counter set request | Binary request to update the effective anti-replay counter for a VCID |
| 4 | Anti-replay enforcement set request | Binary request to enable or disable TC anti-replay enforcement |

## Kind 1: Security Response

The payload is:

```text
input bytes, length input_len
output bytes, length output_len
```

For failure responses, `status` is `FAIL`, `crypto_status` is the CryptoLib error/status code, and `output_len` is `0`.

For success responses, `status` is `SUCCESS`, `crypto_status` is `0`, and `output_len` is the number of returned output bytes.

## Kind 2: Status Message

The payload is plain text, with no required trailing NUL byte. Current producers send one UTF-8-compatible ASCII status line such as:

```text
{"current_time":"2026-06-29T01:19:26.596+00:00","anti_replay_enforcement":true,"vcids":{"0":{"attempts":0,"successes":0,"most_recent_timestamp":"never","most_recent_result":"NONE","arsn":0,"arsn_hex":"0"},"2":{"attempts":42,"successes":39,"most_recent_timestamp":"2026-06-29T01:18:54.697+00:00","most_recent_result":"SUCCESS","arsn":1234,"arsn_hex":"4D2"},"3":{"attempts":0,"successes":0,"most_recent_timestamp":"never","most_recent_result":"NONE","arsn":0,"arsn_hex":"0"}}}
```

Current producers include the current TC anti-replay enforcement state and VCIDs `0`, `2`, and `3`. For these status messages, `arsn` means the effective anti-replay counter value selected from the SA: IV for AES-GCM/GCM-SIV SAs, ARSN for SAs with a transmitted sequence-number field, or `0` when no counter applies.

The fields at offsets 12 through 27 are zero-filled for status messages.

## Kind 3: Anti-Replay Counter Set Request

The request payload is a compact binary structure:

| Payload Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0 | 1 | `vcid` | TC VCID whose effective anti-replay counter should be changed |
| 1 | 1 | `counter_len` | Number of bytes in `counter` |
| 2 | `counter_len` | `counter` | New counter value, unsigned big-endian |

The current implementation accepts VCIDs `2` and `3`. VCID `2` updates SPI `4`'s IV; VCID `3` updates SPI `3`'s ARSN. `counter_len` must exactly match the selected effective counter length.

The response to this request is a kind `2` status message. On success, its payload is a single line such as:

```text
{"current_time":"2026-06-29T01:19:26.596+00:00","anti_replay_counter_modification":{"vcid":2,"previous_counter_hex":"000000000000000000000123","new_counter_hex":"000000000000000000000001"}}
```

On failure, the same object includes an integer `error` field containing the CryptoLib/MSU status code.

## Kind 4: Anti-Replay Enforcement Set Request

The request payload is a compact binary structure:

| Payload Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0 | 1 | `enforce` | `1` enables anti-replay enforcement. `0` ignores anti-replay enforcement. Other values are invalid. |

The current implementation accepts this request on the process standalone only.

The response to this request is a kind `2` status message. On success, its payload is a single line such as:

```text
{"current_time":"2026-06-29T01:19:26.596+00:00","anti_replay_enforcement":{"before":true,"after":false}}
```

On failure, the same object includes an integer `error` field containing the CryptoLib/MSU status code.

## Future Versions

Consumers should check `magic` first, then branch on `version`.

Future versions may keep the same `magic`, increment `version`, and replace the remainder of the header/payload with a richer format such as protobuf. `kind`, `header_len`, and `payload_len` are present so a parser can skip or dispatch newer envelope versions cleanly.
