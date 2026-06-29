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
| 6 | 2 | `kind` | Envelope kind enum. `1` means security response. `2` means status message. |
| 8 | 4 | `payload_len` | Number of bytes after the header |
| 12 | 8 | `status` | For kind `1`: NUL-padded ASCII `SUCCESS` or `FAIL`. For kind `2`: zero-filled. |
| 20 | 4 | `crypto_status` | For kind `1`: CryptoLib status as signed int32, encoded big-endian. For kind `2`: zero-filled. |
| 24 | 2 | `input_len` | For kind `1`: number of input bytes included in the payload. For kind `2`: zero-filled. |
| 26 | 2 | `output_len` | For kind `1`: number of output bytes included in the payload. For kind `2`: zero-filled. |

Defined `kind` values:

| Value | Name | Description |
| ---: | --- | --- |
| 1 | Security response | TC apply/process security result with input bytes and optional output bytes |
| 2 | Status message | Plain text standalone status/debug message |

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
{"current_time":"2026-06-29T01:19:26.596+00:00","vcids":{"0":{"attempts":0,"successes":0,"most_recent_timestamp":"never","most_recent_result":"NONE","arsn":0,"arsn_hex":"0"},"2":{"attempts":42,"successes":39,"most_recent_timestamp":"2026-06-29T01:18:54.697+00:00","most_recent_result":"SUCCESS","arsn":1234,"arsn_hex":"4D2"},"3":{"attempts":0,"successes":0,"most_recent_timestamp":"never","most_recent_result":"NONE","arsn":0,"arsn_hex":"0"}}}
```

Current producers include VCIDs `0`, `2`, and `3`. For these status messages, `arsn` means the effective anti-replay counter value selected from the SA: IV for AES-GCM/GCM-SIV SAs, ARSN for SAs with a transmitted sequence-number field, or `0` when no counter applies.

The fields at offsets 12 through 27 are zero-filled for status messages.

## Future Versions

Consumers should check `magic` first, then branch on `version`.

Future versions may keep the same `magic`, increment `version`, and replace the remainder of the header/payload with a richer format such as protobuf. `kind`, `header_len`, and `payload_len` are present so a parser can skip or dispatch newer envelope versions cleanly.
