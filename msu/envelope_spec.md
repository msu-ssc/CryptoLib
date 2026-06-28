# MSU CryptoLib Standalone Envelope

This is a small binary response envelope used by the standalone CryptoLib tools for TC apply/process responses.

It is intentionally simple: a fixed header followed by the original input bytes and, when available, output bytes.

## Version 1

All multi-byte integer fields are unsigned big-endian.

| Offset | Size | Field | Description |
| --- | ---: | --- | --- |
| 0 | 4 | `magic` | ASCII `MSUC` (`0x4d 0x53 0x55 0x43`) |
| 4 | 1 | `version` | `1` |
| 5 | 1 | `header_len` | `28` |
| 6 | 2 | `kind` | Envelope kind enum. `1` means security response. |
| 8 | 4 | `payload_len` | Number of bytes after the header |
| 12 | 8 | `status` | NUL-padded ASCII: `SUCCESS` or `FAIL` |
| 20 | 4 | `crypto_status` | CryptoLib status as signed int32, encoded big-endian |
| 24 | 2 | `input_len` | Number of input bytes included in the payload |
| 26 | 2 | `output_len` | Number of output bytes included in the payload |

Defined `kind` values:

| Value | Name | Description |
| ---: | --- | --- |
| 1 | Security response | TC apply/process security result with input bytes and optional output bytes |

The payload is:

```text
input bytes, length input_len
output bytes, length output_len
```

For failure responses, `status` is `FAIL`, `crypto_status` is the CryptoLib error/status code, and `output_len` is `0`.

For success responses, `status` is `SUCCESS`, `crypto_status` is `0`, and `output_len` is the number of returned output bytes.

## Future Versions

Consumers should check `magic` first, then branch on `version`.

Future versions may keep the same `magic`, increment `version`, and replace the remainder of the header/payload with a richer format such as protobuf. `kind`, `header_len`, and `payload_len` are present so a parser can skip or dispatch newer envelope versions cleanly.
