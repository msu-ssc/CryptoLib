# Building the Docker Image

This builds the development image `ivvitc/cryptolib:dev`, including compilers and fuzzing tools.

```bash
docker build -f support/Dockerfile -t ivvitc/cryptolib:dev .
```

## Minimal runtime image

For running already-built `lemsa3_apply_security` and `lemsa3_process_security`, build
the separate runtime image from the repository root:

```bash
docker build -f support/Dockerfile.runtime -t msu-ssc/cryptolib-runtime:dev .
```

This image contains Ubuntu 24.04 and the libgcrypt runtime dependencies. It omits
compilers, fuzzing tools, documentation generators, and wolfSSL. It supports the
`CRYPTO_LIBGCRYPT=1` standalone build below, including counter updates and VCIDs
0, 2, and 3. Other cryptography/database backends may require additional libraries.
Use the development image to build or rebuild CryptoLib.

The runtime image does not contain mission binaries, keys, or SADB state. Mount
the compiled executables, `libcryptolib.so`, and writable state directories as shown
below. Preserve the separate Apply and Process state files when changing images.
Prebuilt binaries must match the container architecture and Ubuntu 24.04 ABI.

To transfer the runtime image to the VM:

```bash
docker save --output cryptolib-runtime-image.tar msu-ssc/cryptolib-runtime:dev
# On the destination host, after copying the archive:
docker load --input cryptolib-runtime-image.tar
```

Select `msu-ssc/cryptolib-runtime:dev` in the MOC/VM image configuration to use it.
Building or loading it does not change existing image selections. This name is a
local build tag; these instructions do not assume an image has been published.

# Running and Building CryptoLib

## Building/Rebuilding standalone CryptoLib
To build CryptoLib ensure that `/build/standalone` has been properally emptied for future/current builds via 

```bash
rm -rf build/standalone 
mkdir -p build/standalone
```

You may have to remove this as root given that premissions are transfered from docker into the `PWD`. 

After clearing the `build/standalone` folder we can now run 

```bash
docker run --rm -it \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  bash -lc 'cmake ../.. -DCODECOV=1 -DDEBUG=1 -DMC_INTERNAL=1 -DTEST=1 -DSA_FILE=1 -DCRYPTO_LIBGCRYPT=1 -DKEY_INTERNAL=1 -DSA_INTERNAL=1 -DSUPPORT=1 && make'
```

## Running lemsa3_apply_security

The standalone tools use `127.0.0.1` for all endpoints. When running in Docker, use host networking so loopback refers to the host network namespace.

Within the Cryptolib root directory run 

```bash
docker run --rm -it \
  --network host \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  -e "LD_LIBRARY_PATH=$PWD/build/standalone:$PWD/build/standalone/src" \
  msu-ssc/cryptolib-runtime:dev \
  ./support/lemsa3_apply_security
```

For command-security JSON contexts, use the same Docker networking shape as an argv array: include `--network`, `host`, remove old `--hostname` and `--add-host` entries, and remove old `-p` port-publishing entries.

## Runtime Paths

These paths are relative to the CryptoLib root. Invoke both programs from `build/standalone`.

| Tool | Executable | CWD at invocation | SA save file |
| --- | --- | --- | --- |
| Apply security | `build/standalone/support/lemsa3_apply_security` | `build/standalone` | `build/standalone/standalone_apply_state/sa_save_file.bin` |
| Process security | `build/standalone/support/lemsa3_process_security` | `build/standalone` | `build/standalone/standalone_process_state/sa_save_file.bin` |

The binary response envelope format is described in [`msu/envelope_spec.md`](envelope_spec.md).

## Running lemsa3_process_security

This runs the docker container and exposes the approprate ports to our host machine for use. 

```bash
docker run --rm -it \
  --network host \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  -e "LD_LIBRARY_PATH=$PWD/build/standalone:$PWD/build/standalone/src" \
  msu-ssc/cryptolib-runtime:dev \
  ./support/lemsa3_process_security
```

`lemsa3_process_security` enforces TC anti-replay by default. To ignore TC anti-replay validation, pass:

```bash
./support/lemsa3_process_security --anti-replay=ignore
```

`--anti-replay=enforce` is also accepted explicitly and is equivalent to the default.

# Running lems_a3_standalone_app

## Running Standalone

Run `uv run ./main.py` within the `CryptoLib/lems_a3_standalone_app` directory, ensure CryptoLib is running prior to running `lems_a3_standalone_app/main.py` because it is dependant on the CryptoLib container to be active. 
