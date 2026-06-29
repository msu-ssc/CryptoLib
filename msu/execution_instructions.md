# Building the Docker Image

This builds a docker container with the name `ivvitc/cryptolib:dev`.

```bash
docker build -f support/Dockerfile -t ivvitc/cryptolib:dev .
```

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
  ivvitc/cryptolib:dev \
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
  ivvitc/cryptolib:dev \
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
