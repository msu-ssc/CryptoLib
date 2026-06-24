# CryptoLib Standalone Proof of Concept

These instructions build and run the two minimal TC standalone apps:

- `support/standalone/standalone.c`: TC apply side. It receives an original TC frame and applies security based on the frame VCID.
- `support/standalone/standalone_process.c`: TC process side. It receives the secured or pass-through frame and reconstructs the original TC frame.

The apps use Docker container hostnames and `--add-host ...:host-gateway` entries in the run commands below. The host machine does not need `/etc/hosts` changes for this workflow.

## Build the Docker Image

From the CryptoLib root directory:

```bash
docker build -f support/Dockerfile -t ivvitc/cryptolib:dev .
```

## Build the Standalone Apps

If you need a clean build directory, remove and recreate it first:

```bash
rm -rf build/standalone
mkdir -p build/standalone
```

If the directory was created by a Docker container, you may need to fix ownership or remove it with elevated permissions before rebuilding.

Build inside the Docker image:

```bash
docker run --rm -it \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  bash -lc 'cmake ../.. -DCODECOV=1 -DDEBUG=1 -DMC_INTERNAL=1 -DTEST=1 -DSA_FILE=1 -DCRYPTO_LIBGCRYPT=1 -DKEY_INTERNAL=1 -DSA_INTERNAL=1 -DSUPPORT=1 && make'
```

## Run the Standalone Apps

Run these commands from the CryptoLib root directory in two terminals.

First, start the TC apply side:

```bash
docker run --rm -it \
  --hostname cryptolib \
  --add-host radio-sim:host-gateway \
  --add-host cosmos:host-gateway \
  -p 6010:6010/udp \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  ./support/standalone
```

This app receives original TC frames on UDP port `6010` and forwards the secured or pass-through result to the host at `radio-sim:8010`. The app has a startup delay of about 10 seconds; wait until it prints its UDP port summary before running the round-trip test.

Second, start the TC process side:

```bash
docker run --rm -it \
  --hostname cryptolib \
  --add-host cosmos:host-gateway \
  -p 6012:6012/udp \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  ./support/standalone_process
```

This app receives secured or pass-through TC frames on UDP port `6012` and forwards the reconstructed TC frame to the host at `cosmos:8012`.

Do not publish host ports `8010` or `8012` in the Docker run commands. The round-trip test binds those ports on the host in order to receive frames from the containers.

`standalone` also starts a TM process listener on `cryptolib:8011` that forwards to `cosmos:6011`. That path is not used by the current TC round-trip proof of concept.

## Run the Round-Trip Test

After both standalone apps are running and have printed their port summaries, run:

```bash
python3 msu/test_round_trip.py
```

The test sends each TC frame through this sequence:

1. Send the original TC frame to `standalone` on UDP port `6010`.
2. Receive the secured or pass-through frame from UDP port `8010`.
3. Send that frame to `standalone_process` on UDP port `6012`.
4. Receive the reconstructed TC frame from UDP port `8012`.
5. Compare the reconstructed frame with the original frame.

The test reads its input frames from `msu/untracked/tc_frames.txt`.

## Current TC VCID Behavior

The standalone TC apply side makes its security decision from the TC frame VCID:

- VCID 0: no security is applied; the frame is forwarded unchanged.
- VCID 2: encryption and authentication are applied.
- VCID 3: authentication only is applied.

The standalone TC process side performs the inverse:

- VCID 0: the frame is forwarded unchanged.
- VCID 2: encryption and authentication are processed to reconstruct the original TC frame.
- VCID 3: authentication is processed to reconstruct the original TC frame.

Known bug: the desired behavior is to reject all VCIDs other than 0, 2, and 3. The current proof-of-concept code does not do this yet. Unsupported VCIDs currently follow the no-security pass-through path.

## State Files

The build command above enables file-backed security association state with `-DSA_FILE=1`. If the apps are restarted independently or stale state causes anti-replay/counter behavior to change, restart both apps together from the same build directory so they use a coherent state.
