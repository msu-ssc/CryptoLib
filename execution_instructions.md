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

## Running CryptoLib

set up in `/ect/hosts` the cryptolib radio-sim cosmos as being on ip `127.0.0.1`. It should look like this `127.0.0.1 cryptolib radio-sim cosmos` at the top of `/ect/hosts`.

Within the Cryptolib root directory run 

```bash
docker run --rm -it \
  --hostname cryptolib \
  --add-host radio-sim:host-gateway \
  --add-host cosmos:host-gateway \
  -p 6010:6010/udp \
  -p 8011:8011/udp \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  ./support/standalone
```

This runs the docker container and exposes the approprate ports to our host machine for use. 

## Configuring standalone_config.txt

the `standalone/standalone_config.txt` is formatted as field, value pairs with the syntax

```
Field=Value
```

The table below will show the expected data type for each field. 

- Ports
  - `TC_APPLY_PORT` - Sets the apply port, this expects a number of type `uint16_t`.
  - `TC_APPLY_FWD_PORT`- Sets the apply forward port, this expects a number of type `uint16_t`.
  - `TC_PROCESS_PORT` - Sets the process port, this expects a number of type `uint16_t`.
  - `TC_PROCESS_FWD_PORT`- Sets the process forward port, this expects a number of type `uint16_t`.
  - `INFO_QUERY_PORT` - Sets the port for info query, this expects a number of type `uint16_t`.
  - `INFO_RESPONSE_PORT` - Sets the info response port, this expects a number of type `uint16_t`. 


# Running lems_a3_standalone_app

## Running Standalone

Run `uv run ./main.py` within the `CryptoLib/lems_a3_standalone_app` directory, ensure CryptoLib is running prior to running `lems_a3_standalone_app/main.py` because it is dependant on the CryptoLib container to be active. 

