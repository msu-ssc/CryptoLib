**Build Everything (crypto lib + msu_crypto CLI)**  
Run from repo root `/root/dev/CryptoLib`.

- **Prereqs**: `cmake` (≥3.16), `make`, C compiler; optional real crypto via `libgcrypt` (`sudo apt install libgcrypt20-dev`), otherwise the stub builds automatically.
- **Fresh build directory**: `rm -rf build support/msu_crypto/build && mkdir -p build support/msu_crypto/build`
- **Configure core library** (optional standalone build):  
  `cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCRYPTO_LIBGCRYPT=ON`  
  Builds `libcryptolib.so` in `build`.
- **Configure msu_crypto sample** (this also builds CryptoLib as a subproject):  
  `cmake -S support/msu_crypto -B support/msu_crypto/build -DCMAKE_BUILD_TYPE=Release -DKEY_INTERNAL=ON -DCRYPTO_LIBGCRYPT=ON -DMC_INTERNAL=ON -DSA_INTERNAL=ON`
- **Build**:  
  `cmake --build support/msu_crypto/build --config Release`
- **Outputs**: `support/msu_crypto/build/msu_crypto` (CLI) and `support/msu_crypto/build/cryptolib_build/libcryptolib.so` (linked as `crypto`).
- **Quick verification**:  
  `./support/msu_crypto/build/msu_crypto --help`  
  or run the sample pipeline: `./mayo_test.sh` (it expects the built binary at `support/msu_crypto/build/msu_crypto` and writes frames under `frames/`).  
- **Reconfigure options**: drop `-DCRYPTO_LIBGCRYPT=ON` to use the stub; add other CMake flags from top-level `CMakeLists.txt` (e.g., `-DCRYPTO_EPROC=ON`, `-DDEBUG=ON`) as needed.