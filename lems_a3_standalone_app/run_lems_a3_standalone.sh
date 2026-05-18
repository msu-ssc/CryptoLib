docker run --rm -it \
  --hostname cryptolib \
  -v "$PWD:$PWD" \
  -w "$PWD/build/standalone" \
  ivvitc/cryptolib:dev \
  ./support/standalone

uv run ./lems_a3_standalone_app/main.py
