#!/bin/bash

set -euo pipefail

cd /root/dev/CryptoLib
rm -rf frames

mkdir -p frames

VCID=1
SCID=119
KEY_ID=1
KEY_LENGTH=32

echo "18FAC00000010000" | xxd -r -p > frames/space_packet.original.bin

# Create a key and save it as a variable
KEY=$(openssl rand -hex $KEY_LENGTH)

# Print params to screen
echo "=============================="
printf "VCID: %02d (0x%02X)\n" $VCID $VCID
printf "SCID: %02d (0x%02X)\n" $SCID $SCID
printf "KEY_ID: %02d (0x%02X)\n" $KEY_ID $KEY_ID
echo "Key size: $KEY_LENGTH bytes = $(($KEY_LENGTH * 8)) bits"
echo "Key: $KEY"

# Register a key
./support/msu_crypto/build/msu_crypto --register-key "$KEY" --key-id $KEY_ID

# Encrypt
cat frames/space_packet.original.bin | ./support/msu_crypto/build/msu_crypto --encrypt --space-packet --key-id $KEY_ID --vcid $VCID --scid $SCID > frames/tc_frame.encrypted.bin

# Decrypt
cat frames/tc_frame.encrypted.bin | ./support/msu_crypto/build/msu_crypto --decrypt --space-packet --vcid $VCID --scid $SCID --key-id $KEY_ID > frames/space_packet.decrypted.bin

# Display files
echo "=============================="
echo "Original Space Packet ($(stat -c %s frames/space_packet.original.bin) bytes):"
xxd -p frames/space_packet.original.bin
echo "=============================="
echo "Encrypted TC Frame ($(stat -c %s frames/tc_frame.encrypted.bin) bytes):"
xxd -p frames/tc_frame.encrypted.bin
echo "=============================="
echo "Decrypted Space Packet ($(stat -c %s frames/space_packet.decrypted.bin) bytes):"
xxd -p frames/space_packet.decrypted.bin
echo "=============================="

# Verify
if cmp -s frames/space_packet.original.bin frames/space_packet.decrypted.bin; then
    echo "✅ Success: Decrypted space packet matches original."
else
    echo "❌ Error: Decrypted space packet does not match original."
    exit 1
fi