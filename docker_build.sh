#!/bin/bash
#this is for building msu_crypto and then running mayo_test when the docker runs.

echo "building msu_crypto"
./support/msu_crypto/build/msu_crypto
echo "running mayo_test.sh"
./mayo_test.sh
