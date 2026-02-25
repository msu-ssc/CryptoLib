FROM ubuntu:20.04

WORKDIR /app

#install deps
RUN apt-get update && apt-get install -y gcc g++ make xxd openssl cmake libgcrypt20-dev


# copy in the working enviorment
COPY . .
# clean msu_crypto/build and then create it.
RUN rm -rf build support/msu_crypto/build && mkdir -p build support/msu_crypto/build

# building the project 
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCRYPTO_LIBGCRYPT=ON && \
    cmake -S support/msu_crypto -B support/msu_crypto/build -DCMAKE_BUILD_TYPE=Release -DKEY_INTERNAL=ON -DCRYPTO_LIBGCRYPT=ON -DMC_INTERNAL=ON -DSA_INTERNAL=ON && \
    cmake --build support/msu_crypto/build --config Release


# run the docker_build.sh to run the msu_crypto build and then run mayo_test.sh 
CMD ["./docker_build.sh"] 
