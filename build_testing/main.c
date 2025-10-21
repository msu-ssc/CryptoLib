#include <stdio.h>
#include <crypto.h>

int main(void) {
    printf("Starting CryptoLib test program...\n");

    // Initialize the CryptoLib librar
    Crypto_TC_ApplySecurity();    



    printf("CryptoLib initialized successfully!\n");

    // TODO: Perform any operations your library supports here
    // e.g., key loading, encryption, decryption, etc.

    // If available, clean up before exit
    // Crypto_Terminate();

    printf("Exiting CryptoLib test program.\n");
    return 0;
}

