/*

Given the secret (represented as a C variable)

unsigned char secret[] = "this_is_my_secret";

Write a program in C that computes the keyed digest as

kd = SHA512 ( secret || input_file || secret)

where || indicates the concatenation (without adding any space characters)
hex computes the representation as an hexstring
Surround with CRYPTO25{hex(kd)} to obtain the flag.

HINT: start from hash3.c or hash4.c


FLAG:

CRYPTO25{312f7c144f845211ea18aa82115ae5848dee7036d9527ad014def7d0d495ec54b4f998d688e666aed56b1626bee91359a0db4ddb2f03625e82225dc95a8ff1c5}

*/



#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

// Define the secret for the keyed digest.
unsigned char secret[] = "this_is_my_secret";

int main(int argc, char **argv) {
    // Check for proper usage; ensure one input file is provided.
    if (argc != 2) {
        fprintf(stderr, "Usage: %s input_file\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Open the input file in binary mode.
    // (Standard files handled file opening with error checking.)
    FILE *fp = fopen(argv[1], "rb");
    if (fp == NULL) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    // Create a new EVP message digest context.
    //here we use the same context of the file with the SHA1
    EVP_MD_CTX *SHA512_ctx = EVP_MD_CTX_new();
    if (SHA512_ctx == NULL) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        fclose(fp);
        return EXIT_FAILURE;
    }

    // Initialize the digest context with the SHA512 algorithm.
    //here we are performing the initialization of the context with the SHA512 algorithm
    if (!EVP_DigestInit_ex(SHA512_ctx, EVP_sha512(), NULL)) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(SHA512_ctx);
        fclose(fp);
        return EXIT_FAILURE;
    }

    // Determine the length of the secret.
    size_t secret_len = strlen(secret);

    // First Pass: Update the digest with the secret.
    // The first Update process is performed over the secret
    // this because as read in the track the secret is the first element of the concatenation
    if (!EVP_DigestUpdate(SHA512_ctx, secret, secret_len)) {
        fprintf(stderr, "EVP_DigestUpdate for secret failed\n");
        EVP_MD_CTX_free(SHA512_ctx);
        fclose(fp);
        return EXIT_FAILURE;
    }

    // Second Pass: Read and process the input file in chunks.
    // Here we compute as always the digest of the file in chunks
    unsigned char buffer[1024];

    //this is the variable that will store the number of bytes read from the file
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (!EVP_DigestUpdate(SHA512_ctx, buffer, bytes_read) ) {
            fprintf(stderr, "EVP_DigestUpdate for file chunk failed\n");
            EVP_MD_CTX_free(SHA512_ctx);
            fclose(fp);
            return EXIT_FAILURE;
        }
    }

    // Close the input file.
    fclose(fp);

    // Third Pass: Update the digest with the secret again.
    // In this case the last process will be performed with the secret itself
    // This because the secret is the last element of the concatenation

    if (!EVP_DigestUpdate(SHA512_ctx, secret, secret_len)) {
        fprintf(stderr, "EVP_DigestUpdate for secret second update failed\n");
        EVP_MD_CTX_free(SHA512_ctx);
        return EXIT_FAILURE;
    }

    // Finalize the digest calculation.
    // The final digest is stored in 'digest', and digest_len holds its length.
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len;
    if (!EVP_DigestFinal_ex(SHA512_ctx, digest, &digest_len)) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        EVP_MD_CTX_free(SHA512_ctx);
        return EXIT_FAILURE;
    }

    // Clean up the EVP context.
    EVP_MD_CTX_free(SHA512_ctx);

    // Convert the binary digest into a hexadecimal string and output in the flag format.
    // The flag is formed as CRYPTO25{hex(kd)}.
    printf("CRYPTO25{");
    for (unsigned int i = 0; i < digest_len; i++) {
        printf("%02x", digest[i]);
    }
    printf("}\n");

    return EXIT_SUCCESS;
}
