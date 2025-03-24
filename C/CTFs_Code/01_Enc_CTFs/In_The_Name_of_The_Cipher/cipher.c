/*
Write a program in C that, using the OpenSSL library, 
encrypts the content of a file using a user-selected algorithm.

The input filename is passed as first parameter from the command line, 
key and IV are the second and third parameter, 
the output file is the fourth parameter, the 
algorithm is the last parameter.

The algorithm name must be an OpenSSL-compliant string 
(e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)

Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html

In doing the exercise you have found a very relevant function, 
build the flag as "CRYPTO25{" + relevantFunctionName + "}"


FLAG:
CRYPTO25{EVP_get_cipherbyname}

*/

/*=======================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

#define BUFFER_SIZE 4096

/*=======================================================================*/
void handleErrors() {
    fprintf(stderr, "An error occurred.\n");
    exit(EXIT_FAILURE);
}

/*=======================================================================*/
void encrypt_file(const char *input_filename, const char *key, const char *iv, 
                  const char *output_filename, const char *algorithm) {

    /*=======================================================================*/
    // Open input and output files
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    
    if (!input_file || !output_file) {
        perror("File opening failed");
        exit(EXIT_FAILURE);
    }

    /*=======================================================================*/
    // Load cipher
    // The EVP_get_cipherbyname() function returns the cipher implementation for the given algorithm name.
    // and this one is the FLAG itself.
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    if (!cipher) {
        fprintf(stderr, "Unknown algorithm: %s\n", algorithm);
        exit(EXIT_FAILURE);
    }

    /*=======================================================================*/
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) handleErrors();

    /*=======================================================================*/
    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (unsigned char *)key, (unsigned char *)iv) != 1)
        handleErrors();

    /*=======================================================================*/
    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int bytes_read, len, ciphertext_len;

    /*=======================================================================*/
    // we read the file in chunks of BUFFER_SIZE bytes and encrypt each chunk
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes_read) != 1)
            handleErrors();
        fwrite(ciphertext, 1, len, output_file);
    }

    /*=======================================================================*/
    // we perform the final encryption step
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len) != 1)
        handleErrors();
    fwrite(ciphertext, 1, ciphertext_len, output_file);

    /*=======================================================================*/
    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    fclose(input_file);
    fclose(output_file);
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <input file> <key> <iv> <output file> <algorithm>\n", argv[0]);
        return EXIT_FAILURE;
    }

    encrypt_file(argv[1], argv[2], argv[3], argv[4], argv[5]);

    printf("Encryption successful!\n");

    return EXIT_SUCCESS;
}
