/*

You sniffed the following Base64 string

ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=

You know it is an encrypted payload that has been ciphered with these parameters: 

key = "0123456789ABCDEF" 
iv = "0123456789ABCDEF" 

(Note: key and iv are not to be taken as hex strings)

Write a program (based for instance on dec1.c or a modification of enc4.c) to decrypt it and obtain decryptedcontent.

Then, take note of the following instruction in your decryption program if(!EVP_CipherInit(ctx,algorithm_name(), key, iv, ENCRYPT))

When you succeed, build the flag in this way (Python-style string concatenation)

"CRYPTO25{" + decryptedcontent + algorithm_name + "}"

*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

unsigned char *base64_decode(const char *input, int *len) {
    BIO *bio, *b64;
    int decode_len = strlen(input) * 3 / 4;
    unsigned char *buffer = malloc(decode_len);

    bio = BIO_new_mem_buf(input, -1);
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_push(b64, bio);

    *len = BIO_read(bio, buffer, decode_len);
    BIO_free_all(bio);

    return buffer;
}

void try_decrypt(const char *mode_name, const EVP_CIPHER *(*cipher)(), int key_len, int iv_len) {
    const char *base64_ciphertext = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";
    unsigned char key[16] = "0123456789ABCDEF";
    unsigned char iv[16] = "0123456789ABCDEF";

    int ciphertext_len;
    unsigned char *ciphertext = base64_decode(base64_ciphertext, &ciphertext_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!EVP_CipherInit(ctx, cipher(), key, iv, DECRYPT)) {
        handle_errors();
    }

    unsigned char plaintext[128];
    int plaintext_len = 0, len;

    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return;
    }
    plaintext_len += len;

    if (!EVP_CipherFinal_ex(ctx, plaintext + plaintext_len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return;
    }
    plaintext_len += len;

    plaintext[plaintext_len] = '\0';
    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);

    printf("Mode: %s\nDecrypted text: %s\n", mode_name, plaintext);
    printf("Flag: CRYPTO25{%s%s}\n", plaintext, mode_name);
}

int main() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    try_decrypt("AES-128-CBC", EVP_aes_128_cbc, 16, 16);
    try_decrypt("AES-128-ECB", EVP_aes_128_ecb, 16, 0);
    try_decrypt("AES-128-CFB", EVP_aes_128_cfb128, 16, 16);
    try_decrypt("AES-128-OFB", EVP_aes_128_ofb, 16, 16);
    try_decrypt("ChaCha20", EVP_chacha20, 32, 16);

    return 0;
}
