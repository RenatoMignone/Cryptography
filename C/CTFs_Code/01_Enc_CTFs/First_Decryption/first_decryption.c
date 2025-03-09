/*

You detected the following message

jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==

which has been encrypted with the program whose code is attached.

It has been generated with the following command line string

./enc.exe file.txt 0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF 11111111111111112222222222222222 file.enc openssl base64 -in file.enc

Write a program in C that decrypts the content and get the flag!

FLAG:
CRYPTO25{MyDecryptedString}
*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define DECRYPT 0
#define MAX_BUFFER 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

/* Decode a base64-encoded string into a malloc’d buffer.
   The caller is responsible for freeing the returned buffer.
   out_len is set to the number of decoded bytes. */
unsigned char *base64_decode(const char *input, int *out_len) {
    BIO *b64, *bmem;
    size_t input_len = strlen(input);
    // Allocate a buffer large enough (base64 expands by ~33%)
    unsigned char *buffer = malloc(input_len);
    if (!buffer) {
        perror("malloc");
        exit(1);
    }
    
    b64 = BIO_new(BIO_f_base64());
    // Disable newlines in the base64 decoding
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_new_mem_buf((void*)input, input_len);
    bmem = BIO_push(b64, bmem);

    *out_len = BIO_read(bmem, buffer, input_len);
    BIO_free_all(bmem);
    return buffer;
}

int main(void){
    /* Hardcoded parameters based on the command line:
       key:  0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF
       iv:   11111111111111112222222222222222
       encrypted (base64): jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q== */
    const char *b64_ciphertext = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";
    const char *hex_key = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
    const char *hex_iv  = "11111111111111112222222222222222";

    /* Convert hex key to binary */
    int key_len = strlen(hex_key) / 2;
    unsigned char key[key_len];
    for (int i = 0; i < key_len; i++){
        sscanf(&hex_key[2 * i], "%2hhx", &key[i]);
    }

    /* Convert hex IV to binary */
    int iv_len = strlen(hex_iv) / 2;
    unsigned char iv[iv_len];
    for (int i = 0; i < iv_len; i++){
        sscanf(&hex_iv[2 * i], "%2hhx", &iv[i]);
    }

    /* Decode the base64 ciphertext */
    int cipher_len;
    unsigned char *cipher_bytes = base64_decode(b64_ciphertext, &cipher_len);
    if(cipher_len <= 0){
        fprintf(stderr, "Base64 decoding failed.\n");
        return 1;
    }

    /* Initialize OpenSSL libraries */
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if(!ctx) handle_errors();

    /* Initialize decryption context using ChaCha20 */
    if(!EVP_CipherInit(ctx, EVP_chacha20(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[MAX_BUFFER];
    int out_len1 = 0;
    if(!EVP_CipherUpdate(ctx, plaintext, &out_len1, cipher_bytes, cipher_len))
        handle_errors();

    int out_len2 = 0;
    if(!EVP_CipherFinal_ex(ctx, plaintext + out_len1, &out_len2))
        handle_errors();

    int total_len = out_len1 + out_len2;
    plaintext[total_len] = '\0'; // null-terminate the result

    printf("Decrypted text (flag): %s\n", plaintext);

    EVP_CIPHER_CTX_free(ctx);
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    free(cipher_bytes);
    return 0;
}
