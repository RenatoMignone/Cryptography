#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

/*-----------------------------------------------------------*/
void handle_errors(){
    ERR_print_errors_fp(stderr); //fp is the file pointer, prints on the standard error
    abort();
}

/*-----------------------------------------------------------*/
int main(){
    //ADDEDD ERROR HANDLING NEEDED FOR ALL THE FUNCTIONS
    ERR_load_crypto_strings(); //initializes the error strings for all libcrypto functions
    OpenSSL_add_all_algorithms(); //registers all the algorithms


    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[]  = "abcdef1234567890";
    unsigned char ciphertext[] = "13713c9b8081468892c518592730b3496d2c58ed3a9735d90788e7c24e8d324d75f6c9f5c6e43ee7dccad4a3221d697e";

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT))
        handle_errors();

    unsigned char plaintext[strlen(ciphertext)/2];
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    printf("\nOriginal (hex) ciphertext: %s", ciphertext);
    printf("\n\nNumber of hex characters: %lu", strlen(ciphertext));

    for(int i = 0; i < strlen(ciphertext)/2; i++)
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);

    int length;
    int plaintext_len = 0;

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherUpdate(ctx,plaintext,&length,ciphertext_bin,strlen(ciphertext)/2))
        handle_errors();


    printf("\n\nAfter update (bytes decrypted so far): %d", length);
    plaintext_len += length;

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherFinal(ctx,plaintext + length,&length))
        handle_errors();

    printf("\n\nAfter final (additional bytes decrypted): %d", length);
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len] = '\0';

    printf("\n\nTotal decrypted bytes: %d", plaintext_len);
    printf("\n\nDecrypted plaintext: %s\n", plaintext);

    //CLEANUP OF THE ERRORS
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings(); 

    return 0;
}