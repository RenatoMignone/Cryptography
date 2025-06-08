#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h> //library for the error handling

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

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // check if NULL

    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[]  = "abcdef1234567890";

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();


    unsigned char plaintext[] = "This variable contains the data to encrypt";
    unsigned char ciphertext[48];

    printf("\nPlaintext length: %lu", strlen(plaintext));

    int length;
    int ciphertext_len = 0;

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherUpdate(ctx,ciphertext,&length,plaintext,strlen(plaintext)))
        handle_errors();

    
    printf("\n\nAfter update, so after the initial encryption: %d", length);
    ciphertext_len += length;

    //ADDEDD ERROR HANDLING
    if(!EVP_CipherFinal(ctx,ciphertext + length,&length))
        handle_errors();

    printf("\n\nAfter final, so after the adding of the padding: %d", length);
    ciphertext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    printf("\n\nSize of the ciphertext = %d\n", ciphertext_len);

    printf("\nHexadecimal representation of the ciphertext: ");
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");


    printf("\n Binary representation of the ciphertext: ");
    for (int i = 0; i < ciphertext_len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (ciphertext[i] >> bit) & 1);
        }
        printf(" ");
    }

    //CLEANUP OF THE ERRORS
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}