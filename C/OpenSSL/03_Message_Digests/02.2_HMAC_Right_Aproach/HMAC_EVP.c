#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

//we need to include the openssl hmac header file
#include <openssl/hmac.h>

#define MAXBUF 1024 // Define the maximum buffer size for reading the file

// Function to handle errors by printing them and aborting the program
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){
    // Check if the correct number of arguments is provided
    if(argc != 2){
        fprintf(stderr,"Invalid parameters. Usage: %s filename\n",argv[0]);
        exit(1);
    }

    FILE *f_in;
    // Try to open the input file, if it fails, print an error message and exit
    if((f_in = fopen(argv[1],"r")) == NULL) {
        fprintf(stderr,"Couldn't open the input file, try again\n");
        exit(1);
    }

    // Load the human readable error strings for libcrypto (deprecated since version 1.1.0)
    ERR_load_crypto_strings();
    // Load all digest and cipher algorithms (deprecated since version 1.1.0)
    OpenSSL_add_all_algorithms();

    /*------------------------------------------------------*/
    /*--------------------Body of the hashing---------------*/


    //a key of 16 ASCII characters
    unsigned char key[] = "1234567887654321";
    //we need to create a structure for the key
    //we declare it as a pointer to the EVP_PKEY structure
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));
    
    //now we need to create the structure for the context
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();

    //now we need to initialize the context
    //the second null is to compute the digital signature
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    
    while(n_read = fread(buffer, 1, MAXBUF, f_in) > 0){
        //we have now read MAXBUF data from the file
        //the buffer contains the data read from the file 
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    //the finalization requires the usage of a buffer to store the final value
    //has to be as big as the output of the hash function that we are using
    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];

    //an integer used to store the length of the hmac value
    int hmac_len;

    //the parameters here are the context, the buffer to store the final value and the length of the final value
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    //now we need to free the context
    EVP_MD_CTX_free(hmac_ctx);

    printf("The HMAC is:");
    for(int i = 0; i < 32; i++){
        printf("%02x",hmac_value[i]);
    }
    printf("\n");

    // Clean up the cipher data (deprecated since version 1.1.0)
    CRYPTO_cleanup_all_ex_data();
    // Remove error strings (deprecated since version 1.1.0)
    ERR_free_strings();

    return 0;
}