#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <openssl/hmac.h>

//---------------------------------
// Define the maximum buffer size for reading the file
#define MAXBUF 1024 

//---------------------------------
// Function to handle errors by printing them and aborting the program
// This will be triggered if an OpenSSL function fails
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

//---------------------------------
// Main function for HMAC calculation using the "classic" HMAC API
// Steps:
// 1) Parse arguments
// 2) Open file
// 3) Initialize HMAC context with SHA-256
// 4) Read file and update HMAC
// 5) Finalize and print the HMAC

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

    //---------------------------------
    // Body of the hashing: prepare HMAC context and compute the final value
    // A key of 16 ASCII characters
    unsigned char key[] = "1234567887654321";

    // Create the HMAC context
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();

    // Initialize the context; last NULL is for the engine
    if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha256(), NULL))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];

    // Read the file in chunks of size MAXBUF and update the HMAC
    while((n_read = fread(buffer, 1, MAXBUF, f_in)) > 0){
        if(!HMAC_Update(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // Allocate a buffer for the final HMAC
    unsigned char hmac_value[HMAC_size(hmac_ctx)];
    // Will hold the length of the computed HMAC
    int hmac_len;

    // Finish computing the HMAC and store it
    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // Free the HMAC context
    HMAC_CTX_free(hmac_ctx);

    //---------------------------------
    // Print the computed HMAC in a readable hexadecimal format
    printf("The HMAC is:");
    for(int i = 0; i < 32; i++){
        printf("%02x",hmac_value[i]);
    }
    printf("\n");

    //---------------------------------
    // Clean-up operations
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}