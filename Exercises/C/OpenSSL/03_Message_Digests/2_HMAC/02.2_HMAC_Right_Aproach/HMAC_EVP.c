#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

//we need to include the openssl hmac header file
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
// Main function for HMAC calculation using EVP
// Steps:
// 1) Parse arguments
// 2) Open file
// 3) Prepare HMAC context
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
    // Body of the hashing: setting up the HMAC context and computing the final value

    // A key of 16 ASCII characters
    unsigned char key[] = "1234567887654321";

    // We need to create a structure for the key as a pointer to the EVP_PKEY structure
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key));
    
    // Now we create the structure for the digest context
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();

    // Initialize the context for HMAC with SHA-256
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    
    // Read the file in chunks of size MAXBUF and update the HMAC
    while(n_read = fread(buffer, 1, MAXBUF, f_in) > 0){
        // We have now read data from the file into the buffer
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    // The finalization requires a buffer to store the final value
    // It must be as large as the output of the chosen hash (SHA-256 in this case)
    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];

    // An integer used to store the length of the HMAC value
    int hmac_len;

    // Finish computing the HMAC and store the result in hmac_value
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // Now we free the context
    EVP_MD_CTX_free(hmac_ctx);

    //---------------------------------
    // Print the computed HMAC in a readable hexadecimal format
    printf("The HMAC is: ");
    for(int i = 0; i < 32; i++){
        printf("%02x",hmac_value[i]);
    }
    printf("\n");

    //---------------------------------
    // Clean-up operations
    // Clean up the cipher data (deprecated since version 1.1.0)
    CRYPTO_cleanup_all_ex_data();
    // Remove error strings (deprecated since version 1.1.0)
    ERR_free_strings();

    return 0;
}
