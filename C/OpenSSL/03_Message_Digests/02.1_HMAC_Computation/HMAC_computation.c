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
    
    //now we need to create the structure for the context
    //check if this value is null or not
    HMAC_CTX *hmac_ctx = HMAC_CTX_new();

    //now we need to initialize the context
    //we are here using the sha256 algorithm for the hashing
    //the last null value is for the engine
    if(!HMAC_Init_ex(hmac_ctx, key, strlen(key), EVP_sha256(), NULL))
        handle_errors();

    //now we need to read the 

    int n_read;
    unsigned char buffer[MAXBUF];
    
    while(n_read = fread(buffer, 1, MAXBUF, f_in) > 0){
        //we have now read MAXBUF data from the file
        //the buffer contains the data read from the file 
        if(!HMAC_Update(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    //the finalization requires the usage of a buffer to store the final value
    //has to be as big as the output of the hash function that we are using
    unsigned char hmac_value[HMAC_size(hmac_ctx)];

    //an integer used to store the length of the hmac value
    int hmac_len;

    //the parameters here are the context, the buffer to store the final value and the length of the final value
    if(!HMAC_Final(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    //now we need to free the context
    HMAC_CTX_free(hmac_ctx);

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