#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

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

    // Create a new digest context
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    // Initialize the digest context for SHA-1
    if(!EVP_DigestInit(md, EVP_sha1()))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF]; // Buffer to hold data read from the file
    // Read the file in chunks and update the digest
    while((n_read = fread(buffer,1,MAXBUF,f_in)) > 0){
        if(!EVP_DigestUpdate(md, buffer, n_read))
            handle_errors();
    }

    unsigned char md_value[EVP_MD_size(EVP_sha1())]; // Buffer to hold the final digest value
    int md_len; // Variable to hold the length of the digest

    // Finalize the digest and retrieve the digest value
    if(!EVP_DigestFinal_ex(md, md_value, &md_len))
        handle_errors();

    // Free the digest context
    EVP_MD_CTX_free(md);

    // Print the digest in hexadecimal format
    printf("The digest is: ");
    for(int i = 0; i < md_len; i++)
        printf("%02x", md_value[i]);
    printf("\n");

    // Clean up the cipher data (deprecated since version 1.1.0)
    CRYPTO_cleanup_all_ex_data();
    // Remove error strings (deprecated since version 1.1.0)
    ERR_free_strings();

    return 0;
}