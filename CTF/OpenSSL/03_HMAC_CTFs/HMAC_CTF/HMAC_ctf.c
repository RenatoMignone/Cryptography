/*

Write a program that computes the HMAC-SHA256 of two files whose names are 
passed as parameters from the command line (start from HMAC_computation_EVP).

The flag is obtained as

CRYPTO25{hmac}

where hmac is obtained using the secret "keykeykeykeykeykey" and the two files 
attached to this challenge (and hexdigits in lowercase):

hmac = hex(HMAC-SHA256("keykeykeykeykeykey", file,file2))

where "keykeykeykeykeykey" is an ASCII string (no quotation marks)



FLAG = CRYPTO25{9453ac565269a96ea3ea583b15b410111b42ae03d1054a02fe4ba4b1029734d3}
*/

/*

   IN order to achieve this objective here, we start defining the key to 
   asign to the HMAC-SHA256 protocol. In the beginning of the code in fact
   after having read the single files, we give the key to the algorithm.

   The professor here is asking to compute so the HMAC-SHA256 over this value:
   "file1 | file2", so we do not need to include the key itself also in the computation
   because it is already defined in the algorithm structure

*/


/*=======================================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>

// Define the maximum buffer size for reading the file
#define MAXBUF 1024 

/*=======================================================================*/
// Function to handle errors by printing them and aborting the program.
// This is triggered if an OpenSSL function fails.
void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

/*=======================================================================*/
int main(int argc, char **argv){
    // We expect exactly two file names as parameters.
    if(argc != 3){
        fprintf(stderr, "Invalid parameters. Usage: %s <file1> <file2>\n", argv[0]);
        exit(1);
    }

    FILE *f1, *f2;
    // Open the first file in binary mode. Exit if it fails.
    if((f1 = fopen(argv[1], "rb")) == NULL) {
        fprintf(stderr, "Couldn't open the first file, try again\n");
        exit(1);
    }
    // Open the second file in binary mode. Exit if it fails.
    if((f2 = fopen(argv[2], "rb")) == NULL) {
        fprintf(stderr, "Couldn't open the second file, try again\n");
        fclose(f1);
        exit(1);
    }

    /*=======================================================================*/
    // Load human-readable error strings for libcrypto.
    ERR_load_crypto_strings();
    // Load all digest and cipher algorithms.
    OpenSSL_add_all_algorithms();

    /*=======================================================================*/
    // Secret key (ASCII string)
    unsigned char key[] = "keykeykeykeykeykey";
    // Create an EVP_PKEY structure for the HMAC key using the secret.
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen((char*)key));
    if (!hmac_key) {
        fprintf(stderr, "Error creating HMAC key\n");
        exit(1);
    }
    
    /*=======================================================================*/
    // Create a new message digest context for HMAC operations.
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new();
    if (!hmac_ctx) {
        fprintf(stderr, "Error creating HMAC context\n");
        exit(1);
    }

    /*=======================================================================*/
    // Initialize the HMAC context with SHA-256.
    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha256(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    
    /*=======================================================================*/
    // Process the first file:
    // Read the file in chunks and update the HMAC.
    while ((n_read = fread(buffer, 1, MAXBUF, f1)) > 0) {
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f1); // Close the first file.

    /*=======================================================================*/
    // Process the second file:
    // Read the file in chunks and update the HMAC.
    while ((n_read = fread(buffer, 1, MAXBUF, f2)) > 0) {
        if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }
    fclose(f2); // Close the second file.

    /*=======================================================================*/
    // Finalize the HMAC computation
    // Buffer to store the HMAC result. Its size is determined by SHA-256.
    unsigned char hmac_value[EVP_MD_size(EVP_sha256())];
    // Use size_t for hmac_len as required by EVP_DigestSignFinal.
    // Initialize hmac_len to the size of the hmac_value buffer.
    size_t hmac_len = sizeof(hmac_value);

    // Finalize the HMAC computation and store the result in hmac_value.
    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    // Free the HMAC context.
    EVP_MD_CTX_free(hmac_ctx);

    /*=======================================================================*/
    // Print the computed HMAC in a readable hexadecimal format as the flag.
    // The flag format is: CRYPTO25{<hmac>}
    printf("CRYPTO25{");
    for (size_t i = 0; i < hmac_len; i++){
        printf("%02x", hmac_value[i]);
    }
    printf("}\n");

    /*=======================================================================*/
    // Clean-up operations:
    // Clean up the cipher data and error strings.
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    // Free the EVP_PKEY structure used for the HMAC key.
    EVP_PKEY_free(hmac_key);

    return 0;
}
