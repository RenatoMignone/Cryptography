/*

After Having executed this code, verify the signature with this command:

openssl dgst -sha256 -verify public.pem -signature signature.bin RSA_ds.c

*/


#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h> 
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define MAXBUFFER 1024

/*--------------------------------------------------------*/
void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/*--------------------------------------------------------*/
//argv[1] is the name of the file to sign
//argv[2] is the name of the file where the private key is stored

int main(int argc, char **argv){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();


    /*--------------------------------------------------------*/
    /*--------------------------------------------------------*/
    //check the number of arguments
    if(argc != 3){
        fprintf(stderr, "Usage: %s <file to sign> <private key>\n", argv[0]);
        return 1;
    }

    //file to sign
    FILE *f_in;
    if((f_in = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error reading the file\n");
        return 1;
    }

    //private key file
    FILE *f_key;
    if((f_key = fopen(argv[2], "r")) == NULL){
        fprintf(stderr, "Error reading the file\n");
        return 1;
    }

    /*--------------------------------------------------------*/
    /*--------------------------------------------------------*/
    //DigestSign interface --> EVP_PKEY 

    EVP_PKEY *private_key = PEM_read_PrivateKey(f_key, NULL, NULL, NULL);

    //we close the file of the key since we do not need it anymore
    fclose(f_key);

    EVP_MD_CTX *signature_ctx = EVP_MD_CTX_new();

    //the first parameter is the context
    //the third parameter is the algorithm to use
    if(!EVP_DigestSignInit(signature_ctx, NULL, EVP_sha256(), NULL, private_key))
        handle_errors();

    //we need to read from the file that we want to sign
    unsigned char buffer[MAXBUFFER];

    //we need to create a variable for the number of data read
    size_t n_read;

    //the 2 parameter is the number of elements
    while((n_read = fread(buffer, 1, MAXBUFFER, f_in)) > 0){
        //the first parameter is the context
        //the second parameter is the data to sign
        //the third parameter is the length of the data
        if(!EVP_DigestSignUpdate(signature_ctx, buffer, n_read))
            handle_errors();
    }

    fclose(f_in);

    //now we need to call the finalization function 2 times
    //the first to finalize the digest
    //the second one to compute the signature on the previously finalized digest

    //we create room to save the result
    //thanks to the EVP_PKEY we can know the size of the private key
    unsigned char signature[EVP_PKEY_size(private_key)];

    //we create space to store the length of the signature
    //and the length of the digest
    size_t sig_len;
    size_t dgst_len;

    //the first parameter is the context
    //we save the result in the dgst_len variable
    if(!EVP_DigestSignFinal(signature_ctx, NULL, &dgst_len))
        handle_errors();

    //then we call the function again to compute the signature
    //the second parameter is where we want to store the signature
    //the third parameter is the length of the signature 
    if(!EVP_DigestSignFinal(signature_ctx, signature, &sig_len))
        handle_errors();

    EVP_MD_CTX_free(signature_ctx);
    
    //we write the signature to a file
    FILE *f_out;
    if((f_out = fopen("signature.bin", "w")) == NULL){
        fprintf(stderr, "Error opening the signature file\n");
        exit(1);
    }

    if(fwrite(signature, 1, sig_len, f_out) < sig_len){
        fprintf(stderr, "Error writing the signature file\n");
        exit(1);
    }

    fclose(f_out);

    printf("Signature written to signature.bin\n");


    /*--------------------------------------------------------*/
    /*--------------------------------------------------------*/
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}    