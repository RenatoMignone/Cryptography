#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h> //library for the error handling



// example usage of the tool: 
// ./enc_aes_arguments enc_aes_arguments.c 1234567890123456789012345678901212345678901234567890123456789012 1234567890123456789012345678901212345678901234567890123456789012

#define ENCRYPT 1
#define DECRYPT 0

#define MAX_SIZE 1024

//assume some new arguments from the terminal
// argv[1] --> input file
// argv[2] --> key   (hexstring)
// argv[3] --> IV    (hexstring)
// save in a buffer in memory the result of the enrtypted file


/*-----------------------------------------------------------*/
void handle_errors(){
    ERR_print_errors_fp(stderr); //fp is the file pointer, prints on the standard error
    abort();
}

/*-----------------------------------------------------------*/
int main(int argc, char **argv){

    //ADDEDD ERROR HANDLING NEEDED FOR ALL THE FUNCTIONS
    ERR_load_crypto_strings(); //initializes the error strings for all libcrypto functions
    OpenSSL_add_all_algorithms(); //registers all the algorithms

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // check if NULL


    //if the number of arguments is different from 4, we need to raise an error
    if(argc != 4){
        fprintf(stderr, "Usage: %s <input file> <key> <IV>\n", argv[0]);
        exit(1);
    }

    /*---------------------------------------------------------------------------------*/
    /*---------------------------- INPUT FILE HANDLING --------------------------------*/
    //we open the file in read mode
    FILE *file_input;

    if((file_input = fopen(argv[1], "r")) == NULL){
        fprintf(stderr, "Error opening the input file %s\n", argv[1]);
        exit(1);
    }


    /*---------------------------------------------------------------------------------*/
    /*-------------------------------- KEY HANDLING -----------------------------------*/
    //if differs from 32 hex characters, we need to raise an error
    if(strlen(argv[2])/2 != 32){
        fprintf(stderr, "The key must be 32 characters long\n");
        exit(1);
    }

    //we allocate a variable with half of the size of the hex string
    //so as much bytes as the half of the hex string (4 bit per char in hex)
    unsigned char key[strlen(argv[2])/2];

    //we do the conversion from the hex string to the binary key
    for(int i = 0; i < strlen(argv[2])/2; i++)
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);


    /*---------------------------------------------------------------------------------*/
    /*--------------------------------- IV HANDLING -----------------------------------*/
    //if differs from 32 hex characters, we need to raise an error
    if(strlen(argv[2])/2 != 32){
        fprintf(stderr, "The IV must be 32 characters long\n");
        exit(1);
    }

    //we allocate a variable with half of the size of the hex string
    //so as much bytes as the half of the hex string (4 bit per char in hex)
    unsigned char iv[strlen(argv[3])/2];

    //we do the conversion from the hex string to the binary iv
    for(int i = 0; i < strlen(argv[3])/2; i++)
        sscanf(&argv[3][2*i], "%2hhx", &iv[i]);

    /*---------------------------------------------------------------------------------*/
    /*---------------------------- ENCRYPTION HANDLING --------------------------------*/
    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT))
        handle_errors();

    
    int bytes_read;
    //where the input will be available
    unsigned char buffer[MAX_SIZE];
    //buffer to store the ciphertext
    unsigned char ciphertext[100 * MAX_SIZE];

    int len, ciphertext_len=0;

    while( (bytes_read = fread(buffer, 1, MAX_SIZE, file_input)) > 0 ){

        //if you risk to overflow the ciphertext variable, you exit with an error
        // the number of bytes read + the current length of the ciphertext should be less than 100 * MAX_SIZE - the size of the blocks that we are considering
        if(ciphertext_len + bytes_read > 100 * MAX_SIZE - EVP_CIPHER_CTX_block_size(ctx)){
            fprintf(stderr, "Error: ciphertext buffer too small\n");
            exit(1);
        }

        if(!EVP_CipherUpdate(ctx, ciphertext + ciphertext_len, &len, buffer, bytes_read))
            handle_errors();
        //since we are not reading only once this function, we need to adapt the code 
        //we are adding the value of the current bytes encyphered
        ciphertext_len += len;
        //in this way the next operation of the cipher update, will start from the last position
    }

    if(!EVP_CipherFinal(ctx, ciphertext + ciphertext_len, &len))
        handle_errors();

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);


    //print the length of the ciphertext
    printf("\nCiphertext length: %d\n", ciphertext_len);

    //print the result as a hex string
    for (int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);

    printf("\n");

    //CLEANUP OF THE ERRORS
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}