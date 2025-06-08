#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>


#include <openssl/pem.h>


void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    //we first need to create space for RSA structure
    //this data structure is defined as a collection of BigNums
    RSA *rsa_keypair;

    //Big number public exponent
    BIGNUM *bne = BN_new();
    
    //the most used public parameters are 3,17,65537
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();

    //we need to create the RSA structure
    rsa_keypair = RSA_new();

    //the second parameter is the num of bits
    //the third and fourth parameters are the public exponent and the callback
    //the result keys will be stored in rsa_keypair structure
    if(!RSA_generate_key_ex(rsa_keypair, 2048, bne, NULL))
        handle_errors();



        
    //we need to create a file to store the keys
    FILE *rsa_file;
    
    if((rsa_file = fopen("private.pem", "w")) == NULL){
        fprintf(stderr, "Error generating the file\n");
        handle_errors();
    }

    //we need to write the private key to the file
    //the first parameter is the file pointer
    //then the rsa structure
    //the third parameter is the encryption algorithm
    //the fourth parameter is the password
    //the fifth parameter is the password length
    //the sixth parameter is the callback
    //the seventh parameter is the callback argument
    if(!PEM_write_RSAPrivateKey(rsa_file, rsa_keypair, NULL, NULL, 0, NULL, NULL))
        handle_errors();

    fclose(rsa_file);


    //now we do the same but with the public key
    if((rsa_file = fopen("public.pem", "w")) == NULL){
        fprintf(stderr, "Error generating the file\n");
        handle_errors();
    }

    if(!PEM_write_RSAPublicKey(rsa_file, rsa_keypair))
        handle_errors();
    
    fclose(rsa_file);






    RSA_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}