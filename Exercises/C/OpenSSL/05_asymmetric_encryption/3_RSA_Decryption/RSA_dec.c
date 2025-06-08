#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h> 
#include <string.h>
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


    /*------------------------------------------------------------*/
    /*------------------------------------------------------------*/
    //create the message to encrypt.
    unsigned char message[] = "This is the message to encrypt\n";

    //The maximum amount of data that can be encrypted with RSA 
    //is the key size in bytes minus 41, or 11, which is the padding size

    //we allocate room to save the encrypted message
    //we need to allocate as many bits as the final key size
    unsigned encrypted_message[RSA_size(rsa_keypair)];

    //since the function under will return the length of the encrypted message
    //we need to store it
    int encrypted_length;


    //the function to perform the encryption
    if( (encrypted_length = RSA_public_encrypt(strlen(message),                 //this one is the length of the message to enc
                                                      message,                  //the second parameter is the message
                                                      encrypted_message,        //this one is the variable that we allocated to store the enc message
                                                      rsa_keypair,              //the key that we are going to use. This function is able to take from this data structure the public key
                                                      RSA_PKCS1_OAEP_PADDING)   //this field is the padding. The most used is RSA_PKCS1_PADDING
        ) ==-1)
        handle_errors();


    //we need to create a file to store the encrypted message
    FILE *out;

    //we open the file in write mode
    if((out = fopen("encrypted.enc", "w")) == NULL){
        fprintf(stderr, "Error generating the file\n");
        abort();
    }

    //we write the encrypted message to the file
    if(fwrite(encrypted_message, 1, encrypted_length, out) < encrypted_length){
        fprintf(stderr, "Error writing the file\n");
        abort();
    }

    fclose(out);

    //we print a message to the user
    printf("The message was encrypted successfully\n");


    /*------------------------------------------------------------*/
    /*------------------------------------------------------------*/
    //now we want to decrypt the message


    printf("Reading the encrypted file...\n");

    //we need to create a file to store the encrypted message
    FILE *in;

    //we open the file in write mode
    if((in = fopen("encrypted.enc", "r")) == NULL){
        fprintf(stderr, "Error reading the file\n");
        abort();
    }

    //the encrypted_message can be used again, so we reuse it
    //here we expect as many data as the value of RSA_size(rsa_keypair)
    if( ( encrypted_length = fread(encrypted_message, 1, RSA_size(rsa_keypair), in)) != RSA_size(rsa_keypair)){
        handle_errors();
    }
    fclose(in);

    //now we need to reserve space for the decrypted message
    unsigned char decprypted_message[RSA_size(rsa_keypair)];

    //we need to decrypt the message
    if(RSA_private_decrypt(encrypted_length,       //the length of the encrypted message
                        encrypted_message,      //the encrypted message
                        decprypted_message,     //the variable to store the decrypted message
                        rsa_keypair,            //the key to use, in this case the private key
                        RSA_PKCS1_OAEP_PADDING  //the padding to use, in this case the same as the encryption
    ) == -1)
        handle_errors();

    printf("\nThe decrypted message is: %s\n", decprypted_message);
    


    /*------------------------------------------------------------*/
    /*------------------------------------------------------------*/

    RSA_free(rsa_keypair);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    
    return 0;
}