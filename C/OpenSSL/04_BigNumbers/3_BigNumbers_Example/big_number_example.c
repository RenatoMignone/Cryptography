#include <stdio.h>
#include <stdlib.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

/*-----------------------------------------------*/
void handle_errors(){
    printf("An error occurred\n");
    abort();
}

/*-----------------------------------------------*/
int main(){

    //ADDEDD ERROR HANDLING NEEDED FOR ALL THE FUNCTIONS
    ERR_load_crypto_strings(); //initializes the error strings for all libcrypto functions
    OpenSSL_add_all_algorithms(); //registers all the algorithms


    //let's consider the case in which we have a string which is a sequence of ASCII 
    //characters that represent a decimal number
    char num_string[] = "1234512345123451234512345123451234512346";

    //there is also a way to represent the hex string of a number
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    //we need to allocate the big numbers
    //this one allocates a new "object" so needs to be passed as a reference
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();




    printf("Generating a 1024-bit prime number...\n");
    /*
        int BN_generate_prime_ex(BIGNUM *ret, 
                                int bits, 
                                int safe, 
                                const BIGNUM *add, 
                                const BIGNUM *rem, 
                                BN_GENCB *cb
                                );
    */

    //the function to generate prime numbers
    //the first parameter is the number reference
    //the second parameter is the number of bits
    //a prime number is defined safe if these conditions are met:
        //(p-1)/2 is also prime
        //add, rem -->? p force the generation of the prime number, such that:
        //p % add == rem
        //if rem is NULL --> rem = 1
        //if rem is NULL and safe is true --> rem = 3 add must be a multiple of 4
    //the last parameter is the callback function
    if(!BN_generate_prime_ex(prime1, 1024, 0, NULL, NULL, NULL))
        handle_errors();

    printf("\nGenerated Prime Number (1024-bit):\n");
    BN_print_fp(stdout, prime1);
    puts("");



    printf("\nVerifying the primality of the generated number...\n");
    //we have some specific parameters that are needed to increase the number of checks
    //since the checks are statistics, there are number of iterations that are performed
    if(BN_is_prime_ex(prime1, 16, NULL, NULL))
        printf("it's a prime number\n");
    else
        printf("it's not a prime number\n");

    //in OPENSSL 3.0 the function BN_is_prime_ex is deprecated
    //the new function is BN_check_prime(prime1, ctx, callback);



    printf("\nTesting a non-prime number (16)...\n");
    //verify that if the number is not prime, the lib
    //has to be able to notice it
    //we do a test with a non prime number
    BN_set_word(prime2, 16);



    //we do the same check
    if(BN_is_prime_ex(prime2, 16, NULL, NULL))
        printf("it's a prime number\n");
    else
        printf("it's not a prime number\n");
    
    //the last thing is another function
    //this function returns the number of bytes that are needed to represent the number
    printf("\nByte representation sizes:\n");
    printf(" - Prime 1: %d bytes\n", BN_num_bytes(prime1));
    printf(" - Prime 2: %d bytes\n", BN_num_bytes(prime2));

    //this is important because we may have numbers that have at least the amount of required bits
    //but we need to know the exact numbers in some cases


    BN_free(prime1);
    BN_free(prime2);

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}