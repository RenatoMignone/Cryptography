#include <stdio.h>
#include <openssl/bn.h>


int main(){

    //let's consider the case in which we have a string which is a sequence of ASCII 
    //characters that represent a decimal number
    char num_string[] = "1234512345123451234512345123451234512346";

    //there is also a way to represent the hex string of a number
    char hex_string[] = "3A0BE6DE14A23197B6FE071D5EBBD6DD9";

    //we need to allocate the big numbers
    //this one allocates a new "object" so needs to be passed as a reference
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();


    //if we want to convert a string to a big number we can use the following function
    //the first parameter is the address of the big number
    //the second parameter is the string that we want to convert
    BN_dec2bn(&bn1, num_string);
    BN_print_fp(stdout, bn1);
    printf("\n");

    //here we are converting a hex string to a big number
    BN_hex2bn(&bn2, hex_string);
    BN_print_fp(stdout, bn2);
    printf("\n");

    //the function for the comparison
    //returns 0 if the numbers are equal
    //returns 1 if the first number is greater
    //returns -1 if the second number is greaters
    if(BN_cmp(bn1, bn2) == 0)
        printf("bn1 and bn2 are equal\n");
    else
        printf("bn1 and bn2 are different\n");


    //we can also use the inverse operation 
    //these are other wayt to print the big number
    //the first one is in hex and the second one is in decimal
    printf("bn1 = %s\n", BN_bn2hex(bn1));
    printf("bn1 = %s\n", BN_bn2dec(bn1));


    BN_free(bn1);
    BN_free(bn2);



    return 0;
}