#include <stdio.h>
#include <openssl/bn.h>


int main(){

    //we need to allocate the big numbers
    //this one allocates a new "object" so needs to be passed as a reference
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    //we can for examle print already the value of the big number generated.
    BN_print_fp(stdout, bn1);
    printf("\n");

    //now we want to give it a specific value
    //we can transform an unsigned long to a bignum
    BN_set_word(bn1, 12300000);
    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_set_word(bn2, 124);
    BN_print_fp(stdout, bn2);
    printf("\n");

    //to perform a basic operation like an addition
    //we allocate the space for the result
    BIGNUM *result = BN_new();
    BN_add(result, bn1, bn2);
    BN_print_fp(stdout, result);
    printf("\n");

    //for more sofisticated operation we need a context
    BN_CTX *ctx = BN_CTX_new();

    //we can now do some more sophisticated operations
    //here we are using the 2 bignumber as the modulus
    BN_mod(result, bn1, bn2, ctx);
    BN_print_fp(stdout, result);
    printf("\n");

    //we need to perform an additional check
    //in all the cases in which we have the big numbers
    //we need to free the memory
    BN_free(bn1);
    BN_free(bn2);
    BN_free(result);
    BN_CTX_free(ctx);



    return 0;
}