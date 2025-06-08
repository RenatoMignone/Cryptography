#include <stdio.h>
//OpenSSL headers
#include <openssl/rand.h>      // Provides RAND_load_file, RAND_bytes
#include <openssl/err.h>       // Provides ERR_print_errors_fp

/*-----------------------------------------------*/

#define MAX 128

/*-----------------------------------------------*/
void handleErrors(void)
{
    ERR_print_errors_fp(stderr); // Prints the detailed error messages from OpenSSL
    abort();                     // Terminates the program in case of errors
}

/*-----------------------------------------------*/
int main()
{
    unsigned char random_string[MAX];

    // RAND_load_file loads entropy from /dev/random 
    // Returns the number of bytes read, or -1 on error.
    // We check if it equals 64 to confirm success.
    if (RAND_load_file("/dev/random", 64) != 64)
        handleErrors();

    // RAND_bytes generates cryptographically strong pseudo-random bytes.
    // Returns 1 on success, 0 otherwise.
    if (RAND_bytes(random_string, MAX) != 1)
        handleErrors();

    printf("Sequence generated: ");

    for (int i = 0; i < MAX; i++)
        // Print the random string in hexadecimal format, just the first 2 characters
        printf("%02x-", random_string[i]); 

    printf("\n");

    return 0;
}
/*-----------------------------------------------*/