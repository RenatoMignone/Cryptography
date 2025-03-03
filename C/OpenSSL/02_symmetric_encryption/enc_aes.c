#include <stdio.h>       
#include <string.h>      
#include <openssl/evp.h> // OpenSSL's high-level encryption library

#define ENCRYPT 1 // Used to specify encryption mode
#define DECRYPT 0 // Used to specify decryption mode

int main(){
    // Creates a new cipher context, which will be stored in memory as a new data structure
    //we can refere to this structure as a pointer in the memory
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Sample 16-byte key and IV (not recommended for production)
    unsigned char key[] = "1234567890abcdef";
    unsigned char iv[]  = "abcdef1234567890";

    // Initializes the AES-128-CBC cipher with the given key, IV, and mode
    //As we know, since we are using the cbc mode we need to provide the IV
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, ENCRYPT);

    // Plaintext to encrypt; length is 42 bytes (ASCII characters)
    unsigned char plaintext[] = "This variable contains the data to encrypt";
    // Buffer for the ciphertext; must hold the encrypted data plus potential padding
    unsigned char ciphertext[48];

    // 
    printf("\nPlaintext length: %lu", strlen(plaintext));

    int length;
    int ciphertext_len = 0;


    // Encrypts part (or all) of the plaintext
    EVP_CipherUpdate(
        ctx,              // A pointer to the cipher context (EVP_CIPHER_CTX *)
        ciphertext,       // Destination buffer for the encrypted/decrypted output
        &length,          // Receives the number of bytes written to ciphertext
        plaintext,        // Source buffer (plaintext or ciphertext)
        strlen(plaintext) // Number of bytes to process from plaintext
    );
    
    //Here the value stored will be the size of the data that was encrypted, without padding
    printf("\n\nAfter update, so after the initial encryption: %d", length);
    ciphertext_len += length;


    // Finalizes the encryption, handling any remaining data or padding
    // So the finalization is performed over the final block of the data
    // This means that if we do have some padding, it will be added here
    EVP_CipherFinal(
        ctx,                  // The cipher context used for the operation
        ciphertext + length,  // The buffer to write any remaining output or padding
        &length               // Receives the number of bytes written during finalization
    );
    
    //Now the value stored in this variable will be the length of the padding
    printf("\n\nAfter final, so after the adding of the padding: %d", length);
    ciphertext_len += length;

    // Frees the allocated cipher context
    EVP_CIPHER_CTX_free(ctx);

    // Prints total ciphertext length
    printf("\n\nSize of the ciphertext = %d\n", ciphertext_len);


    printf("\nHexadecimal representation of the ciphertext: ");

    // Prints the ciphertext bytes in hexadecimal
    //Since the result of the encryption is a binary data, we can print it in hexadecimal format
    //This is a common way to represent binary data in a human-readable way
    for(int i = 0; i < ciphertext_len; i++)
        printf("%02x", ciphertext[i]);
    printf("\n");

    printf("\n Binary representation of the ciphertext: ");

    for (int i = 0; i < ciphertext_len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            printf("%d", (ciphertext[i] >> bit) & 1);  // Extract and print each bit of the byte
        }
        printf(" ");  // Print a space between bytes for clarity
    }
    

    return 0;
}