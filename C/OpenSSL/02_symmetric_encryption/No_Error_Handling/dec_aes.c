#include <stdio.h>        
#include <string.h>       
#include <openssl/evp.h>  // OpenSSL's high-level encryption library

#define ENCRYPT 1  // Used to specify encryption mode
#define DECRYPT 0  // Used to specify decryption mode

int main(){
    // Creates a new cipher context, stored in memory as a pointer
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Key and IV must match what was used for encryption
    // We assume that the key and IV are known to the decryptor, by means of some exchange
    unsigned char key[] = "1234567890abcdef";  // 16-byte key (example only)
    unsigned char iv[]  = "abcdef1234567890";  // 16-byte IV (example only)

    // Hex-encoded ciphertext from the encryption process (enc_aes.c file execution)
    // Here the C compiler does not knows if this is a string of ASCIIs or of HEX values, so it depends on how we treat the data itself.
    // For example here we know that this string is made of hex values, so 4 bits each, so we can treat it as a string of hex values 
    unsigned char ciphertext[] = "13713c9b8081468892c518592730b3496d2c58ed3a9735d90788e7c24e8d324d75f6c9f5c6e43ee7dccad4a3221d697e";

    // Initializes the AES-128-CBC cipher for decryption, with the specified key and IV
    // Here instead of putting the encryption mode, we put the decryption one
    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, iv, DECRYPT);

    // Buffer to store the decrypted text (worst case: same as ciphertext length)
    // The reason for using strlen(ciphertext)/2 to define the size of the plaintext array 
    // is because the ciphertext is stored as a hexadecimal string, and each byte of actual binary data is represented by two hex characters.
    // Since the characters are in HEXADECIMAL, and each HEXADECIMAL char is 4 bit, 2 of them are needed to represent a byte (8 bits)
    unsigned char plaintext[strlen(ciphertext)/2];

    // Buffer to hold the binary form of the hexadecimal ciphertext
    unsigned char ciphertext_bin[strlen(ciphertext)/2];

    printf("\nOriginal (hex) ciphertext: %s", ciphertext);
    printf("\n\nNumber of hex characters: %lu", strlen(ciphertext));

    // Converts every pair of hex characters into a byte and stores it in ciphertext_bin
    // The sscanf function reads formatted input from a string, in this case, the ciphertext
    // The %2hhx format specifier reads two hexadecimal characters and stores them in a char variable
    // The loop runs for half the length of the ciphertext, since each byte is represented by two hex characters
    // and since we read two characters at a time, we only need to read half the length of the ciphertext
    for(int i = 0; i < strlen(ciphertext)/2; i++)
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);

    
    // Temporary variables for tracking the number of bytes processed
    int length;
    int plaintext_len = 0;

    // Decrypts the data; writes the result to plaintext and updates 'length' with the bytes produced
    EVP_CipherUpdate(
        ctx,                  // The cipher context
        plaintext,            // Destination buffer for decrypted data
        &length,              // Number of bytes written to 'plaintext'
        ciphertext_bin,       // Source buffer (encrypted data in binary form)
        strlen(ciphertext)/2  // Number of bytes to decrypt
    );

    // Shows how many bytes were decrypted in 'update'
    printf("\n\nAfter update (bytes decrypted so far): %d", length);
    plaintext_len += length;

    // Finalizes decryption, handling any leftover data or padding
    EVP_CipherFinal(
        ctx,                  // The cipher context
        plaintext + length,   // Write any final bytes or padding after the current plaintext offset
        &length               // Number of bytes produced during finalization
    );

    // Shows how many bytes were decrypted in 'final'
    printf("\n\nAfter final (additional bytes decrypted): %d", length);
    plaintext_len += length;

    // Cleans up the cipher context
    EVP_CIPHER_CTX_free(ctx);

    // Ensures the decrypted string is null-terminated
    plaintext[plaintext_len] = '\0';

    // Prints the size of the decrypted text
    printf("\n\nTotal decrypted bytes: %d", plaintext_len);

    // Prints the decrypted text
    printf("\n\nDecrypted plaintext: %s\n", plaintext);

    return 0;
}