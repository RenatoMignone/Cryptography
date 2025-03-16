/*

You have found these data

00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:
eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:
03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:
fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:
42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:
fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:
3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:
9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:
5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:
b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:
d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:
c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:
30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51

00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:
6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:
2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:
49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:
ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:
7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:
64:33:05:11:fb:ee:8b:26:07

Find the other missing parameter using BIGNUM primitives (you 
may have to manipulate these data a bit before).

Use the same representation (with a ':' every two digits). Surround it with CRYPTO25{} t
o have your flag. Add leading zeros if needed to equalize parameters...


FLAG: 
CRYPTO25{00:c1:08:c9:57:09:e0:73:72:7d:b4:5e:4b:4b:20:bf:3c:
        57:41:bf:5c:bc:14:4d:a6:6a:bd:4d:86:69:06:9f:73:9d:40:2c:60:
        0f:29:7b:0b:4c:c7:7b:f6:5e:e5:a6:10:02:71:3e:74:a5:ac:b9:7f:
        f3:c5:78:42:ca:fe:50:6f:5b:1b:df:c7:ee:36:20:bb:56:73:ab:11:
        fa:e2:bf:a8:69:7d:e6:f4:5c:27:c1:21:69:3c:0e:1d:2d:dd:70:25:
        11:57:9f:8a:5a:60:58:09:90:5c:54:e0:55:2a:55:1c:e1:36:9d:14:
        70:ab:b4:e2:ce:c4:92:6b:fa:14:8f:e7}

*/


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <openssl/bn.h> 

/*
 * Function: remove_colons
 * -------------------------
 *   Removes all colon characters from a colon-separated hexadecimal string.
 *
 *   str: input colon-separated string (e.g., "00:ab:cd:ef")
 *
 *   returns: a new string containing the hex digits only (e.g., "00abcdef")
 */

char *remove_colons(const char *str) {
    size_t len = strlen(str);               // Get the length of the input string.
    char *result = malloc(len + 1);         // Allocate enough memory to hold the result (same length; colons are removed).
    if (!result) exit(1);                   // Exit if memory allocation fails.
    char *p = result;                       // Pointer to traverse and fill the result string.
    for (size_t i = 0; i < len; i++) {      // Loop through each character of the input string.
        if (str[i] != ':') {                // If the character is not a colon,
            *p++ = str[i];                  // copy it into the result.
        }
    }
    *p = '\0';                              // Null-terminate the result string.
    return result;                          // Return the new string without colons.
}

/*
 * Function: insert_colons
 * -------------------------
 *   Inserts a colon every two hex digits into a hexadecimal string.
 *
 *   hex_str: input string containing only hex digits (e.g., "00abcdef")
 *
 *   returns: a new string with colons inserted (e.g., "00:ab:cd:ef")
 */
char *insert_colons(const char *hex_str) {
    size_t len = strlen(hex_str);                      // Get the length of the hex string.
    size_t new_len = len + (len / 2 - 1) + 1;          // Calculate the new length:
                                                       //   - len: original hex digits,
                                                       //   - (len/2 - 1): number of colons to insert (one after every two digits, except before the first pair),
                                                       //   - +1 for the null terminator.
    char *result = malloc(new_len);                    // Allocate memory for the new string.
    if (!result) exit(1);                              // Exit if allocation fails.
    char *p = result;                                  // Pointer for writing into the result string.
    for (size_t i = 0; i < len; i += 2) {                // Process the string two hex digits at a time.
        if (i > 0) {
            *p++ = ':';                              // Insert a colon before every pair except the first.
        }
        *p++ = hex_str[i];                           // Copy the first hex digit of the pair.
        *p++ = hex_str[i+1];                         // Copy the second hex digit of the pair.
    }
    *p = '\0';                                       // Null-terminate the string.
    return result;                                   // Return the newly formatted string.
}

/*
 * Function: str_to_lower
 * -------------------------
 *   Converts all characters in a string to lowercase (in-place).
 *
 *   str: the string to be converted.
 */
void str_to_lower(char *str) {
    for (; *str; str++) {      // Loop through each character until the null terminator.
        *str = tolower(*str);  // Convert the character to lowercase.
    }
}

int main(void) {
    // Provided colon-separated hexadecimal strings.
    // n_str: the RSA modulus (2048-bit) with a leading zero to enforce positivity.
    // p_str: one of the prime factors (1024-bit) with a leading zero.
    const char *n_str = "00:9e:ee:82:dc:2c:d4:a0:0c:4f:5a:7b:86:63:b0:c1:ed:06:77:fc:eb:de:1a:23:5d:f4:c3:ff:87:6a:7d:ad:c6:07:fa:a8:35:f6:ae:05:03:57:3e:22:36:76:d5:0d:57:4f:99:f9:58:ad:63:7a:e7:45:a6:aa:fa:02:34:23:b6:9d:34:15:7b:11:41:b6:b1:ca:b9:1a:cd:29:55:bd:42:f5:04:ab:df:45:4a:9d:4e:ca:4e:01:f9:f8:74:59:67:ee:b6:a9:fb:96:b7:c0:94:00:17:8a:53:0e:b6:d8:31:c9:68:e6:64:38:d3:63:3a:04:d7:88:6b:f0:e1:ad:60:7f:41:bd:85:7b:d9:04:e1:97:5b:1f:9b:05:ce:ac:2c:c4:55:3f:b4:8b:89:4d:0a:50:9a:09:4e:5e:8f:5b:5f:55:69:72:5f:04:9b:3a:8a:09:b4:7f:8d:b2:ca:52:0e:5e:bf:f4:b0:ee:c9:ba:dc:93:4f:6d:d3:1f:82:1a:d9:fc:2c:a7:3f:18:23:0d:d7:44:c7:28:54:67:84:ee:73:92:65:f0:1c:e8:1e:6d:4d:95:65:b4:c8:4f:b8:04:62:58:2b:ee:32:64:a0:a7:dc:99:25:0e:50:53:76:bc:30:db:71:5e:93:d6:9f:1f:88:1c:76:5d:82:c8:59:39:51";
    const char *p_str = "00:d2:c6:01:32:6b:4c:4b:85:5f:52:7b:b7:8e:d6:8a:e4:c8:76:7e:6b:c9:24:9a:3e:ca:cd:2f:c9:b8:75:d4:f9:71:11:e1:cf:be:62:d3:2c:5f:f9:fd:9b:fa:ed:62:f3:df:44:c7:57:fb:ee:9b:b2:32:cb:54:49:29:6c:69:2e:30:1d:8c:1f:fa:b1:8e:e4:49:66:c1:fb:92:7c:82:ca:60:c9:40:a4:0a:b2:db:50:ec:f6:ff:98:a7:16:23:38:8d:06:d2:7c:a9:85:8a:c2:2b:4d:d4:e6:f1:89:e5:b0:42:54:a0:5f:3c:dd:c7:64:33:05:11:fb:ee:8b:26:07";

    // --- Step 1: Preprocess the Input Strings ---
    // Remove colons to get plain hexadecimal strings.
    char *n_hex = remove_colons(n_str);  // Now n_hex is a continuous hex string for n.
    char *p_hex = remove_colons(p_str);  // Now p_hex is a continuous hex string for p.

    // --- Step 2: Convert Hex Strings to BIGNUMs ---
    BIGNUM *n = NULL, *p = NULL, *q = BN_new();  // Create BIGNUM variables for n, p, and q.
    // Convert the colon-free hex strings into BIGNUM objects.
    BN_hex2bn(&n, n_hex);  // Convert n_hex into a BIGNUM (n).
    BN_hex2bn(&p, p_hex);  // Convert p_hex into a BIGNUM (p).

    // --- Step 3: Compute q = n / p using BIGNUM arithmetic ---
    BN_CTX *ctx = BN_CTX_new();  // Create a BN_CTX structure for temporary variables used by BN_div.
    BIGNUM *rem = BN_new();      // Create a BIGNUM to hold the remainder.
    
    // Perform the division: q = n / p and store the remainder in 'rem'.
    if (!BN_div(q, rem, n, p, ctx)) {
        fprintf(stderr, "Error during division\n");
        exit(1);
    }
    // Check that p divides n exactly (i.e., remainder is zero).
    if (!BN_is_zero(rem)) {
        fprintf(stderr, "Nonzero remainder: p does not exactly divide n.\n");
        exit(1);
    }

    // --- Step 4: Convert q to a Hex String and Format It ---
    // Convert the computed q to a hexadecimal string.
    char *q_hex = BN_bn2hex(q);  // q_hex now contains the hex representation of q.
    str_to_lower(q_hex);         // Convert the hex string to lowercase to match expected flag format.

    // The canonical representation must match p's length. Notice that p was given with a leading "00",
    // which means its colon-free hex string (p_hex) is 258 characters long. We must pad q_hex to 258 characters.
    int target_len = strlen(p_hex);  // Set target length equal to p_hex's length (likely 258).
    int q_len = strlen(q_hex);         // Current length of q_hex.

    
    char *q_hex_padded = malloc(target_len + 1);  // Allocate memory for the padded q_hex.
    if (!q_hex_padded) exit(1);
    memset(q_hex_padded, '0', target_len);  // Fill the entire string with '0' characters.
    q_hex_padded[target_len] = '\0';          // Null-terminate the padded string.
    if (q_len < target_len) {
        // If q_hex is shorter than target_len, copy it to the rightmost part, leaving leading zeros.
        memcpy(q_hex_padded + (target_len - q_len), q_hex, q_len);
    } else {
        // Otherwise, if it's already target length (or longer), copy the first target_len characters.
        strncpy(q_hex_padded, q_hex, target_len);
    }
    
    // Reinsert colons every two hex digits to match the original representation.
    char *formatted_q = insert_colons(q_hex_padded);

    // --- Step 5: Output the Flag ---
    // Wrap the formatted q in CRYPTO25{...} as specified by the challenge.
    printf("CRYPTO25{%s}\n", formatted_q);

    // --- Step 6: Cleanup ---
    // Free all allocated memory and BIGNUMs.
    BN_free(n);           // Free the BIGNUM for n.
    BN_free(p);           // Free the BIGNUM for p.
    BN_free(q);           // Free the BIGNUM for q.
    BN_free(rem);         // Free the BIGNUM for the remainder.
    BN_CTX_free(ctx);     // Free the BN_CTX structure.

    free(n_hex);          // Free the colon-free string for n.
    free(p_hex);          // Free the colon-free string for p.
    free(q_hex_padded);   // Free the padded q hex string.
    free(formatted_q);    // Free the final formatted string with colons.

    return 0;  // End the program successfully.
}
