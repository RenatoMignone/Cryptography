## Challenge Description

This challenge presents a cryptographic oracle that, for each round, randomly selects either AES-ECB or AES-CBC mode with a random key and (for CBC) a random IV. For each challenge, the user is allowed to submit two plaintexts (as hex strings), which are first XORed with a random one-time pad (OTP) and then encrypted. After both ciphertexts are returned, the user must guess which mode was used. If all rounds are guessed correctly, the flag is revealed.

## Attack Used

The attack is a **chosen-plaintext mode-distinguishing attack**. Normally, ECB and CBC can be distinguished by submitting identical plaintexts and checking if the ciphertexts are also identical (which only happens in ECB). However, in this challenge, the plaintext is XORed with a random OTP before encryption, so submitting the same input twice results in different actual plaintexts being encrypted each time.

## Solution Approach

Despite the OTP, the solution leverages the fact that the OTP is fixed for both queries in a single round. By submitting the same input twice, the actual plaintexts being encrypted are different but related in a way that prevents the standard ECB-vs-CBC distinguishing attack from working directly. However, if the implementation had not used the OTP, the attack would work as follows:

1. Submit the same plaintext twice.
2. If the ciphertexts are identical, the mode is ECB; otherwise, it's CBC.

In this challenge, the provided solution script attempts this attack by sending two identical inputs and comparing the outputs. If the OTP were not present, this would reliably distinguish the modes. The script automates this process for all rounds.

## Vulnerability Exploited

The vulnerability (in the absence of the OTP) is that ECB mode is deterministic for identical plaintext blocks, while CBC mode is randomized due to the IV. This allows an attacker to distinguish the mode by observing ciphertext patterns. The challenge demonstrates the importance of using randomization (like IVs or OTPs) to prevent such attacks.

## Summary

- **What does the challenge do?**  
  It asks the user to distinguish between AES-ECB and AES-CBC encryption modes, given two encryptions per round, with a random OTP applied to the plaintexts.

- **How has it been solved?**  
  By submitting identical inputs and comparing the ciphertexts, the script attempts to distinguish the mode, exploiting the deterministic nature of ECB (if not for the OTP).

- **Which attack was used?**  
  A chosen-plaintext mode-distinguishing attack, commonly used to differentiate ECB from CBC.

- **How was the vulnerability exploited?**  
  By leveraging the fact that ECB produces identical ciphertexts for identical plaintexts, the script can identify the mode unless a randomization step (like the OTP) is present.

