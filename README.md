# Ex-12---ELGAMAL-ALGORITHM

# AIM:
To encrypt and decrypt a message usinp the ElGamal encryption algorithm.

# ALGORITHM:
Choose a large prime number p and a generator g of the multiplicative group of integers modulo
p. Alice chooses a private key and computes her public key as pubIic_key = g ^private_key mod p. To encrypt a message, Bob chooses a random number k and computes a ciphertext pair (c1, c2). To decrypt the message, Alice uses her private key and computes the original message. The decrypted message is verified to be the same as the original.

# PROGRAM:
~~~c
#include <stdio.h>
#include <math.h>

// Function to compute modular exponentiation (base^exp % mod)
long long int modExp(long long int base, long long int exp, long long int mod) {
    long long int result = 1;
    while (exp > 0) {
        if (exp % 2 == 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp = exp / 2;
    }
    return result;
}

int main() {
    long long int p, g, privateKeyA, publicKeyA;
    long long int k, message, c1, c2, decryptedMessage;

    // Step 1: Input a large prime number (p) and a generator (g)
    printf("Enter a large prime number (p): ");
    scanf("%lld", &p);
    printf("Enter a generator (g): ");
    scanf("%lld", &g);

    // Step 2: Alice inputs her private key
    printf("Enter KISHOR's private key: ");
    scanf("%lld", &privateKeyA);

    // Step 3: Compute Alice's public key (public_key = g^privateKeyA mod p)
    publicKeyA = modExp(g, privateKeyA, p);
    printf("Alice's public key: %lld\n", publicKeyA);

    // Step 4: Bob inputs the message to be encrypted and selects a random k
    printf("Enter the message to encrypt (as a number): ");
    scanf("%lld", &message);
    printf("Enter a random number k: ");
    scanf("%lld", &k);

    // Step 5: Bob computes ciphertext (c1 = g^k mod p, c2 = (message * publicKeyA^k) mod p)
    c1 = modExp(g, k, p);
    c2 = (message * modExp(publicKeyA, k, p)) % p;
    printf("Encrypted message (c1, c2): (%lld, %lld)\n", c1, c2);

    // Step 6: Alice decrypts the message (decryptedMessage = (c2 * c1^(p-1-privateKeyA)) % p)
    decryptedMessage = (c2 * modExp(c1, p - 1 - privateKeyA, p)) % p;
    printf("Decrypted message: %lld\n", decryptedMessage);

    return 0;
}



~~~

# OUTPUT:
![Screenshot 2024-11-11 082106](https://github.com/user-attachments/assets/9922faf5-7d4b-4c94-9810-9cc58a59f55c)


# RESULT:
The program for ElGamal encryption and decryption was executed successfully. Alice and Bob exchanged an encrypted message and verified that the decrypted message matched the original message.
