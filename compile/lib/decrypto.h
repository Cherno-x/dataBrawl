#pragma once
#include<Windows.h>


void rc4Decrypt(unsigned char* ciphertext, int ciphertextLength, unsigned char* key, int keyLength) {
    unsigned char S[256];
    for (int i = 0; i < 256; ++i) {
        S[i] = i;
    }

    int j = 0;
    for (int i = 0; i < 256; ++i) {
        j = (j + S[i] + key[i % keyLength]) % 256;
        std::swap(S[i], S[j]);
    }

    int i = 0;
    j = 0;
    for (int k = 0; k < ciphertextLength; ++k) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        int t = (S[i] + S[j]) % 256;
        ciphertext[k] ^= S[t];
    }
}

void XOR(char* data, int len, unsigned char key) {
    int i;
    for (i = 0; i < len; i++)
        data[i] ^= key;
}