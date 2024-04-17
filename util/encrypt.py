
def xor_encrypt(hex_strings, key):
    encrypted_hex_array = []
    for hex_string in hex_strings:
        num = int(hex_string, 16)
        for k in key:
            num ^= int(k, 16) 
        encrypted_hex_array.append(hex(num))
    return encrypted_hex_array


def xor_encrypt_bytes(bytes_array, key):
    encrypted_data = bytearray()
    key_index = 0
    for byte in bytes_array:
        encrypted_byte = byte ^ key[key_index]
        encrypted_data.append(encrypted_byte)
        key_index = (key_index + 1) % len(key)

    return encrypted_data

def KSA(key):
    key_length = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        yield S[(S[i] + S[j]) % 256]

def rc4enc(plaintext, key):
    S = KSA(key)
    keystream = PRGA(S)
    ciphertext = bytearray()
    for byte in plaintext:
        ciphertext.append(byte ^ next(keystream))
    return bytes(ciphertext)



