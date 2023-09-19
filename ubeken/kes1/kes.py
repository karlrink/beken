#!/usr/bin/env python3


import base64


def xor_encrypt(plainText, keyStr):

    # Encode the plaintext to bytes using UTF-8
    plaintext_bytes = plainText.encode('utf-8')

    encrypted_data = []
    key_length = len(keyStr)

    for i, byte in enumerate(plaintext_bytes):
        key_byte = encryption_key[i % key_length]
        encrypted_byte = (byte ^ ord(key_byte))  # Use XOR for encryption
        encrypted_data.append(encrypted_byte)

    # Convert the encrypted bytes to a base64 encoded string
    encrypted_base64 = base64.b64encode(bytes(encrypted_data)).decode('utf-8')

    return encrypted_base64


def xor_decrypt(base64Cipher, keyStr):

    # Decode the base64-encoded ciphertext to bytes
    encrypted_bytes = base64.b64decode(base64Cipher)

    decrypted_data = []
    key_length = len(keyStr)

    for i, byte in enumerate(encrypted_bytes):
        key_byte = encryption_key[i % key_length]
        decrypted_byte = (byte ^ ord(key_byte))  # Use XOR for decryption
        decrypted_data.append(decrypted_byte)

    # Convert the decrypted bytes to a UTF-8 string
    decrypted_text = bytes(decrypted_data).decode('utf-8')
    
    return decrypted_text


def vigenere_encrypt(plainText, keyStr):
    # Encode the plaintext to bytes using UTF-8
    plaintext_bytes = plainText.encode('utf-8')

    encrypted_data = []
    key_length = len(keyStr)

    for i, byte in enumerate(plaintext_bytes):
        key_byte = keyStr[i % key_length]
        encrypted_byte = (byte + ord(key_byte)) % 256  # Use Vigenère encryption
        encrypted_data.append(encrypted_byte)

    # Convert the encrypted bytes to a hexadecimal string
    encrypted_hex = ''.join(format(byte, '02x') for byte in encrypted_data)

    return encrypted_hex


def vigenere_decrypt(hexCipher, keyStr):
    # Convert the hexadecimal string to bytes
    encrypted_bytes = bytes.fromhex(hexCipher)
    decrypted_data = []

    key_length = len(keyStr)

    for i, byte in enumerate(encrypted_bytes):
        key_byte = keyStr[i % key_length]
        decrypted_byte = (byte - ord(key_byte)) % 256  # Use Vigenère decryption
        decrypted_data.append(decrypted_byte)

    # Convert the decrypted bytes to a UTF-8 string
    decrypted_text = bytes(decrypted_data).decode('utf-8')

    return decrypted_text


def encrypt_rail_fence(plainText, num_rails):

    # Base64 encode the plaintext
    encoded_plaintext = base64.b64encode(plainText.encode()).decode()

    # Initialize the rails as empty strings
    rails = [''] * num_rails

    # Fill the rails with the message characters
    rail_index = 0
    direction = 1  # Direction: 1 for down, -1 for up

    for char in encoded_plaintext:
        rails[rail_index] += char

        # Change direction if we reach the top or bottom rail
        if rail_index == 0:
            direction = 1
        elif rail_index == num_rails - 1:
            direction = -1

        # Move to the next rail
        rail_index += direction

    # Concatenate the rails to create the ciphertext
    ciphertext = ''.join(rails)

    # Base64 encode the ciphertext
    base64Cipher = base64.b64encode(ciphertext.encode()).decode()

    return base64Cipher

def decrypt_rail_fence(base64Cipher, num_rails):

    # Decode the base64-encoded ciphertext
    ciphertext = base64.b64decode(base64Cipher.encode()).decode()

    # Create a matrix to represent the rails
    rails = [['' for _ in range(len(ciphertext))] for _ in range(num_rails)]

    # Fill the matrix with placeholder characters
    for i in range(num_rails):
        for j in range(len(ciphertext)):
            rails[i][j] = ' '

    # Fill the matrix with the ciphertext characters
    rail_index = 0
    direction = 1

    for i in range(len(ciphertext)):
        rails[rail_index][i] = '*'

        if rail_index == 0:
            direction = 1
        elif rail_index == num_rails - 1:
            direction = -1

        rail_index += direction

    # Fill the matrix with the ciphertext characters
    index = 0
    for i in range(num_rails):
        for j in range(len(ciphertext)):
            if rails[i][j] == '*' and index < len(ciphertext):
                rails[i][j] = ciphertext[index]
                index += 1

    # Read the matrix to obtain the plaintext
    plaintext = ''
    rail_index = 0
    direction = 1

    for i in range(len(ciphertext)):
        plaintext += rails[rail_index][i]

        if rail_index == 0:
            direction = 1
        elif rail_index == num_rails - 1:
            direction = -1

        rail_index += direction

    # Decode the base64-encoded plaintext
    decoded_plaintext = base64.b64decode(plaintext.encode()).decode()

    return decoded_plaintext



def encryptKES(plainTxt, keyStr):

    # Determine the order of encryption based on the encryption key
    order = sum(ord(char) for char in keyStr) % 2  # 2 encryption options

    # Step 1: Encrypt using Rail Fence
    rail_fence_encrypted = encrypt_rail_fence(plainTxt, len(keyStr))

    if order == 0:
        # Step 2: XOR encrypt
        xor_encrypted = xor_encrypt(rail_fence_encrypted, keyStr)

        # Step 3: Vigenere encrypt
        encrypted = vigenere_encrypt(xor_encrypted, keyStr)
    else:
        # Step 2: Vigenere encrypt
        vigenere_encrypted = vigenere_encrypt(rail_fence_encrypted, keyStr)

        # Step 3: XOR encrypt
        encrypted = xor_encrypt(vigenere_encrypted, keyStr)

    # Convert the encrypted data to a base64 encoded string
    encrypted_base64 = base64.b64encode(encrypted.encode('utf-8')).decode('utf-8')

    return encrypted_base64


def decryptKES(base64Cipher, keyStr):

     # Decode the base64-encoded ciphertext to a string
    base64_decrypted = base64.b64decode(base64Cipher).decode('utf-8')

    # Determine the order of encryption based on the encryption key
    order = sum(ord(char) for char in keyStr) % 2  # 2 encryption options

    if order == 0:
        # Step 3: Vigenere decrypt
        vigenere_decrypted = vigenere_decrypt(base64_decrypted, keyStr)

        # Step 2: XOR decrypt
        decrypted = xor_decrypt(vigenere_decrypted, keyStr)

    else:
        # Step 3: XOR decrypt
        xor_decrypted = xor_decrypt(base64_decrypted, keyStr)

        # Step 2: Vigenere decrypt
        decrypted = vigenere_decrypt(xor_decrypted, keyStr)


    # Step 1: Decrypt using Rail Fence
    plainTxt = decrypt_rail_fence(decrypted, len(keyStr))

    return plainTxt



# Encryption Key
encryption_key = "KEY321"  # Example key, should be kept secret

# Sample data to encrypt
plaintext = "Hello, World! KES"

print("Original Data:", plaintext)

# Encrypt/Decrypt the data

print("XOR")
encrypted_data = xor_encrypt(plaintext, encryption_key)
print("Encrypted Data:", encrypted_data)
decrypted_data = xor_decrypt(encrypted_data, encryption_key)
print("Decrypted Data:", decrypted_data)

print("VIGENERE")
encrypted_data = vigenere_encrypt(plaintext, encryption_key)
print("Encrypted Data:", encrypted_data)
decrypted_data = vigenere_decrypt(encrypted_data, encryption_key)
print("Decrypted Data:", decrypted_data)

print("RAILFENCE")
#encrypted_data = encrypt_rail_fence(plaintext, 3)
encrypted_data = encrypt_rail_fence(plaintext, len(encryption_key))
print("Encrypted Data:", encrypted_data)
#decrypted_data = decrypt_rail_fence(encrypted_data, 3)
decrypted_data = decrypt_rail_fence(encrypted_data, len(encryption_key))
print("Decrypted Data:", decrypted_data)


print("KES")
encrypted_data = encryptKES(plaintext, encryption_key)
print("Encrypted Data:", encrypted_data)
decrypted_data = decryptKES(encrypted_data, encryption_key)
print("Decrypted Data:", decrypted_data)


