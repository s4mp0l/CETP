import sys
import os

def file_to_xor_cpp(input_file, output_file, array_name, key_size=16):
    with open(input_file, 'rb') as f:
        data = f.read()

    # Generate a cryptographically random key
    key = os.urandom(key_size)

    # Encrypt data using cyclic XOR
    encrypted_data = bytearray()
    for i, byte in enumerate(data):
        encrypted_data.append(byte ^ key[i % key_size])

    with open(output_file, 'w') as f:
        f.write(f'// Auto-generated XOR encrypted array from {input_file}\n')
        f.write(f'// Size: {len(data)} bytes | Key Size: {key_size} bytes\n\n')
        f.write('#ifndef PAYLOAD_H\n#define PAYLOAD_H\n\n')
        f.write('#include <stddef.h>\n\n')

        # XOR Key
        f.write(f'// XOR decryption key\n')
        f.write(f'unsigned char {array_name}_key[] = {{\n    ')
        for i, byte in enumerate(key):
            if i > 0 and i % 16 == 0:
                f.write('\n    ')
            f.write(f'0x{byte:02X}')
            if i < len(key) - 1:
                f.write(', ')
        f.write('\n};\n')
        f.write(f'unsigned int {array_name}_key_size = {key_size};\n\n')

        # Encrypted data array
        f.write(f'// Encrypted payload\n')
        f.write(f'unsigned char {array_name}[] = {{\n    ')
        for i, byte in enumerate(encrypted_data):
            if i > 0 and i % 16 == 0:
                f.write('\n    ')
            f.write(f'0x{byte:02X}')
            if i < len(encrypted_data) - 1:
                f.write(', ')
        f.write('\n};\n')
        f.write(f'unsigned int {array_name}_size = sizeof({array_name});\n\n')

        # Decryption routine in C
        f.write(f'// In-place decryption routine\n')
        f.write(f'inline void decrypt_{array_name}() {{\n')
        f.write(f'    for (size_t i = 0; i < {array_name}_size; i++) {{\n')
        f.write(f'        {array_name}[i] ^= {array_name}_key[i % {array_name}_key_size];\n')
        f.write(f'    }}\n')
        f.write(f'}}\n\n')

        f.write('#endif // PAYLOAD_H\n')

    print(f'[+] File generated: {output_file}')
    print(f'[+] Payload size: {len(data)} bytes')
    print(f'[+] XOR key length: {key_size} bytes')

if __name__ == '__main__':
    if len(sys.argv) < 4:
        print('Usage: python xor_encoder.py <input.sys/bin> <output.h> <array_name> [key_length_bytes]')
        sys.exit(1)

    key_len = int(sys.argv[4]) if len(sys.argv) > 4 else 16
    file_to_xor_cpp(sys.argv[1], sys.argv[2], sys.argv[3], key_len)