/**
*
*  Copyright [2025] [Darie-Dragos Mitoiu]
*
* Licensed under the Slovatus License, Version 1.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.dmitoiu.ro/licenses/LICENSE-1.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <openssl/evp.h>

void printUsage() {
    std::cout << "\nUsage:\n"
        << "  hash_app [OPTIONS]\n\n"
        << "Options:\n"
        << "  --string <text>       Hash the given string.\n"
        << "  --file <path>         Hash the contents of the specified file.\n"
        << "  --hash <type>         Specify the hash type to use.\n\n"
        << "Supported Hash Types:\n"
        << "  md5                   MD5 hash (128-bit).\n"
        << "  sha1                  SHA-1 hash (160-bit).\n"
        << "  sha256                SHA-256 hash (256-bit).\n"
        << "  sha512                SHA-512 hash (512-bit).\n\n"
        << "Examples:\n"
        << "  hash_app --string \"Khesus\" --hash sha256\n"
        << "  hash_app --file input.txt --hash md5\n\n";
}

std::string hashString(const std::string& input, const std::string& hashType) {
    const EVP_MD* md = EVP_get_digestbyname(hashType.c_str());
    if (!md) {
        throw std::runtime_error("Invalid hash type: " + hashType);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create OpenSSL context");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to compute hash");
    }

    EVP_MD_CTX_free(ctx);

    // Construct the hex string manually
    std::string result;
    result.reserve(length * 2); // Reserve space for hex string
    const char hexChars[] = "0123456789abcdef";

    for (unsigned int i = 0; i < length; ++i) {
        result.push_back(hexChars[(hash[i] >> 4) & 0xF]);  // High nibble
        result.push_back(hexChars[hash[i] & 0xF]);         // Low nibble
    }

    return result;
}

std::string hashFile(const std::string& filePath, const std::string& hashType) {
    std::ifstream file(filePath, std::ios_base::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open file: " + filePath);
    }

    const EVP_MD* md = EVP_get_digestbyname(hashType.c_str());
    if (!md) {
        throw std::runtime_error("Invalid hash type: " + hashType);
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create OpenSSL context");
    }

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize hash computation");
    }

    std::vector<char> buffer(4096);
    while (file.read(buffer.data(), buffer.size()) || file.gcount() > 0) {
        if (EVP_DigestUpdate(ctx, buffer.data(), file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            throw std::runtime_error("Failed to update hash");
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int length = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &length) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize hash computation");
    }

    EVP_MD_CTX_free(ctx);

    // Construct the hex string manually
    std::string result;
    result.reserve(length * 2); // Reserve space for hex string
    const char hexChars[] = "0123456789abcdef";

    for (unsigned int i = 0; i < length; ++i) {
        result.push_back(hexChars[(hash[i] >> 4) & 0xF]);  // High nibble
        result.push_back(hexChars[hash[i] & 0xF]);         // Low nibble
    }

    return result;
}

int main(int argc, char* argv[])
{
    if (argc != 5) {
        printUsage();
        return 1;
    }

    std::string mode = argv[1];
    std::string input = argv[2];
    std::string hashOption = argv[3];
    std::string hashType = argv[4];

    try {
        std::string result;
        if (mode == "--string" && hashOption == "--hash") {
            result = hashString(input, hashType);
        }
        else if (mode == "--file" && hashOption == "--hash") {
            result = hashFile(input, hashType);
        }
        else {
            printUsage();
            return 1;
        }

        std::cout << "Hash (" << hashType << "): " << result << '\n';
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        return 1;
    }

    return 0;
}