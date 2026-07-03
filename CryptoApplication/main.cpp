#define _CRT_SECURE_NO_WARNINGS
#include "crypto_helpers.h"
#include <openssl/applink.c>
#pragma warning(disable: 4267)
#pragma comment(lib, "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib")
#pragma comment(lib, "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libssl.lib")



int main() {
    // Dynamic runtime mapping configuration allocation
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int choice;
    std::string inFile, outFile, pubKeyFile, privKeyFile;

    // Balanced 256-bit Key & 128-bit Implementation Vector Buffer for processing
    std::vector<unsigned char> aesKey = { 'M','y','S','e','c','r','e','t','K','e','y','1','2','3','4','5','M','y','S','e','c','r','e','t','K','e','y','1','2','3','4','5' };
    std::vector<unsigned char> aesIv = { 'I','n','i','t','V','e','c','t','o','r','1','2','3','4','5','6' };

    while (true) {
        std::cout << "  EXPERIMENTAL CRYPTOGRAPHY APPLICATION CORE \n";
        std::cout << "1. Generate RSA Key Pair (Asymmetric)\n";
        std::cout << "2. RSA Encrypt File\n";
        std::cout << "3. RSA Decrypt File\n";
        std::cout << "4. AES-256-CBC Encrypt File (Symmetric)\n";
        std::cout << "5. AES-256-CBC Decrypt File (Symmetric)\n";
        std::cout << "6. Compute File Checksum Hash (SHA-256)\n";
        std::cout << "7. Exit Application\n";
        std::cout << "Select Operation [1-7]: ";

        if (!(std::cin >> choice)) {
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }

        if (choice == 7) break;

        switch (choice) {
        case 1:
            std::cout << "Enter Public Key output filename (e.g. public.pem): "; std::cin >> pubKeyFile;
            std::cout << "Enter Private Key output filename (e.g. private.pem): "; std::cin >> privKeyFile;
            if (generateRSAKeys(pubKeyFile, privKeyFile)) std::cout << "[+] Key pair generated successfully!\n";
            else std::cout << "[-] Key generation failed.\n";
            break;
        case 2:
            std::cout << "Source file to encrypt: "; std::cin >> inFile;
            std::cout << "Destination encrypted file: "; std::cin >> outFile;
            std::cout << "Recipient Public key file path: "; std::cin >> pubKeyFile;
            if (writeFile(outFile, rsaEncrypt(readFile(inFile), pubKeyFile))) std::cout << "[+] File encrypted using RSA.\n";
            break;
        case 3:
            std::cout << "Encrypted file path: "; std::cin >> inFile;
            std::cout << "Destination decrypted file: "; std::cin >> outFile;
            std::cout << "Your Private key file path: "; std::cin >> privKeyFile;
            if (writeFile(outFile, rsaDecrypt(readFile(inFile), privKeyFile))) std::cout << "[+] File decrypted using RSA.\n";
            break;
        case 4:
            std::cout << "Source file to encrypt: "; std::cin >> inFile;
            std::cout << "Destination encrypted file: "; std::cin >> outFile;
            if (writeFile(outFile, aesEncrypt(readFile(inFile), aesKey, aesIv))) std::cout << "[+] File encrypted using AES-256.\n";
            break;
        case 5:
            std::cout << "Encrypted file path: "; std::cin >> inFile;
            std::cout << "Destination decrypted file: "; std::cin >> outFile;
            if (writeFile(outFile, aesDecrypt(readFile(inFile), aesKey, aesIv))) std::cout << "[+] File decrypted using AES-256.\n";
            break;
        case 6:
            std::cout << "Enter target file path: "; std::cin >> inFile;
            std::cout << "[+] SHA-256 Hash Digest: " << computeSHA256(readFile(inFile)) << "\n";
            break;
        default:
            std::cout << "Invalid selection.\n";
        }
    }

    // Explicit Context Deallocation to eliminate system heap leakage
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
