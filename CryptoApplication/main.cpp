#define _CRT_SECURE_NO_WARNINGS
#include "crypto_helpers.h"
#include <openssl/applink.c>
using namespace std;
#pragma warning(disable: 4267)
#pragma comment(lib, "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libcrypto.lib")
#pragma comment(lib, "C:\\Program Files\\OpenSSL-Win64\\lib\\VC\\x64\\MD\\libssl.lib")


int main() {
    // Dynamic runtime mapping configuration allocation
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int choice;
    string inFile, outFile, pubKeyFile, privKeyFile;

    // Balanced 256-bit Key & 128-bit Implementation Vector Buffer for processing
    vector<unsigned char> aesKey = { 'M','y','S','e','c','r','e','t','K','e','y','1','2','3','4','5','M','y','S','e','c','r','e','t','K','e','y','1','2','3','4','5' };
    vector<unsigned char> aesIv = { 'I','n','i','t','V','e','c','t','o','r','1','2','3','4','5','6' };

    while (true) {
        cout << "  EXPERIMENTAL CRYPTOGRAPHY APPLICATION CORE \n";
        cout << "1. Generate RSA Key Pair (Asymmetric)\n";
        cout << "2. RSA Encrypt File\n";
        cout << "3. RSA Decrypt File\n";
        cout << "4. AES-256-CBC Encrypt File (Symmetric)\n";
        cout << "5. AES-256-CBC Decrypt File (Symmetric)\n";
        cout << "6. Compute File Checksum Hash (SHA-256)\n";
        cout << "7. Exit Application\n";
        cout << "Select Operation [1-7]: ";

        if (!(cin >> choice)) {
            cin.clear();
            cin.ignore(numeric_limits<streamsize>::max(), '\n');
            continue;
        }

        if (choice == 7) break;

        switch (choice) {
        case 1:
            cout << "Enter Public Key output filename (e.g. public.pem): "; cin >> pubKeyFile;
            cout << "Enter Private Key output filename (e.g. private.pem): "; cin >> privKeyFile;
            if (generateRSAKeys(pubKeyFile, privKeyFile)) cout << "[+] Key pair generated successfully!\n";
            else cout << "[-] Key generation failed.\n";
            break;
        case 2:
            cout << "Source file to encrypt: "; cin >> inFile;
            cout << "Destination encrypted file: "; cin >> outFile;
            cout << "Recipient Public key file path: "; cin >> pubKeyFile;
            if (writeFile(outFile, rsaEncrypt(readFile(inFile), pubKeyFile))) cout << "[+] File encrypted using RSA.\n";
            break;
        case 3:
            cout << "Encrypted file path: "; cin >> inFile;
            cout << "Destination decrypted file: "; cin >> outFile;
            cout << "Your Private key file path: "; cin >> privKeyFile;
            if (writeFile(outFile, rsaDecrypt(readFile(inFile), privKeyFile))) cout << "[+] File decrypted using RSA.\n";
            break;
        case 4:
            cout << "Source file to encrypt: "; cin >> inFile;
            cout << "Destination encrypted file: "; cin >> outFile;
            if (writeFile(outFile, aesEncrypt(readFile(inFile), aesKey, aesIv))) cout << "[+] File encrypted using AES-256.\n";
            break;
        case 5:
            cout << "Encrypted file path: "; cin >> inFile;
            cout << "Destination decrypted file: "; cin >> outFile;
            if (writeFile(outFile, aesDecrypt(readFile(inFile), aesKey, aesIv))) cout << "[+] File decrypted using AES-256.\n";
            break;
        case 6:
            cout << "Enter target file path: "; cin >> inFile;
            cout << "[+] SHA-256 Hash Digest: " << computeSHA256(readFile(inFile)) << "\n";
            break;
        default:
            cout << "Invalid selection.\n";
        }
    }

    // Explicit Context Deallocation to eliminate system heap leakage
    EVP_cleanup();
    ERR_free_strings();
    return 0;
}
