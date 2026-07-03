#pragma once
#pragma warning(disable: 4267)

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/sha.h>
using namespace std;

// Handle runtime failures safely
inline void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// Optimized Binary I/O processing systems
inline vector<unsigned char> readFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "[-] Error opening file for reading: " << filename << "\n";
        return {};
    }
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

inline bool writeFile(const string& filename, const vector<unsigned char>& data) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "[-] Error opening file for writing: " << filename << "\n";
        return false;
    }
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

// Compute File Integrity Cryptographic Checksum
inline string computeSHA256(const vector<unsigned char>& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx) return "";

    if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) return "";
    if (1 != EVP_DigestUpdate(ctx.get(), data.data(), data.size())) return "";
    if (1 != EVP_DigestFinal_ex(ctx.get(), hash, &hash_len)) return "";

    char buf[65];
    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf_s(buf + (i * 2), sizeof(buf) - (i * 2), "%02x", hash[i]);
    }
    return string(buf);
}


// AES-256-CBC Symmetric Processing System
inline vector<unsigned char> aesEncrypt(const vector<unsigned char>& plaintext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) handleErrors();

    vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len = 0, ciphertext_len = 0;

    if (1 != EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len, plaintext.data(), plaintext.size())) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len)) handleErrors();
    ciphertext_len += len;

    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

inline vector<unsigned char> aesDecrypt(const vector<unsigned char>& ciphertext, const vector<unsigned char>& key, const vector<unsigned char>& iv) {
    unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx) handleErrors();

    if (1 != EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_cbc(), nullptr, key.data(), iv.data())) handleErrors();

    vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len, ciphertext.data(), ciphertext.size())) handleErrors();
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len)) return {};
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}

// RSA Asymmetric Infrastructure Systems
inline bool generateRSAKeys(const string& publicKeyFile, const string& privateKeyFile) {
    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr), EVP_PKEY_CTX_free);
    if (!ctx || EVP_PKEY_keygen_init(ctx.get()) <= 0) return false;
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), 2048) <= 0) return false;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen(ctx.get(), &pkey) <= 0) return false;

    FILE* pubFile = nullptr;
    FILE* privFile = nullptr;
    fopen_s(&pubFile, publicKeyFile.c_str(), "wb");
    fopen_s(&privFile, privateKeyFile.c_str(), "wb");
    if (!pubFile || !privFile) {
        if (pubFile) fclose(pubFile);
        if (privFile) fclose(privFile);
        EVP_PKEY_free(pkey);
        return false;
    }

    PEM_write_PUBKEY(pubFile, pkey);
    PEM_write_PrivateKey(privFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);

    fclose(pubFile);
    fclose(privFile);
    EVP_PKEY_free(pkey);
    return true;
}

inline vector<unsigned char> rsaEncrypt(const vector<unsigned char>& plaintext, const string& publicKeyFile) {
    FILE* pubFile = nullptr;
    fopen_s(&pubFile, publicKeyFile.c_str(), "rb");
    if (!pubFile) return {};
    EVP_PKEY* pkey = PEM_read_PUBKEY(pubFile, nullptr, nullptr, nullptr);
    fclose(pubFile);
    if (!pkey) return {};

    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY_free(pkey);
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0) return {};
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) return {};

    size_t outLen;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &outLen, plaintext.data(), plaintext.size()) <= 0) return {};
    vector<unsigned char> ciphertext(outLen);
    if (EVP_PKEY_encrypt(ctx.get(), ciphertext.data(), &outLen, plaintext.data(), plaintext.size()) <= 0) return {};

    return ciphertext;
}

inline vector<unsigned char> rsaDecrypt(const vector<unsigned char>& ciphertext, const string& privateKeyFile) {
    FILE* privFile = nullptr;
    fopen_s(&privFile, privateKeyFile.c_str(), "rb");
    if (!privFile) return {};
    EVP_PKEY* pkey = PEM_read_PrivateKey(privFile, nullptr, nullptr, nullptr);
    fclose(privFile);
    if (!pkey) return {};

    unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(EVP_PKEY_CTX_new(pkey, nullptr), EVP_PKEY_CTX_free);
    EVP_PKEY_free(pkey);
    if (!ctx || EVP_PKEY_decrypt_init(ctx.get()) <= 0) return {};
    if (EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0) return {};

    size_t outLen;
    if (EVP_PKEY_decrypt(ctx.get(), nullptr, &outLen, ciphertext.data(), ciphertext.size()) <= 0) return {};
    vector<unsigned char> plaintext(outLen);
    if (EVP_PKEY_decrypt(ctx.get(), plaintext.data(), &outLen, ciphertext.data(), ciphertext.size()) <= 0) return {};

    plaintext.resize(outLen);
    return plaintext;
}
