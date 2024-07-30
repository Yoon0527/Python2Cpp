#include "AESCipher.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <stdexcept>

AESCipher::AESCipher(const std::string& key) {
    key_.resize(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(key.data()), key.size(), key_.data());

    iv_.resize(AES_BLOCK_SIZE, 0); // IV를 0으로 초기화
}

//std::vector<unsigned char> AESCipher::decrypt(const std::vector<unsigned char>& enc) {
//    std::vector<unsigned char> dec_data(enc.size() + AES_BLOCK_SIZE);
//    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//    if (!ctx) {
//        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
//    }
//
//    unsigned char iv[16] = { 0 }; // 초기화 벡터
//
//    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv)) {
//        EVP_CIPHER_CTX_free(ctx);
//        throw std::runtime_error("EVP_DecryptInit_ex failed");
//    }
//
//    int len;
//    if (1 != EVP_DecryptUpdate(ctx, dec_data.data(), &len, enc.data(), enc.size())) {
//        EVP_CIPHER_CTX_free(ctx);
//        throw std::runtime_error("EVP_DecryptUpdate failed");
//    }
//    int plaintext_len = len;
//
//    int final_ret = EVP_DecryptFinal_ex(ctx, dec_data.data() + len, &len);
//    if (1 != final_ret) {
//        unsigned long err_code = ERR_get_error();
//        char err_msg[120];
//        ERR_error_string_n(err_code, err_msg, sizeof(err_msg));
//        EVP_CIPHER_CTX_free(ctx);
//        std::cerr << "EVP_DecryptFinal_ex failed: " << err_msg << std::endl;
//        throw std::runtime_error("EVP_DecryptFinal_ex failed");
//    }
//    plaintext_len += len;
//    EVP_CIPHER_CTX_free(ctx);
//
//    dec_data.resize(plaintext_len);
//    return unpad(dec_data);
//}

std::vector<unsigned char> AESCipher::decrypt(const std::vector<unsigned char>& enc) {
    std::vector<unsigned char> decrypted(enc.size() + AES_BLOCK_SIZE);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    int len;
    int plaintext_len;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key_.data(), iv_.data())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }

    if (1 != EVP_DecryptUpdate(ctx, decrypted.data(), &len, enc.data(), enc.size())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    plaintext_len += len;

    decrypted.resize(plaintext_len);
    EVP_CIPHER_CTX_free(ctx);

    return decrypted;
}

std::vector<unsigned char> AESCipher::unpad(const std::vector<unsigned char>& data) {
    if (data.empty()) {
        throw std::runtime_error("Data is empty");
    }
    size_t padding_size = data.back();
    if (padding_size > data.size()) {
        throw std::runtime_error("Invalid padding");
    }
    return std::vector<unsigned char>(data.begin(), data.end() - padding_size);
}

std::vector<unsigned char> pad(const std::vector<unsigned char>& data, size_t block_size) {
    size_t padding_size = block_size - (data.size() % block_size);
    std::vector<unsigned char> padded_data = data;
    padded_data.insert(padded_data.end(), padding_size, static_cast<unsigned char>(padding_size));
    return padded_data;
}


