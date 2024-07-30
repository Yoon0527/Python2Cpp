//#pragma once
//
//#include <string>
//#include <vector>
//
//class AESCipher {
//public:
//    explicit AESCipher(const std::string& key);
//    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& enc);
//    bool aes_decrypt(const std::vector<unsigned char>& encrypted, std::vector<unsigned char>& decrypted, const std::vector<unsigned char>& key);
//
//private:
//    std::vector<unsigned char> key_;
//    std::vector<unsigned char> iv_;
//    //std::vector<unsigned char> sha256(const std::string& str);
//    std::vector<unsigned char> pad(const std::vector<unsigned char>& data, size_t block_size);
//    std::vector<unsigned char> unpad(const std::vector<unsigned char>& data);
//};
