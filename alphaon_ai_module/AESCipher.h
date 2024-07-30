#pragma once

#include <string>
#include <vector>

class AESCipher {
public:
    explicit AESCipher(const std::string& key);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& enc);
    
private:
    std::vector<unsigned char> key_;
    std::vector<unsigned char> iv_;
    std::vector<unsigned char> pad(const std::vector<unsigned char>& data, size_t block_size);
    std::vector<unsigned char> unpad(const std::vector<unsigned char>& data);
};
