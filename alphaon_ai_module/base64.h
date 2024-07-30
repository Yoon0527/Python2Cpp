#pragma once
#include <vector>
#include <string>

class Base64 {
public:
    static std::vector<unsigned char> decode(const std::string& input);
};