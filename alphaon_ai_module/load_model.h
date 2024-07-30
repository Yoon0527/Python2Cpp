#pragma once
//#include "AESCipher.h"
#include "utils.h"
#include<onnxruntime_cxx_api.h>


Ort::Session load_detection_model(const std::string& key);
Ort::Session load_classification_model(const std::string& key);
std::vector<unsigned char> read_file(const std::string& filename);
//void RunModel(Ort::Session& session, const std::vector<float>& preprocess_frame, std::vector<float>& output);

void unpad(std::vector<unsigned char>& data);
//std::vector<unsigned char> sha256(const std::string& str);
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data, const std::vector<unsigned char>& key);
//std::string vector_to_string(const std::vector<unsigned char>& vec);
//std::string read_file_as_base64(const std::string& filepath);
std::vector<unsigned char> generate_key(const std::string& key_str);
std::vector<unsigned char> read_binary_file(const std::string& filepath);