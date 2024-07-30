#pragma once
#include "AESCipher.h"
#include "utils.h"
#include<onnxruntime_cxx_api.h>


Ort::Session load_detection_model(const std::string& key, Ort::Env& env, Ort::SessionOptions& session_options);
Ort::Session load_classification_model(const std::string& key);
void decrypt_save_model(const std::string& key);
void RunModel(Ort::Session& session, const std::vector<float>& preprocess_frame, std::vector<float>& output);