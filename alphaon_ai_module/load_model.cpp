#include "load_model.h"
#include "utils.h"

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>

//Ort::Session load_detection_model(const std::string& key, Ort::Env& env, Ort::SessionOptions& session_options) {
//    AESCipher aesCipher(key);
//
//    try {
//        std::vector<unsigned char> encrypted_detection_model = read_bin("./model/detection.bin");
//        std::vector<unsigned char> base64_decoded_detection_model = base64_decode(std::string(encrypted_detection_model.begin(), encrypted_detection_model.end()));
//        std::vector<unsigned char> detection_model = aesCipher.decrypt(base64_decoded_detection_model);
//
//        // 임시 파일에 복호화된 모델을 저장
//        std::string temp_model_path = "./model/temp_detection.onnx";
//        std::ofstream temp_model_file(temp_model_path, std::ios::binary);
//        if (!temp_model_file) {
//            throw std::runtime_error("Failed to create temporary file for the model.");
//        }
//        temp_model_file.write(reinterpret_cast<const char*>(detection_model.data()), detection_model.size());
//        temp_model_file.close();
//
//        // Ort::Session 생성
//        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "AESCipherONNX");
//        Ort::Session ort_session_detection(env, temp_model_path.c_str(), session_options);
//        std::cout << "Models loaded successfully." << std::endl;
//
//        // 임시 파일 삭제
//        std::remove(temp_model_path.c_str());
//
//        return ort_session_detection;
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error: " << e.what() << std::endl;
//        throw;
//    }
//}

void decrypt_save_model(const std::string& key) {
    const char key_str[25] = "CAIMI Alphaon V1.0 Model";
    unsigned char key_[AES_BLOCK_SIZE];
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char* data;
    unsigned char* cipher;
    unsigned char* plain;
    AES_KEY decryptKey;

    std::copy(key, key_str + 16, key_);

    memset(iv, 0x00, AES_BLOCK_SIZE);

}


Ort::Session load_classification_model(const std::string& key) {
    AESCipher aesCipher(key);

    try {
        std::vector<unsigned char> encrypted_classification_model = read_bin("./model/classification.bin");
        std::vector<unsigned char> base64_decoded_classification_model = base64_decode(std::string(encrypted_classification_model.begin(), encrypted_classification_model.end()));
        std::vector<unsigned char> classification_model = aesCipher.decrypt(base64_decoded_classification_model);

        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "AESCipherONNX");
        Ort::SessionOptions session_options;
        Ort::Session ort_session_classification(env, classification_model.data(), classification_model.size(), session_options);

        return ort_session_classification;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    
}

//void RunModel(Ort::Session& session, const std::vector<float>& preprocess_frame, std::vector<float>& output) {
//    // 입력 텐서 준비
//    Ort::AllocatorWithDefaultOptions allocator;
//    std::vector<int64_t> input_tensor_shape = { 1, 3, 256, 256 }; // 예시, 실제 모델에 맞게 설정
//    size_t input_tensor_size = 1 * 3 * 256 * 256; // 예시, 실제 데이터 크기에 맞게 설정
//
//    // 입력 텐서 생성
//    Ort::Value input_tensor = Ort::Value::CreateTensor<float>(allocator,
//        preprocess_frame.data(), input_tensor_size, input_tensor_shape.data(), input_tensor_shape.size());
//
//    Ort::Value::CreateTensor<float>()
//    // 입력 이름 가져오기
//    auto input_names = session.GetInputNames(allocator);
//    auto output_names = session.GetOutputNames(allocator);
//
//    // 모델 실행
//    std::vector<Ort::Value> ort_inputs = { std::move(input_tensor) };
//    std::vector<Ort::Value> ort_outputs = session.Run(Ort::RunOptions{ nullptr },
//        input_names.data(), ort_inputs.data(), 1, output_names.data(), 1);
//
//    // 출력 처리
//    auto& output_tensor = ort_outputs.front();
//    float* output_arr = output_tensor.GetTensorMutableData<float>();
//    size_t output_size = output_tensor.GetTensorTypeAndShapeInfo().GetElementCount();
//
//    output.resize(output_size);
//    std::copy(output_arr, output_arr + output_size, output.begin());
//}