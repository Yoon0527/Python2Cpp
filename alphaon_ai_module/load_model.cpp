#include "load_model.h"
#include "utils.h"

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
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

std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file " + filename);
    }

    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

//Ort::Session load_detection_model(const std::string& key) {
//    
//    try {
//        std::vector<unsigned char> key_ = sha256(key);
//
//        std::vector<unsigned char> encrypted_data = read_file(".\\model\\detection.bin");
//
//        std::string encrypted_data_str = vector_to_string(encrypted_data);
//
//        std::vector<unsigned char> decoded_data = base64_decode(encrypted_data_str);
//        std::cout << "Base64 decoded data size: " << decoded_data.size() << std::endl;
//
//        std::vector<unsigned char> decrypted_data;
//        if (!aes_decrypt(decoded_data, decrypted_data, key_)) {
//            std::cerr << "Decryption failed for detection model" << std::endl;
//        }
//
//        std::ofstream decrypted_file("detection_decrypted_model.onnx", std::ios::binary);
//        decrypted_file.write(reinterpret_cast<const char*>(decrypted_data.data()), decrypted_data.size());
//        decrypted_file.close();
//
//        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "DecryptedModel");
//        Ort::SessionOptions session_options;
//        session_options.SetIntraOpNumThreads(1);
//        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);
//
//        Ort::Session detection_session(env, decrypted_data.data(), decrypted_data.size(), session_options);
//
//        std::cout << "Models loaded successfully" << std::endl;
//
//        return detection_session;
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error: " << e.what() << std::endl;
//    }
//
//}

Ort::Session load_detection_model(const std::string& key) {

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    try {
        //암호화된 파일 읽기
        std::vector<unsigned char> file_data = read_binary_file("./model/detection.bin");
        std::cout << "Detection Model Read Successfully. Size: " << file_data.size() << std::endl;

        //Base64 디코딩
        std::string base64_encoded(file_data.begin(), file_data.end());
        std::vector<unsigned char>decoded_data = base64_decode(base64_encoded);
        std::cout << "Base64 decoding done. Size: " << decoded_data.size() << std::endl;

        //암호화 키 생성
        std::string key_str = "CAIMI Alphaon V1.0 Model";
        std::vector<unsigned char> key = generate_key(key_str);
        std::cout << "Key Generated. Length: " << key.size() << std::endl;

        //AES 복호화
        std::vector<unsigned char> decrypted_data = aes_decrypt(decoded_data, key);
        std::cout << "Decrypted data Size: " << decrypted_data.size() << std::endl;

        //onnx session 할당
        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "DecryptedModel");
        Ort::SessionOptions session_options;
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

        try {
            Ort::Session ort_session_detection(env, decrypted_data.data(), decrypted_data.size(), session_options);
            std::cout << "ONNX model loaded successfully." << std::endl;
            // OpenSSL 정리
            EVP_cleanup();
            ERR_free_strings();
            return ort_session_detection;
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to load ONNX model: " << e.what() << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

}

Ort::Session load_classification_model(const std::string& key) {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    try {
        //암호화된 파일 읽기
        std::vector<unsigned char> file_data = read_binary_file("./model/classification.bin");
        std::cout << "Detection Model Read Successfully. Size: " << file_data.size() << std::endl;

        //Base64 디코딩
        std::string base64_encoded(file_data.begin(), file_data.end());
        std::vector<unsigned char>decoded_data = base64_decode(base64_encoded);
        std::cout << "Base64 decoding done. Size: " << decoded_data.size() << std::endl;

        //암호화 키 생성
        std::string key_str = "CAIMI Alphaon V1.0 Model";
        std::vector<unsigned char> key = generate_key(key_str);
        std::cout << "Key Generated. Length: " << key.size() << std::endl;

        //AES 복호화
        std::vector<unsigned char> decrypted_data = aes_decrypt(decoded_data, key);
        std::cout << "Decrypted data Size: " << decrypted_data.size() << std::endl;

        //onnx session 할당
        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "DecryptedModel");
        Ort::SessionOptions session_options;
        session_options.SetIntraOpNumThreads(1);
        session_options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_EXTENDED);

        try {
            Ort::Session ort_session_classification(env, decrypted_data.data(), decrypted_data.size(), session_options);
            std::cout << "ONNX model loaded successfully." << std::endl;
            // OpenSSL 정리
            EVP_cleanup();
            ERR_free_strings();
            return ort_session_classification;
        }
        catch (const std::exception& e) {
            std::cerr << "Failed to load ONNX model: " << e.what() << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

//Ort::Session load_classification_model(const std::string& key) {
//    AESCipher aesCipher(key);
//
//    try {
//        std::vector<unsigned char> encrypted_classification_model = read_bin("./model/classification.bin");
//        std::vector<unsigned char> base64_decoded_classification_model = base64_decode(std::string(encrypted_classification_model.begin(), encrypted_classification_model.end()));
//        std::vector<unsigned char> classification_model = aesCipher.decrypt(base64_decoded_classification_model);
//
//        Ort::Env env(ORT_LOGGING_LEVEL_WARNING, "AESCipherONNX");
//        Ort::SessionOptions session_options;
//        Ort::Session ort_session_classification(env, classification_model.data(), classification_model.size(), session_options);
//
//        return ort_session_classification;
//    }
//    catch (const std::exception& e) {
//        std::cerr << "Error: " << e.what() << std::endl;
//    }
//    
//}

void unpad(std::vector<unsigned char>& data) {
    size_t padding_len = data.back();
    data.resize(data.size() - padding_len);
}

// SHA-256 해시 계산 함수
//std::vector<unsigned char> sha256(const std::string& str) {
//    std::vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
//    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
//    if (mdctx == nullptr) {
//        throw std::runtime_error("Failed to create MD context");
//    }
//
//    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
//        EVP_MD_CTX_free(mdctx);
//        throw std::runtime_error("Failed to initialize digest");
//    }
//
//    if (EVP_DigestUpdate(mdctx, str.c_str(), str.size()) != 1) {
//        EVP_MD_CTX_free(mdctx);
//        throw std::runtime_error("Failed to update digest");
//    }
//
//    unsigned int length;
//    if (EVP_DigestFinal_ex(mdctx, hash.data(), &length) != 1) {
//        EVP_MD_CTX_free(mdctx);
//        throw std::runtime_error("Failed to finalize digest");
//    }
//
//    EVP_MD_CTX_free(mdctx);
//
//    if (length != SHA256_DIGEST_LENGTH) {
//        throw std::runtime_error("Hash length mismatch");
//    }
//
//    return hash;
//}

// Base64 디코딩 함수
std::vector<unsigned char> base64_decode(const std::string& in) {
    static const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<unsigned char> out;
    std::vector<int> T(256, -1);

    for (size_t i = 0; i < chars.size(); ++i)
        T[chars[i]] = i;

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

// SHA-256 키 생성
std::vector<unsigned char> generate_key(const std::string& key_str) {
    std::vector<unsigned char> key(SHA256_DIGEST_LENGTH);
    SHA256(reinterpret_cast<const unsigned char*>(key_str.data()), key_str.size(), key.data());
    return key;
}

// AES-256-CBC 복호화 함수
std::vector<unsigned char> aes_decrypt(const std::vector<unsigned char>& encrypted_data, const std::vector<unsigned char>& key) {
    std::vector<unsigned char> decrypted_data(encrypted_data.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
    }

    unsigned char iv[AES_BLOCK_SIZE] = { 0 }; // IV는 16바이트의 0으로 설정

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize AES decryption");
    }

    int len;
    if (EVP_DecryptUpdate(ctx, decrypted_data.data(), &len, encrypted_data.data(), encrypted_data.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to decrypt data");
    }
    int decrypted_len = len;

    int padding_len = 0;
    int ret = EVP_DecryptFinal_ex(ctx, decrypted_data.data() + len, &padding_len);
    if (ret != 1) {
        char err_buf[256];
        ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error(std::string("Failed to finalize decryption: ") + err_buf);
    }
    decrypted_len += padding_len;
    decrypted_data.resize(decrypted_len);

    EVP_CIPHER_CTX_free(ctx);

    return decrypted_data;
}

//std::string vector_to_string(const std::vector<unsigned char>& vec) {
//    return std::string(vec.begin(), vec.end());
//}

std::vector<unsigned char> read_binary_file(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::in | std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        throw std::runtime_error("Error opening file");
    }

    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        file.close();
        return buffer;
    }
    else {
        file.close();
        throw std::runtime_error("Error reading file");
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