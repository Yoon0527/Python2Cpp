#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <system_error>
#include <ctime>
#include <opencv2/opencv.hpp>
#include <fstream>
#include "json.hpp"
#include "base64.h"

struct NpyArray {
    std::vector<size_t> shape;
    std::vector<double> data;
};

enum class DataType {
    UNKNOWN,
    FLOAT32,
    FLOAT64,
    INT32,
    INT64
};

NpyArray load_npy(const std::string& filename);
DataType parse_dtype(const std::string& dtype);


std::vector<unsigned char> base64_decode(const std::string& encoded);
//std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t block_size);
//std::vector<uint8_t> unpad(const std::vector<uint8_t>& padded_data);

std::string get_date();
std::vector<std::string> get_file_vec(const std::string& input_path);
void create_path(const std::string& input_path);
void show_image(cv::Mat input_image);

std::vector<double> anchor_read(const std::string& path);