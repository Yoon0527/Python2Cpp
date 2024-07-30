#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <system_error>
#include <ctime>
#include<opencv2/opencv.hpp>
#include <fstream>
#include "base64.h"

std::vector<unsigned char> read_bin(const std::string& filename);
std::vector<unsigned char> base64_decode(const std::string& encoded);
//std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t block_size);
//std::vector<uint8_t> unpad(const std::vector<uint8_t>& padded_data);

std::string get_date();
std::vector<std::string> get_file_vec(const std::string& input_path);
void create_path(const std::string& input_path);
void show_image(cv::Mat input_image);