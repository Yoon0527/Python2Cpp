#pragma once
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <system_error>
#include <ctime>
#include<opencv2/opencv.hpp>

std::string get_date();
std::vector<std::string> get_file_vec(const std::string& input_path);
void create_path(const std::string& input_path);
void show_image(cv::Mat input_image);