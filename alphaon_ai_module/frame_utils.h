#pragma once
#include<opencv2/opencv.hpp>
#include<iostream>
#include<string>
#include<vector>

std::pair<cv::Mat, double> preprocess_image(cv::Mat input_img, int img_size);