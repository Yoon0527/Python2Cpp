#include "utils.h"
#include "frame_utils.h"
#include "AESCipher.h"
#include "load_model.h"

#include <iostream>
#include<opencv2/opencv.hpp>
#include<filesystem>
#include <onnxruntime_cxx_api.h>

namespace fs = std::filesystem;

int main()
{
    int BS = 16;
    const std::string key = "CAIMI Alphaon V1.0 Model";

    //Ort::Session ort_session_detection = load_detection_model(key, env, session_options);
    //Ort::Session ort_session_classification = load_classification_model(key);


    std::vector<std::string> class_list = { "fundus", "etc" };

    std::vector<double> score_threshold_list = { 0, 0.45, 0.42, 0.39, 0.35, 0.32, 0.28, 0.24, 0.21, 0.17, 0.13 };

 

    double threshold = 0.28;

    const std::string root_path = "./test_image/";
    const std::string save_root_path = "./result/" + get_date() + "/";

    std::vector<std::string> file_vec = get_file_vec(root_path);

    create_path(save_root_path);

    for (int i = 0; i < file_vec.size(); i++) {
        std::cout << "File Name: " << file_vec[i] << std::endl;

        int frame_number = 0;
        int patient_number = 0;
        int screening_start_time = 0;
        double score_threshold = score_threshold_list[int(1)];
        std::vector<double> result_output;
        
        cv::Mat original_image = cv::imread(root_path + file_vec[i]);
        cv::Mat frame = original_image.clone();

        cv::Mat src_frame = frame.clone();

        cv::cvtColor(frame, frame, cv::COLOR_BGR2RGB);

        int h = frame.rows;
        int w = frame.cols;

        std::pair<cv::Mat, double> preprocess_result = preprocess_image(frame, 256);
        cv::Mat preprocess_frame = preprocess_result.first;
        double scale = preprocess_result.second;
        
        

    }

    return 0;
}

/*
void show_img() {
    cv::Mat image = cv::imread("./test_image/cancer_00018.jpg", cv::IMREAD_COLOR);

    cv::namedWindow("display", cv::WINDOW_AUTOSIZE);
    cv::imshow("display", image);

    cv::waitKey(0);

}
*/