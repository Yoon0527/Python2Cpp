#include "frame_utils.h"

std::pair<cv::Mat, double> preprocess_image(cv::Mat input_img, int img_size) {
	//cv::Mat return_img;
	double return_scale;

	int image_height = input_img.rows;
	int image_width = input_img.cols;

	int resized_height = 0;
	int resized_width = 0;

	if (image_height > image_width) {
		return_scale = static_cast<double>(img_size) / static_cast<double>(image_height);
		resized_height = img_size;
		resized_width = static_cast<int>(image_width * return_scale);
	}
	else {
		return_scale = static_cast<double>(img_size) / static_cast<double>(image_width);
		resized_height = static_cast<int>(image_height * return_scale);
		resized_width = img_size;
	}
	cv::Mat resize_img;
	cv::resize(input_img, resize_img, cv::Size(resized_width, resized_height));
	resize_img.convertTo(resize_img, CV_32F, 1.0/255.0);

	cv::Mat mean = (cv::Mat_<float>(1, 3) << 0.485, 0.456, 0.406);
	cv::Mat std = (cv::Mat_<float>(1, 3) << 0.229, 0.224, 0.225);

	std::vector<cv::Mat> channels(3);
	cv::split(resize_img, channels);

	for (int i = 0; i < 3; ++i) {
		channels[i] -= mean.at<float>(0, i);
		channels[i] /= std.at<float>(0, i);
	}

	cv::Mat normalized_image;
	cv::merge(channels, normalized_image);

	int pad_h = img_size - resized_height;
	int pad_w = img_size - resized_width;

	cv::Mat padded_image;
	cv::copyMakeBorder(normalized_image, padded_image, pad_h, pad_h, pad_w, pad_w, cv::BORDER_CONSTANT, cv::Scalar(0, 0, 0));

	return std::make_pair(padded_image, return_scale);
}