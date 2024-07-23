#include "utils.h"

std::string get_date() {
	std::string return_date;
	
	__time64_t now = _time64(nullptr);
	tm tm_now;
	localtime_s(&tm_now, &now);

	std::string t_y = std::to_string(tm_now.tm_year + 1900);
	std::string t_m;
	if ((tm_now.tm_mon + 1) < 10) {
		t_m = "0" + std::to_string(tm_now.tm_mon + 1);
	}
	else {
		t_m = std::to_string(tm_now.tm_mon + 1);
	}
	
	std::string t_d = std::to_string(tm_now.tm_mday);
	std::string t_h = std::to_string(tm_now.tm_hour);

	return_date = t_y + t_m + t_d + t_h;

	return return_date;
}

std::vector<std::string> get_file_vec(const std::string& input_path) {
	std::vector<std::string> return_vec;
	std::error_code ec;


	for (const auto& entry : std::filesystem::directory_iterator(input_path, ec)) {
		if (ec) {
			std::cerr << "Error accessing directory: " << ec.message() << std::endl;
			return return_vec;
		}
		if (entry.path().extension() == ".jpg") {
			return_vec.push_back(entry.path().filename().string());
		}
	}

	if (ec) {
		std::cerr << "Error during iteration: " << ec.message() << std::endl;
	}

	return return_vec;
}

void create_path(const std::string& input_path) {
	if (std::filesystem::exists(input_path)) {
		return;
	}
	else {
		std::filesystem::create_directories(input_path);
	}
}

void show_image(cv::Mat input_image) {
	cv::namedWindow("display", cv::WINDOW_AUTOSIZE);
	cv::imshow("display", input_image);

	cv::waitKey(0);
}


