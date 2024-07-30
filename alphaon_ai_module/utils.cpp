#include "utils.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

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


std::vector<unsigned char> read_bin(const std::string& filename) {
	std::ifstream file(filename, std::ios::binary);
	if (!file) {
		throw std::runtime_error("Failed to open file: " + filename);
	}
	return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

std::vector<unsigned char> base64_decode(const std::string& encoded_data) {
	BIO* bio = BIO_new_mem_buf(encoded_data.data(), static_cast<int>(encoded_data.size()));
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BUF_MEM* bptr = nullptr;
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_get_mem_ptr(bio, &bptr);

	std::vector<unsigned char> decoded(bptr->length);
	int decoded_length = BIO_read(bio, decoded.data(), static_cast<int>(bptr->length));
	decoded.resize(decoded_length);

	BIO_free_all(bio);
	return decoded;
}


//std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t block_size) {
//	size_t padding_size = block_size - (data.size() % block_size);
//	std::vector<uint8_t> padded_data = data;
//	padded_data.insert(padded_data.end(), padding_size, static_cast<uint8_t>(padding_size));
//	return padded_data;
//}
//
//std::vector<uint8_t> unpad(const std::vector<uint8_t>& padded_data) {
//	if (padded_data.empty()) {
//		throw std::invalid_argument("Padded data is empty");
//	}
//	uint8_t padding_size = padded_data.back();
//	if (padding_size > padded_data.size()) {
//		throw std::invalid_argument("Invalid padding size");
//	}
//	std::vector<uint8_t> data(padded_data.begin(), padded_data.end() - padding_size);
//	return data;
//}
