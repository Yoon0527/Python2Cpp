#include "utils.h"
#include "npy.hpp"
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

std::vector<double> anchor_read(const std::string& path) {
	npy::npy_data anchor_npy = npy::read_npy<double>(path);

	std::vector<double> anchor_vec = anchor_npy.data;
	
	return anchor_vec;
}

NpyArray load_npy(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Unable to open file " + filename);
    }

    // Read magic string
    char magic[6];
    file.read(magic, 6);
    if (std::string(magic, 6) != "\x93NUMPY") {
        throw std::runtime_error("Invalid NPY file.");
    }

    // Read version number
    uint8_t version[2];
    file.read(reinterpret_cast<char*>(version), 2);

    // Read header length
    uint16_t header_len;
    file.read(reinterpret_cast<char*>(&header_len), 2);

    // Read header
    std::string header(header_len, ' ');
    file.read(&header[0], header_len);

    // Output the full header for debugging
    std::cout << "Header: " << header << std::endl;

    // Parse header to find dtype and shape
    auto loc = header.find("descr");
    if (loc == std::string::npos) {
        throw std::runtime_error("Unable to find dtype in header.");
    }
    loc = header.find("'", loc + 6);  // Find the start of dtype
    auto loc1 = header.find("'", loc + 1);  // Find the end of dtype
    auto dtype = header.substr(loc + 1, loc1 - (loc + 1));
    std::cout << "Extracted dtype: " << dtype << std::endl;  // Debug info

    DataType data_type = parse_dtype(dtype);
    if (data_type == DataType::UNKNOWN) {
        throw std::runtime_error("Unsupported data type: " + dtype);
    }

    loc = header.find("shape");
    if (loc == std::string::npos) {
        throw std::runtime_error("Unable to find shape in header.");
    }
    loc = header.find('(', loc);
    auto loc2 = header.find(')', loc);
    auto shape_str = header.substr(loc + 1, loc2 - loc - 1);

    NpyArray array;
    std::istringstream shape_stream(shape_str);
    char c;
    size_t dim;
    while (shape_stream >> dim) {
        array.shape.push_back(dim);
        shape_stream >> c;  // Skip comma
    }

    // Determine number of elements
    size_t num_elements = 1;
    for (auto s : array.shape) {
        num_elements *= s;
    }
    array.data.resize(num_elements);

    // Read data based on type
    switch (data_type) {
    case DataType::FLOAT32: {
        std::vector<float> temp_data(num_elements);
        file.read(reinterpret_cast<char*>(temp_data.data()), num_elements * sizeof(float));
        for (size_t i = 0; i < num_elements; ++i) {
            array.data[i] = static_cast<double>(temp_data[i]);
        }
        break;
    }
    case DataType::FLOAT64:
        file.read(reinterpret_cast<char*>(array.data.data()), num_elements * sizeof(double));
        break;
    case DataType::INT32: {
        std::vector<int32_t> temp_data(num_elements);
        file.read(reinterpret_cast<char*>(temp_data.data()), num_elements * sizeof(int32_t));
        for (size_t i = 0; i < num_elements; ++i) {
            array.data[i] = static_cast<double>(temp_data[i]);
        }
        break;
    }
    case DataType::INT64: {
        std::vector<int64_t> temp_data(num_elements);
        file.read(reinterpret_cast<char*>(temp_data.data()), num_elements * sizeof(int64_t));
        for (size_t i = 0; i < num_elements; ++i) {
            array.data[i] = static_cast<double>(temp_data[i]);
        }
        break;
    }
    default:
        throw std::runtime_error("Unsupported data type: " + dtype);
    }

    return array;
}



DataType parse_dtype(const std::string& dtype) {
    static std::map<std::string, DataType> dtype_map = {
        {"<f4", DataType::FLOAT32},
        {"<f8", DataType::FLOAT64},
        {"<i4", DataType::INT32},
        {"<i8", DataType::INT64}
    };
    auto it = dtype_map.find(dtype);
    if (it != dtype_map.end()) {
        return it->second;
    }
    return DataType::UNKNOWN;
}
