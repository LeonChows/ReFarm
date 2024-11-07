#include <iostream>
#include <openssl/evp.h>
#include <iomanip>
#include <sstream>

std::string getMd5Hash(const std::string& input) {
    unsigned char hash[EVP_MAX_MD_SIZE];  // 哈希值缓冲区

    // 创建和初始化 EVP_MD_CTX 上下文
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx == nullptr) {
        throw std::runtime_error("Failed to create MD_CTX");
    }

    // 初始化 MD5 哈希算法
    if (EVP_DigestInit_ex(mdctx, EVP_md5(), nullptr) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to initialize MD5 algorithm");
    }

    // 更新哈希
    if (EVP_DigestUpdate(mdctx, input.c_str(), input.length()) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to update MD5 hash");
    }

    // 获取哈希结果
    unsigned int len;
    if (EVP_DigestFinal_ex(mdctx, hash, &len) != 1) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("Failed to finalize MD5 hash");
    }

    EVP_MD_CTX_free(mdctx);  // 释放上下文

    // 将哈希值转换为十六进制字符串
    std::stringstream hexStream;
    for (unsigned int i = 0; i < len; ++i) {
        hexStream << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return hexStream.str();  // 返回 128 位（32 字符）十六进制字符串
}


std::string get16bitMd5(const std::string& input) {

    std::string temp = getMd5Hash(input);
    return temp.substr(0, 16);
}
std::string get24bitMd5(const std::string& input) {

    std::string temp = getMd5Hash(input);
    return temp.substr(0, 24);
}
std::string get32bitMd5(const std::string& input) {

    std::string temp = getMd5Hash(input);
    return temp;
}