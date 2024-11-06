#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
// Base64 编码函数
char* base64_encode(const unsigned char* data, size_t length) {
    EVP_ENCODE_CTX* ctx;
    int out_len = 0;
    char* encoded_data = NULL;

    // 创建EVP编码上下文
    ctx = EVP_ENCODE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_ENCODE_CTX_new failed\n");
        return NULL;
    }

    // 初始化编码上下文
    EVP_EncodeInit(ctx);

    // 计算编码后的输出缓冲区大小
    int encoded_len = EVP_ENCODE_LENGTH(length);

    // 分配足够的内存存放编码后的数据
    encoded_data = (char*)malloc(encoded_len + 1);
    if (encoded_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_ENCODE_CTX_free(ctx);
        return NULL;
    }

    // 执行编码
    EVP_EncodeUpdate(ctx, (unsigned char*)encoded_data, &out_len, data, length);

    // 最后一次更新
    EVP_EncodeFinal(ctx, (unsigned char*)encoded_data + out_len, &out_len);

    // 添加字符串结尾符
    encoded_data[encoded_len] = '\0';

    // 清理资源
    EVP_ENCODE_CTX_free(ctx);

    return encoded_data;
}
// Base64 解码函数
unsigned char* base64_decode(const char* encoded_data, size_t length) {
    EVP_ENCODE_CTX* ctx;
    int out_len = 0;
    unsigned char* decoded_data = NULL;

    // 创建EVP解码上下文
    ctx = EVP_ENCODE_CTX_new();
    if (ctx == NULL) {
        fprintf(stderr, "EVP_ENCODE_CTX_new failed\n");
        return NULL;
    }

    // 初始化解码上下文
    EVP_DecodeInit(ctx);

    // 计算解码后的输出缓冲区大小
    length = EVP_DECODE_LENGTH(strlen(encoded_data));

    // 分配足够的内存存放解码后的数据
    decoded_data = (unsigned char*)malloc(length);
    if (decoded_data == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        EVP_ENCODE_CTX_free(ctx);
        return NULL;
    }

    // 执行解码
    EVP_DecodeUpdate(ctx, decoded_data, &out_len, (unsigned char*)encoded_data, strlen(encoded_data));

    // 最后一次更新
    EVP_DecodeFinal(ctx, decoded_data + out_len, &out_len);

    // 更新解码后的长度
    length = out_len;

    // 清理资源
    EVP_ENCODE_CTX_free(ctx);

    return decoded_data;
}