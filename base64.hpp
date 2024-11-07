#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <cstring>
#include <iostream>
// Base64 编码函数
std::string base64_encode(const unsigned char* buffer, size_t length)
{
	BIO* bio = BIO_new(BIO_s_mem());
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// 忽略换行符
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	BIO_write(bio, buffer, length);
	BIO_flush(bio);

	BUF_MEM* buffer_ptr;
	BIO_get_mem_ptr(bio, &buffer_ptr);
	std::string encoded_data(buffer_ptr->data, buffer_ptr->length);
	BIO_free_all(bio);
	return encoded_data;
}
// Base64 解码函数
std::string base64_decode(const std::string& encoded_string) {
	BIO* bio = BIO_new_mem_buf(encoded_string.data(), -1);
	BIO* b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	// 忽略换行符
	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

	std::string decoded_string(encoded_string.length(), '\0');
	int decoded_length = BIO_read(bio, &decoded_string[0], encoded_string.length());

	BIO_free_all(bio);

	decoded_string.resize(decoded_length);  // 调整字符串到实际大小
	return decoded_string;
}