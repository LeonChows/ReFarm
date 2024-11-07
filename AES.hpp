#ifndef AES_HPP
#define AES_HPP
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
/*
libcrypto.lib
libcrypto_static.lib
libssl.lib
libssl_static.lib
*/
#pragma comment (lib,"libcrypto.lib")
#pragma comment (lib,"libcrypto_static.lib")
#pragma comment (lib,"libssl.lib")
#pragma comment (lib,"libssl_static.lib")
enum CryptoType {
	ECB = 0,
	CBC = 1,
	CFB = 2,
	OFB = 3,
	CTR = 4,
};


class AES {
private:
	std::vector<unsigned char> key_;
	std::vector<unsigned char> iv_;
	int key_length_;

public:
	// 构造函数，支持不同长度的密钥
	AES(const std::string& key, const std::string& iv = "0000000000000000") {
		if (key.size() != AES_BLOCK_SIZE && key.size() != 24 && key.size() != 32) {
			throw std::invalid_argument("key 必须是 16, 24, 32 字节的软件将会根据您输入的值自动判断加密的位数");
		}
		if (iv.size() != AES_BLOCK_SIZE) {
			throw std::invalid_argument("iv必须是十六字节的");
		}

		key_.assign(key.begin(), key.end());
		iv_.assign(iv.begin(), iv.end());
		key_length_ = key.size();
	}

	std::string encrypt(const std::string& plaintext, int mode) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) throw std::runtime_error("创建加密上下文数据失败");

		const EVP_CIPHER* cipher = nullptr;

		if (key_length_ == 16) { // AES-128
			if (mode == ECB) {
				cipher = EVP_aes_128_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_128_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_128_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_128_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_128_ctr();
			}
		}
		else if (key_length_ == 24) { // AES-192
			if (mode == ECB) {
				cipher = EVP_aes_192_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_192_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_192_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_192_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_192_ctr();
			}
		}
		else if (key_length_ == 32) { // AES-256
			if (mode == ECB) {
				cipher = EVP_aes_256_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_256_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_256_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_256_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_256_ctr();
			}
		}
		else {
			EVP_CIPHER_CTX_free(ctx);
			throw std::invalid_argument("非法的加密模式");
		}

		if (EVP_EncryptInit_ex(ctx, cipher, nullptr, key_.data(), mode == ECB ? nullptr : iv_.data()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("无法初始化加密操作");
		}

		// 默认启用填充
		if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("设置填充模式失败");
		}
		std::vector<unsigned char> ciphertext(plaintext.size() + AES_BLOCK_SIZE);
		int len = 0;

		if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("加密数据失败，请检查您的key，iv 以及字符编码");
		}

		int ciphertext_len = len;

		if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("加密数据失败，请检查您的key，iv 以及字符编码");
		}

		ciphertext_len += len;
		EVP_CIPHER_CTX_free(ctx);

		return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
	}

	std::string decrypt(const std::string& ciphertext, int mode) {
		EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
		if (!ctx) throw std::runtime_error("创建解密上下文数据失败");

		const EVP_CIPHER* cipher = nullptr;

		if (key_length_ == 16) { // AES-128
			if (mode == ECB) {
				cipher = EVP_aes_128_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_128_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_128_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_128_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_128_ctr();
			}
		}
		else if (key_length_ == 24) { // AES-192
			if (mode == ECB) {
				cipher = EVP_aes_192_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_192_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_192_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_192_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_192_ctr();
			}
		}
		else if (key_length_ == 32) { // AES-256
			if (mode == ECB) {
				cipher = EVP_aes_256_ecb();
			}
			else if (mode == CBC) {
				cipher = EVP_aes_256_cbc();
			}
			else if (mode == CFB) {
				cipher = EVP_aes_256_cfb();
			}
			else if (mode == OFB) {
				cipher = EVP_aes_256_ofb();
			}
			else if (mode == CTR) {
				cipher = EVP_aes_256_ctr();
			}
		}
		else {
			EVP_CIPHER_CTX_free(ctx);
			throw std::invalid_argument("非法的加密模式");
		}

		if (EVP_DecryptInit_ex(ctx, cipher, nullptr, key_.data(), mode == ECB ? nullptr : iv_.data()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("无法初始化解密操作");
		}

		// 默认启用填充
		if (EVP_CIPHER_CTX_set_padding(ctx, 1) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("设置填充模式失败");
		}

		std::vector<unsigned char> decryptedtext(ciphertext.size());
		int len = 0;

		if (EVP_DecryptUpdate(ctx, decryptedtext.data(), &len, reinterpret_cast<const unsigned char*>(ciphertext.data()), ciphertext.size()) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("解密数据失败，请检查您的key，iv 以及字符编码");
		}

		int decryptedtext_len = len;

		if (EVP_DecryptFinal_ex(ctx, decryptedtext.data() + len, &len) != 1) {
			EVP_CIPHER_CTX_free(ctx);
			throw std::runtime_error("解密数据失败，请检查您的key，iv 以及字符编码");
		}

		decryptedtext_len += len;
		EVP_CIPHER_CTX_free(ctx);

		return std::string(decryptedtext.begin(), decryptedtext.begin() + decryptedtext_len);
	}
};
#endif