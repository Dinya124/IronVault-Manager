#include "DataEncryption .h"
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <sstream>
#include <stdexcept>
#include <iostream>

// Инициализация статических констант
const std::string DataEncryption::CIPHER_ALGORITHM = "aes-256-cbc";
const std::string DataEncryption::DIGEST_ALGORITHM = "sha256";

// Основной метод шифрования
std::string
DataEncryption::encrypt(const std::string &plaintext, const std::string &password, const std::string &internal_key) {
    if (plaintext.empty()) {
        throw std::invalid_argument("Plaintext cannot be empty");
    }
    if (password.empty()) {
        throw std::invalid_argument("Password cannot be empty");
    }

};