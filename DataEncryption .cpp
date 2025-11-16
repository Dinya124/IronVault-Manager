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
    // Генерируем соль и IV
    std::vector<unsigned char> salt = generateSalt();
    std::vector<unsigned char> iv = generateIV();

    // Производим ключ из пароля
    std::vector<unsigned char> key = deriveKey(password, salt, internal_key);

    // Создаем контекст шифрования
    EVP_CIPHER_CTX *ctx = createCipherContext();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }
    // Инициализируем шифрование
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
        cleanupCipherContext(ctx);
        throw std::runtime_error("Failed to initialize encryption");
    }
    // Шифруем данные
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_CIPHER_CTX_block_size(ctx));
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                          reinterpret_cast<const unsigned char *>(plaintext.data()),
                          plaintext.size()) != 1) {
        cleanupCipherContext(ctx);
        throw std::runtime_error("Failed to encrypt data");
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        cleanupCipherContext(ctx);
        throw std::runtime_error("Failed to finalize encryption");
    }
    ciphertext_len += len;

    cleanupCipherContext(ctx);

    // Формируем итоговый результат: соль + IV + зашифрованные данные
    std::vector<unsigned char> result;
    result.reserve(salt.size() + iv.size() + ciphertext_len);
    result.insert(result.end(), salt.begin(), salt.end());
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.begin() + ciphertext_len);

    return encodeBase64(result);
}
