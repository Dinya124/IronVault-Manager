#ifndef DATAENCRYPTION_H
#define DATAENCRYPTION_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <openssl/rand.h>

class DataEncryption {
private:
    static const size_t KEY_LENGTH = 32;
    static const size_t IV_LENGTH = 16;
    static const size_t SALT_LENGTH = 16;
    static const int ITERATIONS = 100000;

public:
    // Основные методы шифрования/дешифрования
    static std::string
    encrypt(const std::string &plaintext, const std::string &password, const std::string &internal_key = "");

    static std::string
    decrypt(const std::string &ciphertext, const std::string &password, const std::string &internal_key = "");

    // Генерация ключа пароля
    static std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt,
                                                const std::string &internal_key = "");

    // Вспомогательные методы
    static std::vector<unsigned char> generateSalt();

    static std::vector<unsigned char> generateIV();

    static bool initializeCrypto();

    static void cleanupCrypto();

    // Проверка целостности данных
    static bool
    verifyIntegrity(const std::string &ciphertext, const std::string &password, const std::string &internal_key = "");

private:
    // Внутренние методы для работы с OpenSSL
    static EVP_CIPHER_CTX *createCipherContext();

    static void cleanupCipherContext(EVP_CIPHER_CTX *ctx);

    // Методы для работы с данными
    static std::string encodeBase64(const std::vector<unsigned char> &data);

    static std::vector<unsigned char> decodeBase64(const std::string &data);

    // Константы
    static const std::string CIPHER_ALGORITHM;
    static const std::string DIGEST_ALGORITHM;


};

#endif