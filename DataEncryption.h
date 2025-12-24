#ifndef DATAENCRYPTION_H
#define DATAENCRYPTION_H

#include <string>
#include <vector>
#include <memory> // Для std::unique_ptr
#include <openssl/evp.h>
#include <openssl/rand.h>

class DataEncryption {
private:
    static const size_t KEY_LENGTH = 32;
    static const size_t IV_LENGTH = 16;
    static const size_t SALT_LENGTH = 16;
    static const int ITERATIONS = 100000;

    // Структура-удалитель для unique_ptr
    struct EVP_CIPHER_CTX_Deleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) EVP_CIPHER_CTX_free(ctx);
        }
    };

    // Алиас для удобства: Умный указатель на контекст шифрования
    using CipherContextPtr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

public:
    static std::string encrypt(const std::string &plaintext, const std::string &password, const std::string &internal_key = "");
    static std::string decrypt(const std::string &ciphertext, const std::string &password, const std::string &internal_key = "");

    static std::vector<unsigned char> deriveKey(const std::string &password, const std::vector<unsigned char> &salt, const std::string &internal_key = "");
    static std::vector<unsigned char> generateSalt();
    static std::vector<unsigned char> generateIV();
    static bool initializeCrypto();
    static void cleanupCrypto();
    static bool verifyIntegrity(const std::string &ciphertext, const std::string &password, const std::string &internal_key = "");

private:
    // Возвращает умный указатель
    static CipherContextPtr createCipherContextRAII();

    static std::string encodeBase64(const std::vector<unsigned char> &data);
    static std::vector<unsigned char> decodeBase64(const std::string &data);

    static const std::string CIPHER_ALGORITHM;
    static const std::string DIGEST_ALGORITHM;
};

#endif